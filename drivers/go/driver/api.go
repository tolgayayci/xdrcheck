package driver

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/price"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// L4 maps the SDK-neutral api operations onto go-stellar-sdk, with exactly the argument names of the driver
// protocol's canonical api vocabulary; there are no aliases. Conventions:
//
//   - bytes: {"hex": "…"} (or {"native": "bytes", "hex": "…"}), or a plain hex string under a name ending _hex
//   - numbers and IDs: {"native": "number"|"string"|"bigint", "value": "<decimal>"}; a bare string is a native
//     string. A value the Go type the SDK takes cannot hold is n_a/value_not_representable
//   - assets: "native" or "CODE:ISSUER"; results: IDs as decimal strings, hashes and pool IDs as lower-case hex
//
// An unknown argument name, a missing required argument or a malformed one is a protocol error: the vector is
// wrong, the SDK was never called. Ops and their arguments ([optional]):
//
//	asset.compare               asset_a, asset_b                 value: -1, 0 or 1 (xdr.Asset.LessThan both ways)
//	liquidity_pool.id           asset_a, asset_b, [fee]          value: pool ID (txnbuild.NewLiquidityPoolId;
//	                                                              xdr.NewPoolId when fee is not 30)
//	liquidity_pool.asset        asset_a, asset_b, [fee]          value: pool ID, xdr_hex: ChangeTrustAsset
//	                                                              (txnbuild.LiquidityPoolShareChangeTrustAsset)
//	muxed_account.encode        account, id                      value: M… (xdr.MuxedAccountFromAccountId), xdr_hex
//	muxed_account.decode        text                             value: {account, id} (xdr.AddressToMuxedAccount)
//	offer.manage_sell|buy       offer_id, [selling], [buying], [amount], [price]
//	                                                              value: offer ID read back, xdr_hex: the operation
//	strkey.encode               type, payload_hex                value: strkey (strkey.Encode)
//	strkey.decode               text, [type]                     value: payload hex (strkey.Decode)
//	transaction.parse           xdr_hex, passphrase              value: {tx_hash, operations}, xdr_hex: envelope
//	transaction.hash            xdr_hex, passphrase              value: hash hex
//	memo.text_roundtrip         xdr_hex (Memo)                   value: native text bytes as hex, xdr_hex: Memo
//	address.to_strkey           xdr_hex, [xdr_type]              value: G…/M… (MuxedAccount / AccountId GetAddress)
//	address.from_sc_address     xdr_hex (ScAddress)              value: strkey (ScAddress.String)
//	signer_key.to_strkey        xdr_hex (SignerKey)              value: strkey (SignerKey.GetAddress)
//	operation.object_roundtrip  xdr_hex (Operation)              value: bytes_preserved, xdr_hex: the rebuilt op
//
// self_decode (the SDK's own decoder on what it produced) accompanies every xdr_hex and every strkey result.
// The SDK has no ScVal native layer (scval.*), no XDR-JSON (xdrjson.decode), no price helper (price.encode)
// and no custom-schema XDR (xdr.custom_union_encode): those ops are not declared and answer
// n_a/op_not_supported.

// defaultIssuer is the issuer of the default buying asset of the offer ops.
const defaultIssuer = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

type apiFunc func(a *apiArgs) result

type apiSpec struct {
	fn                 apiFunc
	required, optional []string
}

var apiTable = map[string]apiSpec{
	"address.from_sc_address":    {apiFromScAddress, []string{"xdr_hex"}, nil},
	"address.to_strkey":          {apiToStrkey, []string{"xdr_hex"}, []string{"xdr_type"}},
	"asset.compare":              {apiAssetCompare, []string{"asset_a", "asset_b"}, nil},
	"liquidity_pool.asset":       {apiPoolAsset, []string{"asset_a", "asset_b"}, []string{"fee"}},
	"liquidity_pool.id":          {apiPoolID, []string{"asset_a", "asset_b"}, []string{"fee"}},
	"memo.text_roundtrip":        {apiMemoText, []string{"xdr_hex"}, nil},
	"muxed_account.decode":       {apiMuxedDecode, []string{"text"}, nil},
	"muxed_account.encode":       {apiMuxedEncode, []string{"account", "id"}, nil},
	"offer.manage_buy":           {apiOffer(false), []string{"offer_id"}, []string{"selling", "buying", "amount", "price"}},
	"offer.manage_sell":          {apiOffer(true), []string{"offer_id"}, []string{"selling", "buying", "amount", "price"}},
	"operation.object_roundtrip": {apiOperationRoundtrip, []string{"xdr_hex"}, nil},
	"signer_key.to_strkey":       {apiSignerKey, []string{"xdr_hex"}, nil},
	"strkey.decode":              {apiStrkeyDecode, []string{"text"}, []string{"type"}},
	"strkey.encode":              {apiStrkeyEncode, []string{"type", "payload_hex"}, nil},
	"transaction.hash":           {apiTransaction(false), []string{"xdr_hex"}, []string{"passphrase"}},
	"transaction.parse":          {apiTransaction(true), []string{"xdr_hex"}, []string{"passphrase"}},
}

func apiOps() []string {
	ops := make([]string, 0, len(apiTable))
	for k := range apiTable {
		ops = append(ops, k)
	}
	sort.Strings(ops)
	return ops
}

// apiArgs are one call's arguments; passphrase is the input's own passphrase field, used when the arguments do
// not name one.
type apiArgs struct {
	m          map[string]any
	passphrase string
}

func levelAPI(in *input) result {
	spec, found := apiTable[in.APIOp]
	if !found {
		return notApplicable("op_not_supported", "go-stellar-sdk has no mapping for "+in.APIOp)
	}
	args := in.Args
	if args == nil {
		args = map[string]any{}
	}
	allowed := map[string]bool{}
	for _, n := range spec.required {
		allowed[n] = true
		if _, given := args[n]; !given {
			return protocolError(fmt.Sprintf("%s: missing argument %s", in.APIOp, n))
		}
	}
	for _, n := range spec.optional {
		allowed[n] = true
	}
	var unknown []string
	for n := range args {
		if !allowed[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return protocolError(fmt.Sprintf("%s: unknown argument(s) %s", in.APIOp, strings.Join(unknown, ", ")))
	}
	return spec.fn(&apiArgs{m: args, passphrase: in.Passphrase})
}

// errArg marks an argument the driver cannot use: the request is answered with a protocol error, because the
// SDK was never called.
type errArg struct{ msg string }

func (e errArg) Error() string { return e.msg }

// errNotRepresentable marks a tagged native value the Go type the SDK takes cannot hold.
type errNotRepresentable struct{ msg string }

func (e errNotRepresentable) Error() string { return e.msg }

func argFail(err error) result {
	var ea errArg
	if errors.As(err, &ea) {
		return protocolError(ea.msg)
	}
	var nr errNotRepresentable
	if errors.As(err, &nr) {
		return notApplicable("value_not_representable", nr.msg)
	}
	return reject("other", "xdrcheck-driver-go arguments", err)
}

func (a *apiArgs) has(name string) bool { _, given := a.m[name]; return given }

// str returns a plain string argument.
func (a *apiArgs) str(name string) (string, error) {
	switch t := a.m[name].(type) {
	case string:
		return t, nil
	case map[string]any:
		if t["native"] == "string" {
			if s, isStr := t["value"].(string); isStr && len(t) == 2 {
				return s, nil
			}
		}
	}
	return "", errArg{fmt.Sprintf("argument %s must be a string", name)}
}

// tagged returns a number or ID argument: its decimal text and whether it carries a native tag. A bare string
// is a native string.
func (a *apiArgs) tagged(name string) (string, error) {
	switch t := a.m[name].(type) {
	case string:
		return t, nil
	case map[string]any:
		kind, _ := t["native"].(string)
		switch kind {
		case "number", "string", "bigint":
		default:
			return "", errArg{fmt.Sprintf("argument %s: native tag %v is not number, string or bigint", name, t["native"])}
		}
		if len(t) != 2 {
			return "", errArg{fmt.Sprintf("argument %s: a native value is {\"native\", \"value\"}", name)}
		}
		switch v := t["value"].(type) {
		case string:
			return v, nil
		case json.Number:
			return v.String(), nil
		}
		return "", errArg{fmt.Sprintf("argument %s: value must be a decimal string", name)}
	}
	return "", errArg{fmt.Sprintf("argument %s must be a native-tagged value or a string", name)}
}

// uint64Arg and int64Arg build the SDK's typed integer the way an application would; text the Go type cannot
// hold (out of range, negative for unsigned, not decimal) cannot be passed at all.
func (a *apiArgs) uint64Arg(name string) (uint64, error) {
	s, err := a.tagged(name)
	if err != nil {
		return 0, err
	}
	u, perr := strconv.ParseUint(s, 10, 64)
	if perr != nil {
		return 0, errNotRepresentable{fmt.Sprintf("%s is a uint64 in go-stellar-sdk; %q is not representable", name, s)}
	}
	return u, nil
}

func (a *apiArgs) int64Arg(name string) (int64, error) {
	s, err := a.tagged(name)
	if err != nil {
		return 0, err
	}
	n, perr := strconv.ParseInt(s, 10, 64)
	if perr != nil {
		return 0, errNotRepresentable{fmt.Sprintf("%s is an int64 in go-stellar-sdk; %q is not representable", name, s)}
	}
	return n, nil
}

// bytesArg returns a byte argument: {"hex": …}, {"native": "bytes", "hex": …}, or a plain hex string (the
// names that take bytes all end in _hex).
func (a *apiArgs) bytesArg(name string) ([]byte, error) {
	var s string
	switch t := a.m[name].(type) {
	case string:
		s = t
	case map[string]any:
		h, isStr := t["hex"].(string)
		_, tagged := t["native"]
		if !isStr || len(t) > 2 || (len(t) == 2 && (!tagged || t["native"] != "bytes")) {
			return nil, errArg{fmt.Sprintf("argument %s is not {\"hex\": …}", name)}
		}
		s = h
	default:
		return nil, errArg{fmt.Sprintf("argument %s is not bytes", name)}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errArg{fmt.Sprintf("argument %s: %v", name, err)}
	}
	return b, nil
}

// xdrArg decodes xdr_hex as the named type (the op's default, or xdr_type when the op takes one, restricted to
// allowed) with the strict entry point; a refusal there is the SDK's.
func (a *apiArgs) xdrArg(defaultType string, allowed ...string) (codec, string, []byte, *result) {
	fail := func(err error) (codec, string, []byte, *result) { r := argFail(err); return nil, "", nil, &r }
	raw, err := a.bytesArg("xdr_hex")
	if err != nil {
		return fail(err)
	}
	name := defaultType
	if a.has("xdr_type") {
		if name, err = a.str("xdr_type"); err != nil {
			return fail(err)
		}
		valid := false
		for _, t := range allowed {
			valid = valid || t == name
		}
		if !valid {
			return fail(errArg{fmt.Sprintf("xdr_type %q is not one of %s", name, strings.Join(allowed, ", "))})
		}
	}
	v, rej := decodeStrict(name, raw)
	if rej != nil {
		return nil, "", nil, rej
	}
	_, goName, _ := newValue(name)
	return v, goName, raw, nil
}

// assetArg returns an asset argument's text after checking its shape ("native" or "CODE:ISSUER"); whether the
// code and issuer are valid is the SDK's to decide.
func (a *apiArgs) assetArg(name, def string) (string, error) {
	if !a.has(name) {
		return def, nil
	}
	s, err := a.str(name)
	if err != nil {
		return "", err
	}
	if s != "native" {
		code, issuer, found := strings.Cut(s, ":")
		if !found || code == "" || issuer == "" {
			return "", errArg{fmt.Sprintf("argument %s: %q is not native or CODE:ISSUER", name, s)}
		}
	}
	return s, nil
}

func apiValue(value any, extra map[string]any) result {
	api := map[string]any{"value": value}
	for k, v := range extra {
		api[k] = v
	}
	return ok(map[string]any{"api": api})
}

// selfDecode reports whether the SDK's strict decoder accepts bytes it produced as the named type.
func selfDecode(name string, b []byte) string {
	if _, rej := decodeStrict(name, b); rej != nil {
		return "rejected"
	}
	return "accepted"
}

// withXDR is an ok api result with value, xdr_hex and self_decode; when the SDK's own decoder refuses its
// output the outcome is diverge/own_output_rejected.
func withXDR(value any, typeName string, out []byte) result {
	sd := selfDecode(typeName, out)
	res := apiValue(value, map[string]any{"xdr_hex": hex.EncodeToString(out), "self_decode": sd})
	if sd == "rejected" {
		res.Outcome, res.Reason = "diverge", &reason{Code: "own_output_rejected", EntryPoint: "xdr.SafeUnmarshal(" + typeName + ")"}
	}
	return res
}

// xdrAsset and txnAsset parse "native" or "CODE:ISSUER" into the two SDK asset types.
func xdrAsset(s string) (xdr.Asset, error) {
	if s == "native" {
		return xdr.MustNewNativeAsset(), nil
	}
	code, issuer, _ := strings.Cut(s, ":")
	return xdr.NewCreditAsset(code, issuer)
}

func txnAsset(s string) txnbuild.Asset {
	if s == "native" {
		return txnbuild.NativeAsset{}
	}
	code, issuer, _ := strings.Cut(s, ":")
	return txnbuild.CreditAsset{Code: code, Issuer: issuer}
}

func apiAssetCompare(args *apiArgs) result {
	sa, err := args.assetArg("asset_a", "")
	if err != nil {
		return argFail(err)
	}
	sb, err := args.assetArg("asset_b", "")
	if err != nil {
		return argFail(err)
	}
	a, err := xdrAsset(sa)
	if err != nil {
		return reject("other", "xdr.NewCreditAsset", err)
	}
	b, err := xdrAsset(sb)
	if err != nil {
		return reject("other", "xdr.NewCreditAsset", err)
	}
	switch {
	case a.LessThan(b):
		return apiValue(-1, nil)
	case b.LessThan(a):
		return apiValue(1, nil)
	}
	return apiValue(0, nil)
}

func poolArgs(args *apiArgs) (string, string, int32, error) {
	sa, err := args.assetArg("asset_a", "")
	if err != nil {
		return "", "", 0, err
	}
	sb, err := args.assetArg("asset_b", "")
	if err != nil {
		return "", "", 0, err
	}
	fee := int32(xdr.LiquidityPoolFeeV18)
	if args.has("fee") {
		s, err := args.tagged("fee")
		if err != nil {
			return "", "", 0, err
		}
		n, perr := strconv.ParseInt(s, 10, 32)
		if perr != nil {
			return "", "", 0, errNotRepresentable{fmt.Sprintf("fee is an int32 in go-stellar-sdk; %q is not representable", s)}
		}
		fee = int32(n)
	}
	return sa, sb, fee, nil
}

func apiPoolID(args *apiArgs) result {
	sa, sb, fee, err := poolArgs(args)
	if err != nil {
		return argFail(err)
	}
	if fee != int32(xdr.LiquidityPoolFeeV18) {
		a, err := xdrAsset(sa)
		if err != nil {
			return reject("other", "xdr.NewCreditAsset", err)
		}
		b, err := xdrAsset(sb)
		if err != nil {
			return reject("other", "xdr.NewCreditAsset", err)
		}
		id, err := xdr.NewPoolId(a, b, xdr.Int32(fee))
		if err != nil {
			return reject(classifyAPI(err), "xdr.NewPoolId", err)
		}
		return apiValue(hex.EncodeToString(id[:]), nil)
	}
	id, err := txnbuild.NewLiquidityPoolId(txnAsset(sa), txnAsset(sb))
	if err != nil {
		return reject(classifyAPI(err), "txnbuild.NewLiquidityPoolId", err)
	}
	return apiValue(hex.EncodeToString(id[:]), nil)
}

// apiPoolAsset builds the pool-share ChangeTrustAsset as a ChangeTrust operation carries it: the operation is
// validated (where the SDK checks the asset order), then the line is serialised and its pool ID read back.
func apiPoolAsset(args *apiArgs) result {
	sa, sb, fee, err := poolArgs(args)
	if err != nil {
		return argFail(err)
	}
	line := txnbuild.LiquidityPoolShareChangeTrustAsset{LiquidityPoolParameters: txnbuild.LiquidityPoolParameters{
		AssetA: txnAsset(sa), AssetB: txnAsset(sb), Fee: fee}}
	op := txnbuild.ChangeTrust{Line: line, Limit: "922337203685.4775807"}
	if err := op.Validate(); err != nil {
		return reject(classifyAPI(err), "txnbuild.ChangeTrust.Validate", err)
	}
	x, err := line.ToXDR()
	if err != nil {
		return reject(classifyAPI(err), "txnbuild.LiquidityPoolShareChangeTrustAsset.ToXDR", err)
	}
	out, err := x.MarshalBinary()
	if err != nil {
		return reject("other", "ChangeTrustAsset.MarshalBinary", err)
	}
	var id [32]byte
	if fee == int32(xdr.LiquidityPoolFeeV18) {
		pid, err := txnbuild.NewLiquidityPoolId(line.LiquidityPoolParameters.AssetA, line.LiquidityPoolParameters.AssetB)
		if err != nil {
			return reject(classifyAPI(err), "txnbuild.NewLiquidityPoolId", err)
		}
		id = pid
	} else {
		pid, err := xdr.NewPoolId(x.LiquidityPool.ConstantProduct.AssetA, x.LiquidityPool.ConstantProduct.AssetB, xdr.Int32(fee))
		if err != nil {
			return reject(classifyAPI(err), "xdr.NewPoolId", err)
		}
		id = pid
	}
	return withXDR(hex.EncodeToString(id[:]), "ChangeTrustAsset", out)
}

func apiMuxedEncode(args *apiArgs) result {
	g, err := args.str("account")
	if err != nil {
		return argFail(err)
	}
	id, err := args.uint64Arg("id")
	if err != nil {
		return argFail(err)
	}
	m, err := xdr.MuxedAccountFromAccountId(g, id)
	if err != nil {
		return reject(classifyStrkey(err), "xdr.MuxedAccountFromAccountId", err)
	}
	addr, err := m.GetAddress()
	if err != nil {
		return reject(classifyStrkey(err), "MuxedAccount.GetAddress", err)
	}
	out, err := m.MarshalBinary()
	if err != nil {
		return reject("other", "MuxedAccount.MarshalBinary", err)
	}
	res := withXDR(addr, "MuxedAccount", out)
	back, err := xdr.AddressToMuxedAccount(addr)
	if err == nil {
		if bid, ierr := back.GetId(); ierr != nil || bid != id {
			err = fmt.Errorf("decoded id differs: %v %v", bid, ierr)
		}
	}
	if err != nil {
		res.Actual["api"].(map[string]any)["self_decode"] = "rejected"
		res.Outcome, res.Reason = "diverge", &reason{Code: "own_output_rejected", EntryPoint: "xdr.AddressToMuxedAccount", Message: trim(err.Error())}
	}
	return res
}

func apiMuxedDecode(args *apiArgs) result {
	addr, err := args.str("text")
	if err != nil {
		return argFail(err)
	}
	m, err := xdr.AddressToMuxedAccount(addr)
	if err != nil {
		return reject(classifyStrkey(err), "xdr.AddressToMuxedAccount", err)
	}
	acc := m.ToAccountId()
	g, err := acc.GetAddress()
	if err != nil {
		return reject(classifyStrkey(err), "AccountId.GetAddress", err)
	}
	id, err := m.GetId()
	if err != nil {
		// a G address decodes to an unmuxed account, which has no ID: not an M address
		return reject("strkey_version", "MuxedAccount.GetId", err)
	}
	return apiValue(map[string]any{"account": g, "id": strconv.FormatUint(id, 10)}, nil)
}

func apiOffer(sell bool) apiFunc {
	return func(args *apiArgs) result {
		id, err := args.int64Arg("offer_id")
		if err != nil {
			return argFail(err)
		}
		selling, err := args.assetArg("selling", "native")
		if err != nil {
			return argFail(err)
		}
		buying, err := args.assetArg("buying", "USD:"+defaultIssuer)
		if err != nil {
			return argFail(err)
		}
		amount, priceText := "1", "1"
		if args.has("amount") {
			if amount, err = args.tagged("amount"); err != nil {
				return argFail(err)
			}
		}
		if args.has("price") {
			if priceText, err = args.tagged("price"); err != nil {
				return argFail(err)
			}
		}
		p, err := price.Parse(priceText)
		if err != nil {
			return reject(classifyAPI(err), "price.Parse", err)
		}
		var op txnbuild.Operation
		name := "txnbuild.ManageSellOffer"
		if sell {
			op = &txnbuild.ManageSellOffer{Selling: txnAsset(selling), Buying: txnAsset(buying), Amount: amount, Price: p, OfferID: id}
		} else {
			name = "txnbuild.ManageBuyOffer"
			op = &txnbuild.ManageBuyOffer{Selling: txnAsset(selling), Buying: txnAsset(buying), Amount: amount, Price: p, OfferID: id}
		}
		if err := op.Validate(); err != nil {
			return reject(classifyAPI(err), name+".Validate", err)
		}
		x, err := op.BuildXDR()
		if err != nil {
			return reject(classifyAPI(err), name+".BuildXDR", err)
		}
		out, err := x.MarshalBinary()
		if err != nil {
			return reject("other", "Operation.MarshalBinary", err)
		}
		var back int64
		if sell {
			back = int64(x.Body.ManageSellOfferOp.OfferId)
		} else {
			back = int64(x.Body.ManageBuyOfferOp.OfferId)
		}
		return withXDR(strconv.FormatInt(back, 10), "Operation", out)
	}
}

func apiTransaction(parse bool) apiFunc {
	return func(args *apiArgs) result {
		raw, err := args.bytesArg("xdr_hex")
		if err != nil {
			return argFail(err)
		}
		pass := args.passphrase
		if args.has("passphrase") {
			if pass, err = args.str("passphrase"); err != nil {
				return argFail(err)
			}
		}
		if pass == "" {
			return protocolError("a transaction op needs a passphrase")
		}
		gt, err := txnbuild.TransactionFromXDR(base64.StdEncoding.EncodeToString(raw))
		if err != nil {
			return reject(classifyObject(err, len(raw)), parseEntry, err)
		}
		h, err := gt.Hash(pass)
		if err != nil {
			return reject("object_validation", "GenericTransaction.Hash", err)
		}
		if !parse {
			return apiValue(hex.EncodeToString(h[:]), nil)
		}
		out, err := gt.MarshalBinary()
		if err != nil {
			return reject("object_validation", "GenericTransaction.MarshalBinary", err)
		}
		value := map[string]any{"tx_hash": hex.EncodeToString(h[:]), "operations": len(parsedOperations(gt))}
		return withXDR(value, "TransactionEnvelope", out)
	}
}

func apiMemoText(args *apiArgs) result {
	v, _, _, rej := args.xdrArg("Memo")
	if rej != nil {
		return *rej
	}
	m := v.(*xdr.Memo)
	if m.Type != xdr.MemoTypeMemoText || m.Text == nil {
		return protocolError("memo.text_roundtrip needs a MEMO_TEXT memo")
	}
	native := *m.Text
	x, err := txnbuild.MemoText(native).ToXDR()
	if err != nil {
		return reject(classifyAPI(err), "txnbuild.MemoText.ToXDR", err)
	}
	out, err := x.MarshalBinary()
	if err != nil {
		return reject("other", "Memo.MarshalBinary", err)
	}
	return withXDR(hex.EncodeToString([]byte(native)), "Memo", out)
}

// strkeyResult is an ok result whose value is a strkey, with self_decode: whether the SDK's own strkey decoder
// accepts it (decode is the SDK's matching decoder for that text).
func strkeyResult(s string, decode func(string) error, entry string) result {
	res := apiValue(s, nil)
	api := res.Actual["api"].(map[string]any)
	if err := decode(s); err != nil {
		api["self_decode"] = "rejected"
		res.Outcome, res.Reason = "diverge", &reason{Code: "own_output_rejected", EntryPoint: entry, Message: trim(err.Error())}
		return res
	}
	api["self_decode"] = "accepted"
	return res
}

func apiToStrkey(args *apiArgs) result {
	v, goName, _, rej := args.xdrArg("MuxedAccount", "MuxedAccount", "AccountId")
	if rej != nil {
		return *rej
	}
	switch t := v.(type) {
	case *xdr.MuxedAccount:
		s, err := t.GetAddress()
		if err != nil {
			return reject(classifyStrkey(err), "MuxedAccount.GetAddress", err)
		}
		return strkeyResult(s, func(s string) error { _, err := xdr.AddressToMuxedAccount(s); return err }, "xdr.AddressToMuxedAccount")
	case *xdr.AccountId:
		s, err := t.GetAddress()
		if err != nil {
			return reject(classifyStrkey(err), "AccountId.GetAddress", err)
		}
		return strkeyResult(s, func(s string) error { _, err := xdr.AddressToAccountId(s); return err }, "xdr.AddressToAccountId")
	}
	return protocolError("address.to_strkey takes a MuxedAccount or AccountId, not " + goName)
}

func apiFromScAddress(args *apiArgs) result {
	v, _, _, rej := args.xdrArg("ScAddress")
	if rej != nil {
		return *rej
	}
	s, err := v.(*xdr.ScAddress).String()
	if err != nil {
		code := classifyStrkey(err)
		if code == "decode_error" {
			code = "unsupported_address_type"
		}
		return reject(code, "xdr.ScAddress.String", err)
	}
	return strkeyResult(s, func(s string) error { _, _, err := strkey.DecodeAny(s); return err }, "strkey.DecodeAny")
}

func apiSignerKey(args *apiArgs) result {
	v, _, _, rej := args.xdrArg("SignerKey")
	if rej != nil {
		return *rej
	}
	sk := v.(*xdr.SignerKey)
	s, err := sk.GetAddress()
	if err != nil {
		return reject(classifyStrkey(err), "xdr.SignerKey.GetAddress", err)
	}
	return strkeyResult(s, func(s string) error { var back xdr.SignerKey; return back.SetAddress(s) }, "xdr.SignerKey.SetAddress")
}

// apiOperationRoundtrip passes an operation through the SDK's object layer and back. The SDK parses operations
// only inside a transaction: the operation is wrapped in a minimal envelope, parsed with
// txnbuild.TransactionFromXDR, and rebuilt from its txnbuild object. The value says whether the bytes came back
// unchanged.
func apiOperationRoundtrip(args *apiArgs) result {
	v, _, raw, rej := args.xdrArg("Operation")
	if rej != nil {
		return *rej
	}
	op := v.(*xdr.Operation)
	env := xdr.TransactionEnvelope{Type: xdr.EnvelopeTypeEnvelopeTypeTx, V1: &xdr.TransactionV1Envelope{Tx: xdr.Transaction{
		SourceAccount: xdr.MuxedAccount{Type: xdr.CryptoKeyTypeKeyTypeEd25519, Ed25519: &xdr.Uint256{}},
		Fee:           100, SeqNum: 1, Cond: xdr.Preconditions{Type: xdr.PreconditionTypePrecondNone},
		Memo: xdr.Memo{Type: xdr.MemoTypeMemoNone}, Operations: []xdr.Operation{*op},
	}}}
	b64, err := xdr.MarshalBase64(env)
	if err != nil {
		return reject("other", "xdr.MarshalBase64", err)
	}
	gt, err := txnbuild.TransactionFromXDR(b64)
	if err != nil {
		return reject(classifyObject(err, len(raw)), parseEntry, err)
	}
	ops := parsedOperations(gt)
	if len(ops) != 1 {
		return reject("object_validation", parseEntry, fmt.Errorf("%d operations parsed", len(ops)))
	}
	built, err := ops[0].BuildXDR()
	if err != nil {
		return reject(classifyAPI(err), fmt.Sprintf("%T.BuildXDR", ops[0]), err)
	}
	out, err := built.MarshalBinary()
	if err != nil {
		return reject("other", "Operation.MarshalBinary", err)
	}
	return withXDR(bytes.Equal(out, raw), "Operation", out)
}

// strkey types: the manifest's strkeyVector.type names, their single-letter prefixes and version bytes. The
// claimable-balance (B) and muxed-contract (W) bytes are written as numbers because older SDK versions do
// not name them.
var strkeyTypes = []struct {
	name, letter string
	vb           strkey.VersionByte
}{
	{"account", "G", strkey.VersionByteAccountID},
	{"muxed_account", "M", strkey.VersionByteMuxedAccount},
	{"secret_seed", "S", strkey.VersionByteSeed},
	{"pre_auth_tx", "T", strkey.VersionByteHashTx},
	{"hash_x", "X", strkey.VersionByteHashX},
	{"signed_payload", "P", strkey.VersionByteSignedPayload},
	{"contract", "C", strkey.VersionByteContract},
	{"muxed_contract", "W", strkey.VersionByte(22 << 3)},
	{"liquidity_pool", "L", strkey.VersionByteLiquidityPool},
	{"claimable_balance", "B", strkey.VersionByte(1 << 3)},
}

// typeVersionByte resolves a strkey type name (exactly the schema's names) to its version byte.
func typeVersionByte(name string) (strkey.VersionByte, bool) {
	for _, s := range strkeyTypes {
		if s.name == name {
			return s.vb, true
		}
	}
	return 0, false
}

// levelStrkey is L4 on a strkey text: strkey.Decode with the declared type's version byte, or else the one the
// first character names; text whose first character names no known type goes to strkey.DecodeAny.
func levelStrkey(text, declared string) result {
	var vb strkey.VersionByte
	known := false
	if declared != "" {
		if vb, known = typeVersionByte(declared); !known {
			return protocolError(fmt.Sprintf("unknown strkey type %q", declared))
		}
	} else if text != "" {
		c := strings.ToUpper(text[:1])
		for _, s := range strkeyTypes {
			if s.letter == c {
				vb, known = s.vb, true
			}
		}
	}
	var payload []byte
	var err error
	entry := "strkey.Decode"
	if known {
		payload, err = strkey.Decode(vb, text)
	} else {
		entry = "strkey.DecodeAny"
		_, payload, err = strkey.DecodeAny(text)
	}
	if err != nil {
		return reject(classifyStrkey(err), entry, err)
	}
	return apiValue(hex.EncodeToString(payload), nil)
}

func apiStrkeyDecode(args *apiArgs) result {
	text, err := args.str("text")
	if err != nil {
		return argFail(err)
	}
	typ := ""
	if args.has("type") {
		if typ, err = args.str("type"); err != nil {
			return argFail(err)
		}
		if typ == "" {
			return protocolError("strkey.decode: type is empty")
		}
	}
	return levelStrkey(text, typ)
}

func apiStrkeyEncode(args *apiArgs) result {
	typ, err := args.str("type")
	if err != nil {
		return argFail(err)
	}
	vb, known := typeVersionByte(typ)
	if !known {
		return protocolError(fmt.Sprintf("strkey.encode: unknown type %q", typ))
	}
	payload, err := args.bytesArg("payload_hex")
	if err != nil {
		return argFail(err)
	}
	s, err := strkey.Encode(vb, payload)
	if err != nil {
		if classifyStrkey(err) == "strkey_version" {
			// The SDK's strkey package does not know this type's version byte (before v0.8.0 there is no
			// muxed-contract W… type): the SDK has no encoder for the type, which is not a refusal of the payload.
			return notApplicable("type_not_generated", fmt.Sprintf("strkey.Encode does not know the %s version byte in this version: %v", typ, err))
		}
		return reject(classifyStrkey(err), "strkey.Encode", err)
	}
	return strkeyResult(s, func(s string) error {
		back, err := strkey.Decode(vb, s)
		if err == nil && !bytes.Equal(back, payload) {
			err = errors.New("strkey.Decode of the SDK's own output returned a different payload")
		}
		return err
	}, "strkey.Decode")
}

// classifyStrkey maps strkey errors to reason codes.
func classifyStrkey(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "checksum"):
		return "strkey_checksum"
	case strings.Contains(msg, "version byte"):
		return "strkey_version"
	case strings.Contains(msg, "padding"):
		return "strkey_padding"
	case strings.Contains(msg, "non-canonical"), strings.Contains(msg, "base32"):
		return "strkey_noncanonical"
	case strings.Contains(msg, "payload length"), strings.Contains(msg, "payload bytes"), strings.Contains(msg, "bytes long"),
		strings.Contains(msg, "length"):
		return "strkey_length"
	case strings.Contains(msg, "type"):
		return "unsupported_address_type"
	}
	return "decode_error"
}

// classifyAPI maps builder errors: the asset-order rule as ordering, a negative or oversized amount or ID as
// value_out_of_range, other validation failures as object_validation.
func classifyAPI(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "AssetA must be") || strings.Contains(msg, "lexicographic"):
		return "ordering"
	case strings.Contains(msg, "negative"), strings.Contains(msg, "out of range"), strings.Contains(msg, "overflow"):
		return "value_out_of_range"
	case strings.Contains(msg, "strkey"), strings.Contains(msg, "checksum"), strings.Contains(msg, "version byte"):
		return classifyStrkey(err)
	}
	return "object_validation"
}
