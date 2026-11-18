// Throwaway conformance probe for github.com/stellar/go-stellar-sdk.
// One module directory per SDK version symlinks this file; build: go build -o probe .
// Usage: ./probe <vectors.json> [vectorId ...]
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type Vec struct {
	ID     string                 `json:"id"`
	Group  int                    `json:"group"`
	Hex    *string                `json:"hex"`
	Params map[string]interface{} `json:"params"`
	Expect map[string]interface{} `json:"expect"`
}

var errNA = errors.New("n/a")

type na struct{ why string }

func (n na) Error() string { return n.why }

var p30 = xdr.StellarValueType(0).ValidEnum(3) && xdr.ScAddressType(0).ValidEnum(5)

func sdkVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/stellar/go-stellar-sdk" {
				v := d.Version
				for _, d2 := range bi.Deps {
					if d2.Path == "github.com/stellar/go-xdr" {
						v += " (go-xdr " + d2.Version + ")"
					}
				}
				return v
			}
		}
	}
	return "unknown"
}

func ps(v Vec, k string) string { s, _ := v.Params[k].(string); return s }
func raw(v Vec) []byte        { b, _ := hex.DecodeString(*v.Hex); return b }

func asset(code, iss string) (xdr.Asset, error) { return xdr.NewCreditAsset(code, iss) }

var decodeTarget = map[string]func() interface{}{
	"ScVal":                func() interface{} { return &xdr.ScVal{} },
	"TransactionEnvelope":  func() interface{} { return &xdr.TransactionEnvelope{} },
	"Memo":                 func() interface{} { return &xdr.Memo{} },
	"Operation":            func() interface{} { return &xdr.Operation{} },
	"ScAddress":            func() interface{} { return &xdr.ScAddress{} },
	"MuxedAccount":         func() interface{} { return &xdr.MuxedAccount{} },
	"LedgerCloseMetaBatch": func() interface{} { return &xdr.LedgerCloseMetaBatch{} },
}

type marshaler interface{ MarshalBinary() ([]byte, error) }

func mhex(m marshaler) string { b, err := m.MarshalBinary(); if err != nil { return "ERR " + err.Error() }; return hex.EncodeToString(b) }

var versionBytes = map[byte]strkey.VersionByte{'G': strkey.VersionByteAccountID, 'M': strkey.VersionByteMuxedAccount, 'S': strkey.VersionByteSeed,
	'T': strkey.VersionByteHashTx, 'X': strkey.VersionByteHashX, 'P': strkey.VersionByteSignedPayload, 'C': strkey.VersionByteContract,
	'L': strkey.VersionByteLiquidityPool, 'B': strkey.VersionByte(1 << 3), 'W': strkey.VersionByte(22 << 3)}

func run(v Vec, dir string) (string, string, error) {
	switch {
	case v.Group == 1 && v.ID != "1c":
		a, err := asset(ps(v, "code"), ps(v, "a"))
		if err != nil { return "", "", err }
		b, err := asset(ps(v, "code"), ps(v, "b"))
		if err != nil { return "", "", err }
		id, err := xdr.NewPoolId(a, b, xdr.LiquidityPoolFeeV18)
		tb, terr := txnbuild.NewLiquidityPoolId(txnbuild.CreditAsset{Code: ps(v, "code"), Issuer: ps(v, "a")}, txnbuild.CreditAsset{Code: ps(v, "code"), Issuer: ps(v, "b")})
		det := fmt.Sprintf("txnbuild.NewLiquidityPoolId: %x err=%v", tb[:], terr)
		if err != nil { return "", det, err }
		return hex.EncodeToString(id[:]), det, nil
	case v.ID == "1c":
		gt, err := txnbuild.TransactionFromXDR(base64.StdEncoding.EncodeToString(raw(v)))
		if err != nil { return "", "", err }
		tx, ok := gt.Transaction()
		if !ok { return "", "", errors.New("not a Transaction") }
		h, err := tx.HashHex(ps(v, "network"))
		if err != nil { return "", "", err }
		ct := tx.Operations()[2].(*txnbuild.ChangeTrust)
		lp := ct.Line.(txnbuild.LiquidityPoolShareChangeTrustAsset).LiquidityPoolParameters
		pid, err := txnbuild.NewLiquidityPoolId(lp.AssetA, lp.AssetB)
		if err != nil { return "", "", err }
		return fmt.Sprintf("hash=%s pool=%x", h, pid[:]), "", nil
	case v.Group == 2 && strings.HasPrefix(v.ID, "2m"):
		val := ps(v, "value")
		u, err := strconv.ParseUint(val, 10, 64)
		if err != nil { return "", "", na{"MuxedAccountFromAccountId takes a typed uint64; " + val + " is not representable (no lossy/string entry point)"} }
		m, err := xdr.MuxedAccountFromAccountId(ps(v, "g"), u)
		if err != nil { return "", "", err }
		addr, err := m.GetAddress()
		if err != nil { return "", "", err }
		back, err := xdr.AddressToMuxedAccount(addr)
		if err != nil { return "", "", err }
		id, _ := back.GetId()
		return strconv.FormatUint(id, 10), "", nil
	case v.Group == 2:
		val := ps(v, "value")
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil { return "", "", na{"ManageSellOffer.OfferID is a typed int64; " + val + " is not representable"} }
		op := txnbuild.ManageSellOffer{Selling: txnbuild.NativeAsset{}, Buying: txnbuild.CreditAsset{Code: "USD", Issuer: ps(v, "g")}, Amount: "1", Price: xdr.Price{N: 1, D: 1}, OfferID: n}
		verr := op.Validate()
		x, err := op.BuildXDR()
		if err != nil { return "", "", err }
		got := strconv.FormatInt(int64(x.Body.ManageSellOfferOp.OfferId), 10)
		if verr != nil { return "", "BuildXDR alone encodes " + got, verr }
		return got, "Validate() passed", nil
	case v.Group == 3 || v.ID == "6d2":
		b := raw(v)
		var env xdr.TransactionEnvelope
		rawOK := false
		if v.ID != "6d2" { // 6d2: high-level parser only
			if err := xdr.SafeUnmarshal(b, &env); err != nil { return "", "", err }
			rawOK = mhex(env) == *v.Hex
		}
		gt, err := txnbuild.TransactionFromXDR(base64.StdEncoding.EncodeToString(b))
		if err != nil { return "", "", err }
		tx, _ := gt.Transaction()
		b64, err := tx.Base64()
		if err != nil { return "", "", err }
		sdkOK := b64 == base64.StdEncoding.EncodeToString(b)
		m, err := xdr.AddressToMuxedAccount(tx.SourceAccount().AccountID)
		if err != nil { return "", "", err }
		id, _ := m.GetId()
		off := tx.Operations()[1].(*txnbuild.ManageSellOffer).OfferID
		s := fmt.Sprintf("roundtrip=%v src_id=%d offer=%d", rawOK && sdkOK, id, off)
		if !(rawOK && sdkOK) { s += fmt.Sprintf(" [raw=%v sdk=%v]", rawOK, sdkOK) }
		return s, "", nil
	case v.Group == 4 || v.Group == 5:
		return "", "", na{"go-stellar-sdk has no ScVal<->native conversion or sorted-map builder (xdr/scval.go has only String/Equals)"}
	case v.Group == 6 || v.Group == 8:
		t := ps(v, "type")
		obj := decodeTarget[t]()
		err := xdr.SafeUnmarshal(raw(v), obj)
		det := ""
		if v.ID == "6d" { // second entry point: generated UnmarshalBinary (no full-consumption check)
			var sv xdr.ScVal
			e2 := sv.UnmarshalBinary(raw(v))
			det = fmt.Sprintf("ScVal.UnmarshalBinary err=%v", e2)
		}
		if err != nil { return "", det, err }
		if v.Group == 8 { return "decoded", det, nil }
		return mhex(obj.(marshaler)), det, nil
	case v.Group == 7:
		b := raw(v)
		switch v.ID {
		case "7a":
			var m xdr.Memo
			if err := xdr.SafeUnmarshal(b, &m); err != nil { return "", "", err }
			native := *m.Text
			x, err := txnbuild.MemoText(native).ToXDR()
			if err != nil { return "", "", err }
			return mhex(x), fmt.Sprintf("native=%q", native), nil
		case "7b":
			var o xdr.Operation
			if err := xdr.SafeUnmarshal(b, &o); err != nil { return "", "", err }
			md := o.Body.ManageDataOp
			op := txnbuild.ManageData{Name: string(md.DataName), Value: []byte(*md.DataValue)}
			x, err := op.BuildXDR()
			if err != nil { return "", "", err }
			return mhex(x), fmt.Sprintf("value=%x", op.Value), nil
		default:
			var sv xdr.ScVal
			if err := xdr.SafeUnmarshal(b, &sv); err != nil { return "", "", err }
			var back xdr.ScVal
			if v.ID == "7c" {
				native := string(*sv.Str)
				s := xdr.ScString(native)
				back = xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &s}
				return mhex(back), fmt.Sprintf("native=%q", native), nil
			}
			native := string(*sv.Sym)
			s := xdr.ScSymbol(native)
			back = xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &s}
			return mhex(back), fmt.Sprintf("native=%q", native), nil
		}
	case v.Group == 9:
		switch v.ID {
		case "9E1":
			c, _ := hex.DecodeString(ps(v, "contract"))
			id, _ := new(big.Int).SetString(ps(v, "id"), 10)
			p := append(c, make([]byte, 8)...)
			id.FillBytes(p[32:])
			s, err := strkey.Encode(strkey.VersionByte(22<<3), p)
			if err != nil { return "", "", err }
			if _, derr := strkey.Decode(strkey.VersionByte(22<<3), s); derr != nil {
				return "", "Encode produced " + s + " but Decode rejects it", derr
			}
			return s, "", nil
		case "9E2", "9E4":
			obj := decodeTarget[ps(v, "type")]()
			if err := xdr.SafeUnmarshal(raw(v), obj); err != nil { return "", "", err }
			if a, ok := obj.(*xdr.ScAddress); ok { s, err := a.String(); return s, "", err }
			s, err := obj.(*xdr.MuxedAccount).GetAddress()
			return s, "", err
		case "9E3":
			k, _ := hex.DecodeString(ps(v, "key"))
			var u xdr.Uint256
			copy(u[:], k)
			sk := xdr.SignerKey{Type: xdr.SignerKeyTypeSignerKeyTypeEd25519SignedPayload, Ed25519SignedPayload: &xdr.SignerKeyEd25519SignedPayload{Ed25519: u, Payload: []byte{}}}
			s, err := sk.GetAddress()
			if err != nil { return "", "", err }
			var back xdr.SignerKey
			berr := back.SetAddress(s)
			return s, fmt.Sprintf("SignerKey.SetAddress(own output) err=%v", berr), nil
		}
		s := ps(v, "s")
		r := []rune(s)
		c := byte(r[0]) & 0xff
		if c >= 'a' && c <= 'z' { c -= 32 }
		vb := versionBytes[c]
		out, err := strkey.Decode(vb, s)
		det := ""
		if c == 'B' {
			var cb xdr.ClaimableBalanceId
			det = fmt.Sprintf("ClaimableBalanceId.DecodeFromStrkey err=%v", cb.DecodeFromStrkey(s))
		}
		if err != nil { return "", det, err }
		return hex.EncodeToString(out), det, nil
	case v.Group == 10:
		b, err := os.ReadFile(filepath.Join(dir, "..", ps(v, "file")))
		if err != nil { return "", "", err }
		var batch xdr.LedgerCloseMetaBatch
		if err := xdr.SafeUnmarshal(b, &batch); err != nil { return "", "", err }
		lcm := batch.LedgerCloseMetas[0]
		h := lcm.LedgerHeaderHistoryEntry().Header
		rt, _ := batch.MarshalBinary()
		return fmt.Sprintf("lcm=v%d seq=%d proto=%d sv_ext=%s roundtrip=%v", lcm.V, h.LedgerSeq, h.LedgerVersion, h.ScpValue.Ext.V.String(), bytes.Equal(rt, b)), "", nil
	}
	return "", "", na{"not implemented"}
}

func judge(v Vec, got string) string {
	acc := v.Expect["accept"]
	if acc == "p30" { acc = p30 }
	if acc == false { return "wrong" }
	if want, ok := v.Expect["value"].(string); ok && got != want { return "wrong" }
	return "ok"
}

func main() {
	vf := os.Args[1]
	data, _ := os.ReadFile(vf)
	var vs []Vec
	if err := json.Unmarshal(data, &vs); err != nil { panic(err) }
	want := map[string]bool{}
	for _, a := range os.Args[2:] { want[a] = true }
	ver := sdkVersion()
	for _, v := range vs {
		if len(want) > 0 && !want[v.ID] { continue }
		out := map[string]interface{}{"vector": v.ID, "sdk": "go", "version": ver, "p30": p30}
		func() {
			defer func() {
				if r := recover(); r != nil {
					out["outcome"] = "crash"
					out["detail"] = fmt.Sprintf("panic: %v", r)
				}
			}()
			got, det, err := run(v, filepath.Dir(vf))
			var n na
			switch {
			case errors.As(err, &n):
				out["outcome"], out["detail"] = "n/a", n.why
			case err != nil:
				out["outcome"], out["detail"] = "reject", strings.TrimSpace(fmt.Sprintf("%v %s", err, det))
			default:
				o := judge(v, got)
				out["outcome"], out["got"], out["detail"] = o, got, det
			}
		}()
		j, _ := json.Marshal(out)
		fmt.Println(string(j))
	}
}
