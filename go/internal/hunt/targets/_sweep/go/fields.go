package main

// Fields mode (xcheck): for each transaction of the reference cut, the fields txnbuild computes, as JSONL.
// usage: sweep -fields OUT.jsonl -cut TXS_DIR -list LIST [-passphrase P]

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// assetCID is xdr.Asset.ContractID of a txnbuild asset, as a C… strkey.
func assetCID(a txnbuild.Asset) string {
	x, err := a.ToXDR()
	if err != nil {
		return "error: " + err.Error()
	}
	id, err := x.ContractID(pass)
	if err != nil {
		return "error: " + err.Error()
	}
	s, _ := strkey.Encode(strkey.VersionByteContract, id[:])
	return s
}

func fieldsMode(out, cut, list string) {
	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	lb, err := os.ReadFile(list)
	if err != nil {
		panic(err)
	}
	dec, _ := zstd.NewReader(nil)
	for _, line := range strings.Split(string(lb), "\n") {
		seq := strings.Split(line, "\t")[0]
		if _, err := strconv.Atoi(seq); err != nil {
			continue
		}
		z, err := os.ReadFile(cut + "/" + seq + ".jsonl.zst")
		if err != nil {
			panic(err)
		}
		raw, err := dec.DecodeAll(z, nil)
		if err != nil {
			panic(err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if l == "" {
				continue
			}
			var r struct {
				Seq  uint32 `json:"seq"`
				Idx  int    `json:"idx"`
				Hash string `json:"hash"`
				Env  string `json:"env"`
				Pair string `json:"pair"`
			}
			json.Unmarshal([]byte(l), &r)
			row := txFields(r.Seq, r.Idx, r.Env)
			if _, bad := row["error"]; !bad {
				var p xdr.TransactionResultPair
				if err := xdr.SafeUnmarshalBase64(r.Pair, &p); err == nil {
					row["fee_charged"] = strconv.FormatInt(int64(p.Result.FeeCharged), 10)
				} else {
					row["fee_charged"] = "error: " + err.Error()
				}
			}
			enc.Encode(row)
		}
	}
}

func assetStr(a any) any {
	switch v := a.(type) {
	case nil:
		return nil
	case txnbuild.Asset:
		if v.IsNative() {
			return "native"
		}
		return v.GetCode() + ":" + v.GetIssuer()
	case txnbuild.ChangeTrustAsset:
		if v.IsNative() {
			return "native"
		}
		if p, ok := v.(txnbuild.LiquidityPoolShareChangeTrustAsset); ok {
			id, _ := p.GetLiquidityPoolID()
			return fmt.Sprintf("pool:%x", id[:])
		}
		return v.GetCode() + ":" + v.GetIssuer()
	}
	return fmt.Sprint(a)
}

func txFields(seq uint32, idx int, env string) map[string]any {
	row := map[string]any{"ledger": seq, "tx": idx}
	g, err := txnbuild.TransactionFromXDR(env)
	if err != nil {
		row["error"] = err.Error()
		return row
	}
	tx, ok := g.Transaction()
	if fb, isFB := g.FeeBump(); isFB {
		row["fee_source"] = fb.FeeAccount()
		if x := fb.ToXDR(); x.FeeBump != nil {
			row["fee"] = strconv.FormatInt(int64(x.FeeBump.Tx.Fee), 10)
		}
		tx, ok = fb.InnerTransaction(), true
		if h, err := tx.HashHex(pass); err == nil {
			row["inner_hash"] = h
		}
	}
	if !ok {
		return row
	}
	if h, err := g.HashHex(pass); err == nil {
		row["hash"] = h
	}
	acct := tx.SourceAccount()
	row["source"] = acct.AccountID
	if _, isFB := g.FeeBump(); !isFB {
		row["fee"] = strconv.FormatInt(tx.MaxFee(), 10)
	}
	ops := tx.Operations()
	row["op_count"] = len(ops)
	row["seq"] = strconv.FormatInt(tx.SequenceNumber(), 10)
	switch m := tx.Memo().(type) {
	case nil:
		row["memo"] = map[string]any{"type": "none"}
	case txnbuild.MemoText:
		row["memo"] = map[string]any{"type": "text", "value": string(m)}
	case txnbuild.MemoID:
		row["memo"] = map[string]any{"type": "id", "value": strconv.FormatUint(uint64(m), 10)}
	case txnbuild.MemoHash:
		row["memo"] = map[string]any{"type": "hash", "value": fmt.Sprintf("%x", m[:])}
	case txnbuild.MemoReturn:
		row["memo"] = map[string]any{"type": "return", "value": fmt.Sprintf("%x", m[:])}
	}
	tb := tx.Timebounds()
	if tb.MinTime != 0 || tb.MaxTime != 0 {
		row["time_bounds"] = map[string]any{"min": strconv.FormatInt(tb.MinTime, 10), "max": strconv.FormatInt(tb.MaxTime, 10)}
	} else {
		row["time_bounds"] = nil
	}
	var out []map[string]any
	for i, op := range ops {
		o := map[string]any{"type": reflect.TypeOf(op).Elem().Name()}
		if s := op.GetSourceAccount(); s != "" {
			o["source"] = s
		}
		switch v := op.(type) {
		case *txnbuild.Payment:
			o["destination"], o["amount"], o["asset"] = v.Destination, v.Amount, assetStr(v.Asset)
		case *txnbuild.CreateAccount:
			o["destination"], o["amount"] = v.Destination, v.Amount
		case *txnbuild.PathPaymentStrictSend:
			o["destination"], o["send_asset"], o["send_amount"], o["dest_asset"], o["dest_min"] = v.Destination, assetStr(v.SendAsset), v.SendAmount, assetStr(v.DestAsset), v.DestMin
		case *txnbuild.PathPaymentStrictReceive:
			o["destination"], o["send_asset"], o["send_max"], o["dest_asset"], o["dest_amount"] = v.Destination, assetStr(v.SendAsset), v.SendMax, assetStr(v.DestAsset), v.DestAmount
		case *txnbuild.ManageSellOffer:
			o["selling"], o["buying"], o["amount"], o["price"] = assetStr(v.Selling), assetStr(v.Buying), v.Amount, fmt.Sprintf("%d/%d", v.Price.N, v.Price.D)
		case *txnbuild.ManageBuyOffer:
			o["selling"], o["buying"], o["amount"], o["price"] = assetStr(v.Selling), assetStr(v.Buying), v.Amount, fmt.Sprintf("%d/%d", v.Price.N, v.Price.D)
		case *txnbuild.CreatePassiveSellOffer:
			o["selling"], o["buying"], o["amount"], o["price"] = assetStr(v.Selling), assetStr(v.Buying), v.Amount, fmt.Sprintf("%d/%d", v.Price.N, v.Price.D)
		case *txnbuild.ChangeTrust:
			o["asset"], o["limit"] = assetStr(v.Line), v.Limit
		case *txnbuild.BumpSequence:
			o["bump_to"] = strconv.FormatInt(v.BumpTo, 10)
		case *txnbuild.ClaimClaimableBalance:
			o["balance_id"] = v.BalanceID
		case *txnbuild.ClawbackClaimableBalance:
			o["balance_id"] = v.BalanceID
		case *txnbuild.LiquidityPoolDeposit:
			o["liquidity_pool_id"] = fmt.Sprintf("%x", v.LiquidityPoolID[:])
		case *txnbuild.LiquidityPoolWithdraw:
			o["liquidity_pool_id"] = fmt.Sprintf("%x", v.LiquidityPoolID[:])
		case *txnbuild.Clawback:
			o["from"], o["amount"], o["asset"] = v.From, v.Amount, assetStr(v.Asset)
		case *txnbuild.AllowTrust:
			o["trustor"] = v.Trustor
		case *txnbuild.SetTrustLineFlags:
			o["trustor"], o["asset"] = v.Trustor, assetStr(v.Asset)
		case *txnbuild.BeginSponsoringFutureReserves:
			o["sponsored_id"] = v.SponsoredID
		case *txnbuild.ManageData:
			o["name"] = v.Name
			if v.Value == nil {
				o["data_value"] = nil
			} else {
				o["data_value"] = fmt.Sprintf("%x", v.Value)
			}
		case *txnbuild.CreateClaimableBalance:
			if id, err := tx.ClaimableBalanceID(i); err == nil {
				o["cb_id"] = id
			} else {
				o["cb_id"] = "error: " + err.Error()
			}
		case *txnbuild.SetOptions:
			if v.HomeDomain != nil {
				o["home_domain"] = *v.HomeDomain
			}
			if v.InflationDestination != nil {
				o["inflation_dest"] = *v.InflationDestination
			}
			for k, t := range map[string]*txnbuild.Threshold{"master_weight": v.MasterWeight, "low_threshold": v.LowThreshold, "med_threshold": v.MediumThreshold, "high_threshold": v.HighThreshold} {
				if t != nil {
					o[k] = strconv.Itoa(int(*t))
				}
			}
			if v.Signer != nil {
				o["signer_key"], o["signer_weight"] = v.Signer.Address, strconv.Itoa(int(v.Signer.Weight))
			}
		}
		switch v := op.(type) {
		case *txnbuild.Payment:
			o["asset_cid"] = assetCID(v.Asset)
		case *txnbuild.Clawback:
			o["asset_cid"] = assetCID(v.Asset)
		}
		switch v := op.(type) {
		case *txnbuild.ManageSellOffer:
			o["offer_id"] = strconv.FormatInt(v.OfferID, 10)
		case *txnbuild.ManageBuyOffer:
			o["offer_id"] = strconv.FormatInt(v.OfferID, 10)
		}
		out = append(out, o)
	}
	row["operations"] = out
	return row
}
