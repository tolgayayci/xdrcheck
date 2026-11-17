package xdr103

// Compliant shapes from a small JSON-emitting reader: a builder that keeps a
// transaction hash next to contract-supplied text, a formatter shared by a
// contract-supplied and a ledger-supplied value, an ID that parsed as an
// integer, and an event kind fixed by a switch on literals.

import (
	"strconv"

	"github.com/stellar/go-stellar-sdk/xdr"
)

type obsLocator struct {
	TxHash string `json:"tx_hash"`
}

type obsMovement struct {
	Locator obsLocator `json:"locator"`
	Kind    string     `json:"kind"`
	Asset   string     `json:"asset"`
	Muxed   string     `json:"muxed_id"`
}

type obsChange struct {
	Locator obsLocator `json:"locator"`
	Asset   string     `json:"asset"`
}

type builder struct {
	hash      string
	labels    []string
	movements []obsMovement
	changes   []obsChange
}

// (l) A method reads the builder's hash; another field of the same builder
// holds contract-supplied text. The hash is not that text.
func newBuilder(tx xdr.TransactionResultPair, topic xdr.ScVal) *builder {
	b := &builder{hash: xdr.Hash(tx.TransactionHash).HexString()}
	if s, ok := topic.GetStr(); ok {
		b.labels = append(b.labels, string(s))
	}
	b.record()
	return b
}

func (b *builder) record() {
	b.movements = append(b.movements, obsMovement{Locator: b.loc()})
}

func (b *builder) loc() obsLocator {
	return obsLocator{TxHash: b.hash}
}

// (m) One formatter, two call sites: a contract-named asset is formatted at
// one (and dropped, see (o)), a ledger entry's asset at the other. The
// second call's result carries only the ledger entry's labels.
func formatAsset(a xdr.Asset) string { return a.StringCanonical() }

func (b *builder) trustline(t xdr.TrustLineEntry, named xdr.ScVal) {
	if s, ok := named.GetStr(); ok {
		if a, err := xdr.NewCreditAsset(string(s), "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7"); err == nil {
			_ = formatAsset(a)
		}
	}
	asset := formatAsset(xdr.Asset{Type: t.Asset.Type, AlphaNum4: t.Asset.AlphaNum4, AlphaNum12: t.Asset.AlphaNum12})
	b.changes = append(b.changes, obsChange{Locator: b.loc(), Asset: asset})
}

// (n) A routing ID stored only after it parsed as an unsigned integer.
func (b *builder) routed(v xdr.ScVal) {
	s, ok := v.GetStr()
	if !ok {
		return
	}
	text := string(s)
	if id, err := strconv.ParseUint(text, 10, 64); err == nil {
		b.movements = append(b.movements, obsMovement{Muxed: text, Asset: strconv.FormatUint(id, 16)})
	}
}

// (o) An event kind read from a contract string but kept only when it is one
// of a few literals.
func (b *builder) kind(topic xdr.ScVal) {
	s, ok := topic.GetStr()
	if !ok {
		return
	}
	kind := string(s)
	switch kind {
	case "transfer", "mint", "burn":
	default:
		return
	}
	b.movements = append(b.movements, obsMovement{Kind: kind})
}
