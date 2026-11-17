package xdr103

// The reported counterparts of good_builder.go: each keeps the flow that
// the compliant shape removes.

import (
	"strconv"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// (q) A method reads the builder field that holds the contract text.
func (b *builder) firstLabel() obsMovement {
	return obsMovement{Locator: b.loc(), Kind: b.labels[0]} // want `XDR103 \(warning\): xdr.ScVal.GetStr\(\) .* into JSON field xdr103.obsMovement.Kind`
}

func labelled(tx xdr.TransactionResultPair, topic xdr.ScVal) obsMovement {
	b := newBuilder(tx, topic)
	return b.firstLabel()
}

// (r) The shared formatter's result at the call site that passes the
// contract-named asset.
func (b *builder) namedAsset(named xdr.ScVal) {
	s, ok := named.GetStr()
	if !ok {
		return
	}
	a, err := xdr.NewCreditAsset(string(s), "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7")
	if err != nil {
		return
	}
	b.changes = append(b.changes, obsChange{Asset: formatAsset(a)}) // want `XDR103 \(warning\): xdr.ScVal.GetStr\(\) .* into JSON field xdr103.obsChange.Asset`
}

// (s) The text is stored whether or not it parsed.
func (b *builder) routedAnyway(v xdr.ScVal) {
	text := string(v.MustStr())
	if _, err := strconv.ParseUint(text, 10, 64); err != nil {
		b.labels = append(b.labels, "unparsed")
	}
	b.movements = append(b.movements, obsMovement{Muxed: text}) // want `XDR103 \(warning\): xdr.ScVal.MustStr\(\) .* into JSON field xdr103.obsMovement.Muxed`
}

// (t) A switch whose default keeps the value.
func (b *builder) kindAnyway(topic xdr.ScVal) {
	kind := string(topic.MustStr())
	switch kind {
	case "transfer", "mint":
	default:
		b.labels = append(b.labels, "other")
	}
	b.movements = append(b.movements, obsMovement{Kind: kind}) // want `XDR103 \(warning\): xdr.ScVal.MustStr\(\) .* into JSON field xdr103.obsMovement.Kind`
}
