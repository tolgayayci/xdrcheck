// Package bugs holds the seeded-bug indexers: the baseline indexer with exactly one deliberate defect switched
// on (`baseline --bug NAME`). They are the replay harness's own test. Each must land in its documented class and
// qualifier on its demonstrating entries, which is how every branch of the classifier is shown to fire, including
// the ones no real indexer has produced on demand (a crash, a silent drop, a dirty refusal).
//
// A bug changes at most three things, and nothing else:
//
//   - Gates: the limits the indexer both declares and enforces;
//   - Describe: what the adapter declares beyond the gates (a modelling choice, a declared limit the indexer
//     does not keep);
//   - Seed: the defect inside the indexer, run on each ledger after the baseline derived its facts and before
//     anything is written (indexer.Seed).
//
// The target is named `xdrcheck/NAME`, which the harness reports as a self-test target, never a pipeline.
//
// What each bug must produce is in table.json beside this file; scripts/harness-selftest.sh (`make
// harness-selftest`) replays every bug over its entries and checks the report against it (selftest.go).
package bugs

import (
	"fmt"
	"slices"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
	"github.com/tolgayayci/xdrcheck/go/adapters/baseline/indexer"
)

// Bug is one seeded defect.
type Bug struct {
	Name     string
	Does     string                           // one line: what the defect is
	Gates    func(*indexer.Gates)             // optional: changes the limits the indexer declares and enforces
	Describe func(*adapterkit.DescribeResult) // optional: changes what the adapter declares
	Seed     func() indexer.Seed              // optional: a fresh instance of the defect for one indexer run
}

// None is the name of the unmodified baseline in the table.
const None = "none"

// Lookup returns the named bug; "" and "none" are the baseline (nil, no error).
func Lookup(name string) (*Bug, error) {
	if name == "" || name == None {
		return nil, nil
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("unknown seeded bug %q; known: %v", name, Names())
}

// Names lists every seeded bug, in table order.
func Names() []string {
	out := make([]string, 0, len(all))
	for _, b := range all {
		out = append(out, b.Name)
	}
	return out
}

// seed wraps a function as an indexer.Seed.
type seed func(l *ledger) indexer.Outcome

func (f seed) Ledger(lcm xdr.LedgerCloseMeta, doc *indexer.Doc, passphrase string) indexer.Outcome {
	return f(&ledger{lcm: lcm, doc: doc, passphrase: passphrase})
}

func stateless(f func(l *ledger) indexer.Outcome) func() indexer.Seed {
	return func() indexer.Seed { return seed(f) }
}

// all is the table of seeded bugs, in the order of the specification's table.
var all = []Bug{
	{Name: "truncate-address-56", Does: "stores every address in a 56-character column",
		Seed: stateless(truncateAddresses)},
	{Name: "payload-dropped", Does: "keeps only the 32-byte key of a signed-payload signer",
		Seed: stateless(dropSignerPayload)},
	{Name: "drop-ledger-silently", Does: "skips a ledger whose transaction set is empty or whose protocol is odd, advancing anyway",
		Seed: stateless(dropLedgerSilently)},
	{Name: "drop-contract-trustline", Does: "derives trustline history from ChangeTrust operations only",
		Seed: stateless(dropContractTrustlines)},
	{Name: "extra-fee-rows", Does: "control, not a bug: stores the fee as a balance state change and the initial authorisation as its own change, and declares that modelling",
		Describe: declareInitialAuthorizationSeparate, Seed: stateless(extraFeeRows)},
	{Name: "panic-on-signed-payload", Does: "dereferences nil on a signed-payload signer",
		Seed: stateless(panicOnSignedPayload)},
	{Name: "loop-forever", Does: "spins on a fee-bump whose inner transaction failed",
		Seed: stateless(loopOnFailedInnerFeeBump)},
	{Name: "exit-permanent-error", Does: "returns an error and exits non-zero on a signed-payload signer, nothing written",
		Seed: stateless(exitOnSignedPayload)},
	{Name: "halt-after-partial-write", Does: "writes half the ledger's records, then exits",
		Seed: stateless(haltAfterPartialWrite)},
	{Name: "refuse-protocol-gate", Does: "built with maximum protocol 28; refuses newer ledgers cleanly through its declared gate",
		Gates: func(g *indexer.Gates) { g.MaxProtocol = 28 }},
	{Name: "fake-refusal", Does: "claims a gate refusal on a Protocol 28 ledger, inside its declared envelope",
		Seed: stateless(fakeRefusal)},
	{Name: "dirty-refusal", Does: "declares maximum protocol 28 and refuses newer ledgers through that gate, but writes their records first",
		Describe: func(d *adapterkit.DescribeResult) { p := 28; d.Envelope.MaxProtocol = &p }, Seed: stateless(dirtyRefusal)},
	{Name: "fabricate-m-from-memo", Does: "builds an M… destination from a text or hash memo",
		Seed: stateless(fabricateMuxedFromMemo)},
	{Name: "participants-from-auth", Does: "adds every address in Soroban authorisation entries as a participant",
		Seed: stateless(participantsFromAuth)},
	{Name: "participants-from-envelope", Does: "adds operation destinations of failed transactions as participants",
		Seed: stateless(participantsFromEnvelope)},
	{Name: "muxed-only-identity", Does: "stores the M… form of a muxed participant and no base account",
		Seed: stateless(muxedOnlyIdentity)},
	{Name: "credit-from-forged-event", Does: "credits a classic asset from any transfer-shaped event naming it, without checking the emitter is that asset's contract",
		Seed: stateless(creditFromForgedEvent)},
	{Name: "double-count-transfer", Does: "records a custom-token transfer once from the event and once more from the raw contract event",
		Seed: stateless(doubleCountTransfer)},
	{Name: "float-amounts", Does: "passes amounts through a 64-bit float",
		Seed: stateless(floatAmounts)},
	{Name: "void-means-zero", Does: "treats a Void routing ID as muxed ID 0",
		Seed: stateless(voidMeansZero)},
	{Name: "memory-hog", Does: "keeps every ledger it has read in memory",
		Seed: func() indexer.Seed { return &memoryHog{} }},
	{Name: "header-protocol-parser", Does: "picks its parser from the header's protocol version",
		Seed: stateless(headerProtocolParser)},
}

func declareInitialAuthorizationSeparate(d *adapterkit.DescribeResult) {
	m := &d.Observations.StateChanges.Modelling
	if !slices.Contains(*m, "initial_authorization_separate") {
		*m = append(slices.Clone(*m), "initial_authorization_separate")
	}
}
