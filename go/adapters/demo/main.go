// Command demo is the minimal adapter (../minimal) with one bug planted on purpose, for scripts/demo.sh: its
// indexer skips failed transactions, as an indexer that stores only successful ones would. The replay then
// reports every entry with a failed transaction as mishandled, with what was expected, what was observed and
// the command that reproduces it. Everything but this comment, the name and the block marked SEEDED BUG is
// identical to ../minimal/main.go (a test checks it).
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/ingest/ledgerbackend"
	"github.com/stellar/go-stellar-sdk/support/datastore"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/tolgayayci/xdrcheck/go/adapterkit"
)

// REPLACE: your adapter's name and version (the target version you test is given to xdrcheck replay).
const (
	name    = "demo"
	version = "0.1.0"
)

func main() { os.Exit(adapterkit.Main(&minimal{sessions: map[string]*session{}})) }

// session is one replay unit's indexer state. REPLACE: your indexer's store (a database, a directory) and
// whatever you need to reach it.
type session struct {
	ledgers map[int64]adapterkit.Ledger
	cursor  *int64 // the last ledger fully stored: your indexer's own progress marker
}

type minimal struct{ sessions map[string]*session }

// Describe declares what the indexer handles. Declare only what is true; every kind you do not model is
// not_applicable and costs nothing.
func (m *minimal) Describe(adapterkit.DescribeParams) (adapterkit.DescribeResult, error) {
	maxP, minTx := 30, 10
	no := func(why string) adapterkit.Capability { return adapterkit.Capability{Supported: false, Reason: why} }
	return adapterkit.DescribeResult{
		Adapter: adapterkit.NameVersion{Name: name, Version: version},
		Target:  adapterkit.Target{Name: "xdrcheck " + name + " indexer", Version: version, VersionKind: "tag"},
		Inputs:  []string{"sep54-dir"}, // REPLACE: the inputs your indexer reads (sep54-dir, sep54-s3, rpc)
		Units:   []string{"single", "chain", "stream"},
		// sdk_limit: no gate of its own; entries beyond what the pinned SDK decodes are not run.
		Envelope: adapterkit.Envelope{Enforcement: "sdk_limit", MaxProtocol: &maxP, MinProtocolWithTransactions: &minTx,
			LedgerCloseMetaVersions: []int{0, 1, 2}, Basis: "go-stellar-sdk v0.9.0 reads ledgers up to protocol 30"},
		Observations: adapterkit.Observations{
			Receipts:     adapterkit.Capability{Supported: true, Subkinds: []string{"transactions", "operations"}},
			Transactions: adapterkit.Capability{Supported: true},
			Participants: no("the template maps receipts and transactions only"),
			StateChanges: no("the template maps receipts and transactions only"),
			Movements:    no("the template maps receipts and transactions only"),
			Addresses:    no("the template maps receipts and transactions only"),
		},
		Requirements: &adapterkit.Requirements{Network: "none"},
	}, nil
}

// Prepare creates an empty store for the session. REPLACE: create a fresh database or directory under
// p.Workdir; refuse one that already holds data you did not write.
func (m *minimal) Prepare(p adapterkit.PrepareParams) (adapterkit.PrepareResult, error) {
	m.sessions[p.Session] = &session{ledgers: map[int64]adapterkit.Ledger{}}
	return adapterkit.PrepareResult{Ready: true, TargetVersion: version, State: "clean"}, nil
}

// Ingest makes the indexer ingest the range and reports the facts behind the status. Serve has already
// refused inputs and units Describe did not declare.
func (m *minimal) Ingest(p adapterkit.IngestParams) (adapterkit.IngestResult, error) {
	s, ok := m.sessions[p.Session]
	if !ok {
		return adapterkit.IngestResult{}, adapterkit.Errorf(adapterkit.CodeUnknownSession, "session %q was not prepared", p.Session)
	}
	start, before := time.Now(), s.cursor
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.DeadlineMS)*time.Millisecond*9/10)
	defer cancel()
	failing, err := index(ctx, s, p) // REPLACE: start your indexer on p.Input and p.Range and wait for it
	sig := adapterkit.Signals{CursorBefore: before, CursorAfter: s.cursor, WallMS: time.Since(start).Milliseconds(),
		RuntimePanic: adapterkit.Some(false), FailingLedger: adapterkit.Null[int64](), Phase: adapterkit.Null[string]()}
	res := adapterkit.IngestResult{Status: adapterkit.StatusCompleted, LastLedger: s.cursor, Signals: sig}
	if err != nil {
		res.Status = adapterkit.StatusHalted // stopped on its own below range.end
		if ctx.Err() != nil {
			res.Status = adapterkit.StatusTimeout // still working at the deadline
		}
		res.Signals.FailingLedger, res.Signals.Phase = adapterkit.Some(failing), adapterkit.Some("process")
		res.Signals.RowsForFailingLedger = adapterkit.Some(int64(0))
		res.Signals.StderrTail = adapterkit.Some(err.Error())
	}
	return res, nil
}

// index is the stand-in indexer: it reads each ledger of the range from the SEP-54 directory and stores its
// receipt and transactions, moving the cursor only after a ledger is stored whole.
func index(ctx context.Context, s *session, p adapterkit.IngestParams) (int64, error) {
	ds, err := datastore.NewDataStore(ctx, datastore.DataStoreConfig{Type: "Filesystem", Params: map[string]string{"destination_path": p.Input.Path}})
	if err != nil {
		return p.Range.Start, err
	}
	schema, err := datastore.LoadSchema(ctx, ds, datastore.DataStoreConfig{NetworkPassphrase: p.Network.Passphrase})
	if err != nil {
		return p.Range.Start, err
	}
	backend, err := ledgerbackend.NewBufferedStorageBackend(ledgerbackend.BufferedStorageBackendConfig{BufferSize: 10, NumWorkers: 2, RetryLimit: 3, RetryWait: 100 * time.Millisecond}, ds, schema)
	if err != nil {
		return p.Range.Start, err
	}
	defer backend.Close()
	if err := backend.PrepareRange(ctx, ledgerbackend.BoundedRange(uint32(p.Range.Start), uint32(p.Range.End))); err != nil {
		return p.Range.Start, err
	}
	for seq := p.Range.Start; seq <= p.Range.End; seq++ {
		lcm, err := backend.GetLedger(ctx, uint32(seq))
		if err != nil {
			return seq, err
		}
		l, err := facts(lcm, p.Network.Passphrase)
		if err != nil {
			return seq, err
		}
		s.ledgers[seq], s.cursor = l, adapterkit.Int64(seq)
	}
	return 0, nil
}

// facts derives one ledger's receipt and transaction list from the ledger itself, never from log text.
func facts(lcm xdr.LedgerCloseMeta, passphrase string) (adapterkit.Ledger, error) {
	l := adapterkit.Ledger{LedgerSeq: int64(lcm.LedgerSequence()), LedgerHash: lcm.LedgerHash().HexString()}
	reader, err := ingest.NewLedgerTransactionReaderFromLedgerCloseMeta(passphrase, lcm)
	if err != nil {
		return l, err
	}
	defer reader.Close()
	var nTx, nOps int64
	for {
		tx, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return l, err
		}
		// SEEDED BUG: a failed transaction is skipped, so it is neither stored nor counted.
		if !tx.Successful() {
			continue
		}
		// END SEEDED BUG
		i, ok := int(tx.Index)-1, tx.Successful() // a fee bump: whether the inner transaction succeeded
		l.Transactions = append(l.Transactions, adapterkit.ObsTransaction{Hash: tx.Hash.HexString(), Index: &i,
			Successful: &ok, FeeCharged: strconv.FormatInt(int64(tx.Result.Result.FeeCharged), 10)})
		nTx, nOps = nTx+1, nOps+int64(len(tx.Envelope.Operations()))
	}
	l.Receipt = &adapterkit.Receipt{Transactions: &nTx, Operations: &nOps}
	return l, nil
}

// Observe returns what the indexer stored for the range. REPLACE: one query per kind against your store, each
// stored record mapped to one fact; a ledger you hold nothing for is left out (that is how drops are seen).
func (m *minimal) Observe(p adapterkit.ObserveParams) (adapterkit.Observation, error) {
	s, ok := m.sessions[p.Session]
	if !ok {
		return adapterkit.Observation{}, adapterkit.Errorf(adapterkit.CodeUnknownSession, "session %q was not prepared", p.Session)
	}
	d, _ := m.Describe(adapterkit.DescribeParams{})
	o := adapterkit.Observation{Schema: adapterkit.ObservationSchema, Range: p.Range, Kinds: adapterkit.ProvidedKinds(d.Observations, p.Kinds), Ledgers: []adapterkit.Ledger{}}
	for seq := p.Range.Start; seq <= p.Range.End; seq++ {
		if l, held := s.ledgers[seq]; held {
			if !o.Kinds.Provided(adapterkit.KindReceipts) {
				l.Receipt = nil
			}
			if !o.Kinds.Provided(adapterkit.KindTransactions) {
				l.Transactions = nil
			}
			o.Ledgers = append(o.Ledgers, l)
		}
	}
	return o, nil
}

// Teardown drops the session's store. REPLACE: drop your database or remove the directory.
func (m *minimal) Teardown(p adapterkit.TeardownParams) (adapterkit.TeardownResult, error) {
	delete(m.sessions, p.Session)
	return adapterkit.TeardownResult{OK: true}, nil
}
