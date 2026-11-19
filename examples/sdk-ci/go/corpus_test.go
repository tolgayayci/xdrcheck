// The corpus test an SDK maintainer adds to go-stellar-sdk's CI (docs/use-in-sdk-ci.md, Go recipe): every
// ledger and xdr variant of the corpus goes through the SDK's own generated XDR types.
//
//   - a variant whose validity is malformed or invalid must be refused by xdr.SafeUnmarshal;
//   - any other must decode, consume every byte, and re-encode to the identical bytes (the expected value at
//     the byte level is the bytes stellar-core emitted; go-stellar-sdk has no SEP-51 JSON to compare);
//   - a type the SDK does not generate is unread; a panic is a failure.
//
// The failures must be exactly the lines of expected-failures.txt, and every variant must be read or listed as
// unread. Run it with XDRCHECK_CORPUS set to the release archive (or an extracted release, or a corpus directory):
//
//	XDRCHECK_CORPUS=xdrcheck-30.0.0.tar.gz go test ./...
//
// XDRCHECK_WRITE_EXPECTED_FAILURES=1 rewrites expected-failures.txt from the run instead of checking it; review the
// result before committing it.
package sdkci

import (
	"bytes"
	"encoding"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
	xdrcheckcorpus "github.com/tolgayayci/xdrcheck/packages/go"
)

const listFile = "expected-failures.txt"

// newValue returns a fresh value of the XDR type the corpus names, or nil when the SDK has none. The corpus uses
// the type names of the XDR definitions; go-stellar-sdk spells a few differently (ScVal).
func newValue(name string) any {
	switch name {
	case "LedgerCloseMeta":
		return &xdr.LedgerCloseMeta{}
	case "LedgerHeader":
		return &xdr.LedgerHeader{}
	case "TransactionEnvelope":
		return &xdr.TransactionEnvelope{}
	case "TransactionMeta":
		return &xdr.TransactionMeta{}
	case "TransactionResult":
		return &xdr.TransactionResult{}
	case "LedgerEntry":
		return &xdr.LedgerEntry{}
	case "LedgerKey":
		return &xdr.LedgerKey{}
	case "BucketEntry":
		return &xdr.BucketEntry{}
	case "ConfigUpgradeSet":
		return &xdr.ConfigUpgradeSet{}
	case "ScVal", "SCVal":
		return &xdr.ScVal{}
	case "ContractEvent":
		return &xdr.ContractEvent{}
	case "SorobanTransactionData":
		return &xdr.SorobanTransactionData{}
	}
	return nil
}

// decode puts one variant's bytes through the SDK; it returns the failure, or "" when the variant conforms.
func decode(v *xdrcheckcorpus.Variant, raw []byte) (failure string) {
	defer func() {
		if p := recover(); p != nil {
			failure = fmt.Sprintf("crash: panic: %v", p)
		}
	}()
	val := newValue(v.XDRType)
	err := xdr.SafeUnmarshal(raw, val) // refuses trailing bytes
	switch {
	case v.MustRefuse() && err == nil:
		return fmt.Sprintf("accepted %d bytes a correct reader refuses (%s)", len(raw), v.Validity)
	case v.MustRefuse():
		return ""
	case err != nil:
		return "refused valid bytes: " + oneLine(err.Error())
	}
	again, err := val.(encoding.BinaryMarshaler).MarshalBinary()
	switch {
	case err != nil:
		return "decoded, but re-encoding failed: " + oneLine(err.Error())
	case !bytes.Equal(again, raw):
		return fmt.Sprintf("re-encoding differs: %d bytes from %d", len(again), len(raw))
	}
	return ""
}

func TestCorpus(t *testing.T) {
	path := os.Getenv("XDRCHECK_CORPUS")
	if path == "" {
		t.Fatal("XDRCHECK_CORPUS is not set: point it at the corpus release archive (xdrcheck-<version>.tar.gz)")
	}
	c, err := xdrcheckcorpus.OpenSHA256(path, os.Getenv("XDRCHECK_CORPUS_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("corpus %s from %s", c.Version, c.Source)

	var res xdrcheckcorpus.Results
	for _, e := range c.Entries {
		if e.Tier == "stress" || (e.Kind != "ledger" && e.Kind != "xdr") {
			continue // stress entries need limits (docs/release.md §3); other kinds have no bytes to decode
		}
		res.Select(e.ID)
		for _, v := range e.Variants {
			if !v.Decodable() {
				res.Unread(e.ID, v.Key, "record-marked stream")
				continue
			}
			if newValue(v.XDRType) == nil {
				res.Unread(e.ID, v.Key, "type_not_generated: "+v.XDRType)
				continue
			}
			raw, err := v.Blob()
			if err != nil {
				t.Fatal(err)
			}
			if f := decode(v, raw); f != "" {
				res.Fail(e.ID, v.Key, "L0", f)
			} else {
				res.Pass(e.ID, v.Key, "L0")
			}
		}
	}

	if os.Getenv("XDRCHECK_WRITE_EXPECTED_FAILURES") == "1" {
		f, err := os.Create(listFile)
		if err != nil {
			t.Fatal(err)
		}
		n, err := res.WriteExpectedFailures(f, "go-stellar-sdk", c.Version)
		if err == nil {
			err = f.Close()
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d lines to %s; review them before committing", n, listFile)
		return
	}
	list, err := xdrcheckcorpus.ReadExpectedFailures(listFile)
	if err != nil {
		t.Fatal(err)
	}
	cmp := res.Compare(list, true)
	var out strings.Builder
	cmp.Print(&out, "go-stellar-sdk", listFile)
	t.Log("\n" + out.String())
	if !cmp.Passed() {
		t.Fail()
	}
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
