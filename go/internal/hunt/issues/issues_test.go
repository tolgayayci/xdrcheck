package issues

import (
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt/rundir"
)

func TestIssuesFileValidates(t *testing.T) {
	if err := rundir.ValidateValue(rundir.SchemaIssues, Raw()); err != nil {
		t.Fatal(err)
	}
	all, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	is, err := Find(all, "stellar/js-stellar-sdk#1766")
	if err != nil || is.Prefix != "17.2.0" || is.Fixed != "17.2.1" {
		t.Fatal(is, err)
	}
	vs, err := Corpus("../../../../corpus")
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range all {
		if i.CorpusEntry != "" && len(ByEntry(vs, i.CorpusEntry)) == 0 {
			t.Errorf("%s: corpus entry %s has no ledger", i.ID, i.CorpusEntry)
		}
	}
}
