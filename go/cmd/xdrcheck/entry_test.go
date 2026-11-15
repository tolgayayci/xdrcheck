package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const entryCorpus = "../../../corpus"

func runEntry(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := entryMain(append([]string{"--corpus", entryCorpus}, args...), &out, &errb)
	return rc, out.String(), errb.String()
}

func TestEntryListByCap(t *testing.T) {
	rc, out, _ := runEntry(t, "--cap", "40")
	if rc != 0 || !strings.Contains(out, "cap-0040/signed-payload-signer-added\tledger\tCAP-0040\t") {
		t.Fatalf("rc %d, out:\n%s", rc, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.Contains(strings.Split(line, "\t")[2], "CAP-0040") {
			t.Errorf("listed an entry without CAP 40: %s", line)
		}
	}
	if rc, _, _ := runEntry(t, "--list", "no-such-group/*"); rc != 1 {
		t.Errorf("an empty listing exits %d, want 1", rc)
	}
}

func TestEntryShow(t *testing.T) {
	rc, out, _ := runEntry(t, "cap-0040/signed-payload-signer-added")
	if rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	for _, want := range []string{"CAP-0040", "variants", "expected", "known indexer divergences", "on mainnet", "xdrcheck conform run --entries"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	rc, _, errs := runEntry(t, "signed-payload-signer-added")
	if rc != 2 || !strings.Contains(errs, "did you mean: cap-0040/signed-payload-signer-added") {
		t.Errorf("a partial ID: rc %d, %s", rc, errs)
	}
}

func TestEntryDecoded(t *testing.T) {
	for _, args := range [][]string{
		{"--decoded", "cap-0040/signed-payload-signer-added"},
		{"--decoded", "testnet", "cap-0040/signed-payload-signer-added"},
		{"--decoded", "1", "cap-0040/signed-payload-signer-added"},
	} {
		rc, out, errs := runEntry(t, args...)
		var v map[string]any
		if rc != 0 || json.Unmarshal([]byte(out), &v) != nil || v["v1"] == nil && v["v0"] == nil && v["v2"] == nil {
			t.Errorf("%v: rc %d, %s, %.200s", args, rc, errs, out)
		}
	}
	if rc, _, errs := runEntry(t, "--decoded", "mars", "cap-0040/signed-payload-signer-added"); rc != 2 || !strings.Contains(errs, "variants: testnet") {
		t.Errorf("an unknown variant: rc %d, %s", rc, errs)
	}
}
