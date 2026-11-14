package verdict

import (
	"reflect"
	"testing"
)

// A source build (version with build metadata) is compared on its own line, so a difference that only the main
// branch has shows in the cross-SDK comparison instead of being folded into the release.
func TestLatestPerSDKKeepsSourceBuilds(t *testing.T) {
	cols := []MatrixColumn{
		{ID: "rs-xdr-json@30.0.0", SDK: "rs-xdr-json", Version: "30.0.0", Kind: "sdk"},
		{ID: "rs-xdr-json@30.0.0+ebec5fb1c76e", SDK: "rs-xdr-json", Version: "30.0.0+ebec5fb1c76e", Kind: "sdk"},
		{ID: "go@v0.8.0", SDK: "go", Version: "v0.8.0", Kind: "sdk"},
		{ID: "go@v0.9.0", SDK: "go", Version: "v0.9.0", Kind: "sdk"},
		{ID: "rust@30.0.0:limits-default", SDK: "rust", Version: "30.0.0", Profile: "limits-default", Kind: "sdk"},
		{ID: "rust@30.0.0:limits-none", SDK: "rust", Version: "30.0.0", Profile: "limits-none", Kind: "sdk"},
		{ID: "stub@0.1.0", SDK: "stub", Version: "0.1.0", Kind: "selftest"},
	}
	got := latestPerSDK(cols)
	want := map[string]bool{
		"rs-xdr-json@30.0.0":              true,
		"rs-xdr-json@30.0.0+ebec5fb1c76e": true,
		"go@v0.9.0":                       true,
		"rust@30.0.0:limits-default":      true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("latestPerSDK = %v, want %v", got, want)
	}

	lc := LatestColumns(cols)
	if !lc["rs-xdr-json@30.0.0"] || !lc["rs-xdr-json@30.0.0+ebec5fb1c76e"] || lc["go@v0.8.0"] {
		t.Fatalf("LatestColumns = %v", lc)
	}

	m := &Matrix{Columns: cols[:2], Cells: []Cell{
		{Entry: "e", Variant: "v", Level: "json", Column: "rs-xdr-json@30.0.0", Outcome: "ok", Value: "a"},
		{Entry: "e", Variant: "v", Level: "json", Column: "rs-xdr-json@30.0.0+ebec5fb1c76e", Outcome: "ok", Value: "b"},
	}}
	x := crossSDK(m)
	if len(x) != 1 || x[0].Agree {
		t.Fatalf("a main-only difference is not a cross-SDK split: %+v", x)
	}
}
