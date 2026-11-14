package conform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func example(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "corpus", "schema", "examples", "driver-protocol", name))
	if err != nil {
		t.Fatal(err)
	}
	// The examples are pretty-printed; the wire format is one object per line.
	return []byte(strings.Join(strings.Fields(string(data)), " "))
}

// The frozen schema's own examples pass the validator.
func TestSchemaExamples(t *testing.T) {
	v := validator(t)
	d, err := v.ParseDescribe(example(t, "valid-02.json"), 1)
	if err != nil {
		t.Fatalf("valid-02 (describe): %v", err)
	}
	if *d.SDK.Version != "17.2.0" || !d.HasLevel("L4") || string(d.Decode.DefaultDepth) != "1500" {
		t.Errorf("describe decoded as %+v", d)
	}
	req := &RunRequest{ID: 7, Entry: "cap-0038/pool-issuers-order-by-bytes-not-strkey", Variant: "testnet", Level: "L1"}
	r, err := v.ParseRun(example(t, "valid-04.json"), req)
	if err != nil {
		t.Fatalf("valid-04 (run, L1 reject): %v", err)
	}
	if r.OutcomeString() != "reject" || r.ReasonCode() != "ordering" || *r.Actual.Object.EnvelopesParsed != 18 {
		t.Errorf("run decoded as %+v", r)
	}
	req = &RunRequest{ID: 10, Entry: "strkey/api-encode-signed-payload-empty", Level: "L4"}
	if _, err := v.ParseRun(example(t, "valid-06.json"), req); err != nil {
		t.Fatalf("valid-06 (run, L4 diverge): %v", err)
	}
	// Requests are not responses.
	if _, err := v.ParseDescribe(example(t, "valid-01.json"), 1); err == nil {
		t.Error("a describe request was accepted as a describe response")
	}
}

const okDescribe = `{"xcc":"xcc.driver/1","id":1,"op":"describe","driver":{"name":"d","version":"1"},"sdk":{"ecosystem":"npm","package":"p","version":"1"},"runtime":{"name":"node","version":"24"},"xdr_schema":{"probes":{"sc_address_type_muxed_contract":true,"stellar_value_signed_ms":false}},"levels":["L0"],"api_ops":["strkey.decode"],"decode":{"entry_point":"x","default_depth":null,"checks_consumed_length":true}}`

func TestDescribeValidation(t *testing.T) {
	v := validator(t)
	if _, err := v.ParseDescribe([]byte(okDescribe), 1); err != nil {
		t.Fatalf("minimal describe: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown top field":    func(s string) string { return strings.Replace(s, `"op":"describe"`, `"op":"describe","extra":1`, 1) },
		"unknown nested field": func(s string) string { return strings.Replace(s, `"version":"24"`, `"version":"24","x":1`, 1) },
		"wrong id":             func(s string) string { return strings.Replace(s, `"id":1`, `"id":2`, 1) },
		"wrong tag":            func(s string) string { return strings.Replace(s, `xcc.driver/1`, `xcc.driver/2`, 1) },
		"missing probe": func(s string) string {
			return strings.Replace(s, `"stellar_value_signed_ms":false`, `"other":false`, 1)
		},
		"probe not bool": func(s string) string {
			return strings.Replace(s, `"stellar_value_signed_ms":false`, `"stellar_value_signed_ms":"no"`, 1)
		},
		"bad level":       func(s string) string { return strings.Replace(s, `["L0"]`, `["L5"]`, 1) },
		"duplicate level": func(s string) string { return strings.Replace(s, `["L0"]`, `["L0","L0"]`, 1) },
		"unknown api op":  func(s string) string { return strings.Replace(s, `"strkey.decode"`, `"strkey.mangle"`, 1) },
		"bad ecosystem":   func(s string) string { return strings.Replace(s, `"npm"`, `"cpan"`, 1) },
		"missing decode":  func(s string) string { return s[:strings.Index(s, `,"decode"`)] + "}" },
		"missing default_depth": func(s string) string {
			return strings.Replace(s, `"default_depth":null,`, ``, 1)
		},
		"negative depth": func(s string) string { return strings.Replace(s, `"default_depth":null`, `"default_depth":-1`, 1) },
		"null sdk": func(s string) string {
			return strings.Replace(s, `"sdk":{"ecosystem":"npm","package":"p","version":"1"}`, `"sdk":null`, 1)
		},
		"null name":       func(s string) string { return strings.Replace(s, `"name":"d"`, `"name":null`, 1) },
		"protocol_error":  func(string) string { return `{"xcc":"xcc.driver/1","op":"protocol_error","error":"what?"}` },
		"not json":        func(string) string { return `describe ok` },
		"trailing data":   func(s string) string { return s + ` {}` },
		"array":           func(string) string { return `[1]` },
		"float id":        func(s string) string { return strings.Replace(s, `"id":1`, `"id":1.5`, 1) },
		"missing api_ops": func(s string) string { return strings.Replace(s, `"api_ops":["strkey.decode"],`, ``, 1) },
	} {
		line := mutate(okDescribe)
		if _, err := v.ParseDescribe([]byte(line), 1); err == nil || !IsProtocolError(err) {
			t.Errorf("%s: accepted (%v): %s", name, err, line)
		}
	}
}

const okRun = `{"xcc":"xcc.driver/1","id":5,"op":"run","entry":"e/x","variant":"testnet","level":"L0","outcome":"ok","actual":{"consumed_bytes":4,"reencoded_sha256":"0000000000000000000000000000000000000000000000000000000000000000","object":{"envelopes_rejected":[{"tx_index":0,"code":"ordering"}]},"pinpoints":[{"path":"/a","found":true,"value":null}],"api":{"value":null,"self_decode":"accepted"}},"resources":{"wall_ms":0.5}}`

func TestRunValidation(t *testing.T) {
	v := validator(t)
	req := &RunRequest{ID: 5, Entry: "e/x", Variant: "testnet", Level: "L0"}
	if _, err := v.ParseRun([]byte(okRun), req); err != nil {
		t.Fatalf("ok run: %v", err)
	}
	long := strings.Repeat("é", 501)
	for name, mutate := range map[string]func(string) string{
		"unknown field": func(s string) string {
			return strings.Replace(s, `"outcome":"ok"`, `"outcome":"ok","verdict":"conform"`, 1)
		},
		"unknown actual field": func(s string) string {
			return strings.Replace(s, `"consumed_bytes":4`, `"consumed_bytes":4,"bytes":4`, 1)
		},
		"wrong id":              func(s string) string { return strings.Replace(s, `"id":5`, `"id":4`, 1) },
		"wrong entry":           func(s string) string { return strings.Replace(s, `"entry":"e/x"`, `"entry":"e/y"`, 1) },
		"wrong level":           func(s string) string { return strings.Replace(s, `"level":"L0"`, `"level":"L1"`, 1) },
		"wrong variant":         func(s string) string { return strings.Replace(s, `"variant":"testnet"`, `"variant":"pubnet"`, 1) },
		"bad outcome":           func(s string) string { return strings.Replace(s, `"outcome":"ok"`, `"outcome":"wrong"`, 1) },
		"missing outcome":       func(s string) string { return strings.Replace(s, `"outcome":"ok",`, ``, 1) },
		"reject without reason": func(s string) string { return strings.Replace(s, `"outcome":"ok"`, `"outcome":"reject"`, 1) },
		"bad reason code": func(s string) string {
			return strings.Replace(s, `"outcome":"ok"`, `"outcome":"reject","reason":{"code":"assets_unsorted"}`, 1)
		},
		"long message": func(s string) string {
			return strings.Replace(s, `"outcome":"ok"`, `"outcome":"reject","reason":{"code":"ordering","message":"`+long+`"}`, 1)
		},
		"upper-case sha": func(s string) string {
			return strings.Replace(s, `"reencoded_sha256":"0000`, `"reencoded_sha256":"AAAA`, 1)
		},
		"short sha": func(s string) string {
			return strings.Replace(s, `0000000000000000000000000000000000000000000000000000000000000000`, `00`, 1)
		},
		"negative bytes": func(s string) string { return strings.Replace(s, `"consumed_bytes":4`, `"consumed_bytes":-4`, 1) },
		"rejected env without code": func(s string) string {
			return strings.Replace(s, `{"tx_index":0,"code":"ordering"}`, `{"tx_index":0}`, 1)
		},
		"pinpoint without found": func(s string) string { return strings.Replace(s, `"found":true,`, ``, 1) },
		"projection and pinpoints": func(s string) string {
			return strings.Replace(s, `"pinpoints":`, `"projection":{},"pinpoints":`, 1)
		},
		"bad self_decode": func(s string) string { return strings.Replace(s, `"accepted"`, `"maybe"`, 1) },
		"null actual":     func(s string) string { return s[:strings.Index(s, `"actual"`)] + `"actual":null}` },
		"null outcome":    func(s string) string { return strings.Replace(s, `"outcome":"ok"`, `"outcome":null`, 1) },
		"negative wall":   func(s string) string { return strings.Replace(s, `"wall_ms":0.5`, `"wall_ms":-1`, 1) },
	} {
		line := mutate(okRun)
		if _, err := v.ParseRun([]byte(line), req); err == nil || !IsProtocolError(err) {
			t.Errorf("%s: accepted (%v): %s", name, err, line)
		}
	}
}

func TestShutdownValidation(t *testing.T) {
	v := validator(t)
	if err := v.ParseShutdown([]byte(`{"xcc":"xcc.driver/1","id":3,"op":"shutdown","ok":true}`), 3); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"xcc":"xcc.driver/1","id":3,"op":"shutdown","ok":false}`,
		`{"xcc":"xcc.driver/1","id":2,"op":"shutdown","ok":true}`,
		`{"xcc":"xcc.driver/1","id":3,"op":"shutdown"}`,
	} {
		if err := v.ParseShutdown([]byte(bad), 3); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
