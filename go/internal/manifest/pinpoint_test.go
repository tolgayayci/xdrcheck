package manifest

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestResolveSelect(t *testing.T) {
	doc := decode(t, `{"changes": [
		{"state": {"last_modified_ledger_seq": 5, "data": {"account": {"account_id": "GB", "balance": "1"}}, "ext": "v0"}},
		{"state": {"last_modified_ledger_seq": 5, "data": {"account": {"account_id": "GA", "balance": "2"}}, "ext": "v0"}},
		{"updated": {"last_modified_ledger_seq": 6, "data": {"account": {"account_id": "GA", "balance": "3"}}, "ext": "v0"}},
		{"removed": {"trustline": {"account_id": "GA", "asset": "native"}}},
		{"created": {"last_modified_ledger_seq": 6, "data": {"config_setting": {"contract_max_size_bytes": 1}}, "ext": "v0"}}
	], "keys": [{"ttl": {"key_hash": "aa"}}, {"ttl": {"key_hash": "bb"}}]}`)
	cases := []struct {
		in, key, change, want, err string
	}{
		{"/changes", `{"account": {"account_id": "GA"}}`, "updated", "/changes/2", ""},
		{"/changes", `{"account": {"account_id": "GA"}}`, "state", "/changes/1", ""},
		{"/changes", `{"account": {"account_id": "GA"}}`, "", "", "add `change`"},
		{"/changes", `{"account": {"account_id": "GC"}}`, "", "", "no element"},
		{"/changes", `{"trustline": {"account_id": "GA", "asset": "native"}}`, "removed", "/changes/3", ""},
		{"/changes", `{"config_setting": {"config_setting_id": "contract_max_size_bytes"}}`, "", "/changes/4", ""},
		{"/keys", `{"ttl": {"key_hash": "bb"}}`, "", "/keys/1", ""},
		{"/keys", `{"ttl": {"key_hash": "bb"}}`, "updated", "", "no element"},
		{"/nope", `{"ttl": {"key_hash": "bb"}}`, "", "", "does not resolve"},
		{"/changes", `{"ttl": {"key_hash": "bb"}}`, "modified", "", "not a change type"},
	}
	for _, c := range cases {
		got, err := ResolveSelect(doc, &Select{In: c.in, Key: decode(t, c.key), Change: c.change})
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s %s %s: error %v, want %q", c.in, c.key, c.change, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s %s %s: %q %v, want %q", c.in, c.key, c.change, got, err, c.want)
		}
	}
}
