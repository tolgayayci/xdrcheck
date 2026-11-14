package conform

import (
	"strings"
	"testing"
)

// A column that answers n_a at every level of an entry has not read it, and Unread names each of its variants;
// a refusal or a crash is a read; a column whose driver declares no level the run plans reads nothing; a column
// that answers every entry has nothing unread.
func TestUnread(t *testing.T) {
	skipper := stubColumn(t, "skipper@0.1.0", rules(
		map[string]any{"entry": "cap-0040/*", "do": "n_a", "code": "type_not_generated"},
		map[string]any{"entry": "cap-0038/*", "level": "L0", "do": "reject", "code": "union_arm_undeclared"},
		map[string]any{"entry": "cap-0038/*", "do": "n_a"},
	))
	reader := stubColumn(t, "reader@0.1.0", nil)
	deaf := stubColumn(t, "deaf@0.1.0", map[string]any{"levels": []string{"L4"}})
	res := run(t, Limits{}, 3, skipper, reader, deaf)

	variants := map[string]int{} // variants per entry, from the run itself
	seen := map[string]bool{}
	for _, o := range res.Observations {
		if k := o.Cell.Entry.ID + " " + o.Cell.VariantKey; !seen[k] {
			seen[k] = true
			variants[o.Cell.Entry.ID]++
		}
	}
	total := len(seen)

	per := map[string][]Unread{}
	for _, u := range res.Unread() {
		per[u.Column] = append(per[u.Column], u)
	}
	if n := len(per["reader@0.1.0"]); n != 0 {
		t.Errorf("a column that read everything has %d unread items: %v", n, per["reader@0.1.0"])
	}
	sk := per["skipper@0.1.0"]
	if len(sk) != variants["cap-0040/signed-payload-signer-added"] {
		t.Fatalf("skipper: %d unread, want every cap-0040 variant (%d): %v", len(sk), variants["cap-0040/signed-payload-signer-added"], sk)
	}
	for _, u := range sk {
		if u.Entry != "cap-0040/signed-payload-signer-added" || !strings.Contains(strings.Join(u.Reasons, ","), "L0 n_a/type_not_generated") {
			t.Errorf("skipper unread item %s", u)
		}
	}
	if n := len(per["deaf@0.1.0"]); n != total {
		t.Errorf("a driver that declares no planned level: %d unread, want all %d", n, total)
	}
	for _, u := range per["deaf@0.1.0"] {
		if !strings.Contains(u.String(), "n_a/level_not_supported") {
			t.Errorf("deaf unread item %s", u)
		}
	}
	counts := res.ReadCounts()
	if c := counts["skipper@0.1.0"]; c[0] != total || c[1] != total-len(sk) {
		t.Errorf("skipper read counts %v, want %d of %d", c, total-len(sk), total)
	}
}
