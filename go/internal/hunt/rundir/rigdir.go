package rundir

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RigSchema is the manifest schema of raw rig output (`xdrcheck replay --rig`): manifest.json, status.jsonl and
// rows.jsonl in the judge's row schema. It is not a run directory; `xdrcheck replay --target <pipeline>` runs the
// rig and the judge and writes one.
const RigSchema = "xcc.rig/v1"

var rigStatuses = map[string]bool{"ingested": true, "halted": true, "skipped": true, "harness_fault": true, "dropped": true}

// IsRigDir reports whether path holds raw rig output: a manifest.json whose schema is RigSchema.
func IsRigDir(path string) bool {
	b, err := os.ReadFile(filepath.Join(path, ManifestFile))
	if err != nil {
		return false
	}
	var m struct {
		Schema string `json:"schema"`
	}
	return json.Unmarshal(b, &m) == nil && m.Schema == RigSchema
}

// ValidateRigDir checks raw rig output: the manifest names a rig and a ledger count, status.jsonl has one
// line per requested ledger with a known status, and every line of rows.jsonl is a JSON object with a kind.
// It returns the per-status counts and one message per problem.
func ValidateRigDir(path string) (map[string]int, []string) {
	var bad []string
	var m struct {
		Rig     string `json:"rig"`
		Ledgers int    `json:"ledgers"`
	}
	b, err := os.ReadFile(filepath.Join(path, ManifestFile))
	if err == nil {
		err = json.Unmarshal(b, &m)
	}
	switch {
	case err != nil:
		bad = append(bad, fmt.Sprintf("%s: %v", ManifestFile, err))
	case m.Rig == "":
		bad = append(bad, ManifestFile+": no rig")
	}
	counts := map[string]int{}
	lines := 0
	err = eachLine(filepath.Join(path, "status.jsonl"), func(n int, line []byte) {
		lines++
		var st struct {
			Ledger uint32 `json:"ledger"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(line, &st); err != nil {
			bad = append(bad, fmt.Sprintf("status.jsonl:%d: %v", n, err))
			return
		}
		if !rigStatuses[st.Status] {
			bad = append(bad, fmt.Sprintf("status.jsonl:%d: unknown status %q", n, st.Status))
		}
		counts[st.Status]++
	})
	if err != nil {
		bad = append(bad, err.Error())
	} else if m.Ledgers > 0 && lines != m.Ledgers {
		bad = append(bad, fmt.Sprintf("status.jsonl has %d lines, the manifest requests %d ledgers", lines, m.Ledgers))
	}
	err = eachLine(filepath.Join(path, "rows.jsonl"), func(n int, line []byte) {
		var r struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal(line, &r); err != nil || r.Kind == "" {
			bad = append(bad, fmt.Sprintf("rows.jsonl:%d: not a row with a kind", n))
		}
	})
	if err != nil {
		bad = append(bad, err.Error())
	}
	if len(bad) > 20 {
		bad = append(bad[:20], fmt.Sprintf("… %d more", len(bad)-20))
	}
	return counts, bad
}

// RigStatusText lists per-status counts, for example "2 halted, 18 ingested".
func RigStatusText(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", counts[k], k))
	}
	return strings.Join(parts, ", ")
}

func eachLine(path string, fn func(n int, line []byte)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	for n := 1; sc.Scan(); n++ {
		if line := sc.Bytes(); len(strings.TrimSpace(string(line))) > 0 {
			fn(n, line)
		}
	}
	return sc.Err()
}
