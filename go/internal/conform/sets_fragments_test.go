package conform

import (
	"strings"
	"testing"
)

// Fragments add columns and [extend] members; a column defined twice, an [extend] of a set the main file does
// not define, a [sets] table in a fragment, and a set naming a column no file defines are refused. The floor
// and limits keys are read and kept.
func TestSetsFragments(t *testing.T) {
	col := func(id, ver string) string {
		return `[columns."` + id + `"]
sdk = "stub"
kind = "selftest"
ecosystem = "other"
package = "p"
target = "p"
version = "` + ver + `"
role = "selftest"
dir = "drivers/stub"
run = ["bin/x"]
`
	}
	main := []byte("[sets]\nbase = [\"stub@1\"]\nother = [\"@base\"]\n")
	ok := []Fragment{
		{Path: "a.toml", Data: []byte(col("stub@1", "1") + "floor = {L0 = 0.95}\nlimits = {memory = \"1G\", tasks = 256, cpu_seconds = 120, nofile = 256, fsize = \"64M\", as = \"off\"}\n")},
		{Path: "b.toml", Data: []byte(col("stub@2", "2") + "\n[extend]\nbase = [\"stub@2\"]\n")},
	}
	s, err := ParseSetsFiles(main, ok, "sets.toml", "/r")
	if err != nil {
		t.Fatal(err)
	}
	cols, err := s.Resolve("other")
	if err != nil || len(cols) != 2 || cols[1].ID != "stub@2" {
		t.Errorf("[extend] not applied through an include: %v %v", cols, err)
	}
	c := s.Columns["stub@1"]
	if c.Floor["L0"] != 0.95 || c.Limits == nil || c.Limits.Memory != "1G" || c.Limits.CPUSeconds != 120 || c.Limits.AS != "off" {
		t.Errorf("floor and limits not read: %v %+v", c.Floor, c.Limits)
	}
	for want, frags := range map[string][]Fragment{
		"defined twice":  {ok[0], {Path: "c.toml", Data: []byte(col("stub@1", "1"))}},
		"no such set":    {ok[0], {Path: "c.toml", Data: []byte("[extend]\nmissing = [\"stub@1\"]\n")}},
		"unknown keys":   {ok[0], {Path: "c.toml", Data: []byte("[sets]\nx = [\"stub@1\"]\n")}},
		"unknown column": {{Path: "c.toml", Data: []byte(col("stub@2", "2"))}},
	} {
		if _, err := ParseSetsFiles(main, frags, "sets.toml", "/r"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}
