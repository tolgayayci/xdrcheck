package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The demo is the template plus one planted bug: apart from the package comment, the name and the SEEDED BUG
// block, its source is the minimal adapter's, so the demo shows what the template does with a real bug.
func TestDemoIsTheTemplatePlusOneBug(t *testing.T) {
	demo, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := os.ReadFile("../minimal/main.go")
	if err != nil {
		t.Fatal(err)
	}
	seeded := regexp.MustCompile(`(?s)\n\t*// SEEDED BUG:.*?// END SEEDED BUG`)
	if len(seeded.FindAll(demo, -1)) != 1 {
		t.Fatal("the demo has no SEEDED BUG block, or more than one")
	}
	body := func(src []byte) string {
		s := string(seeded.ReplaceAll(src, nil))
		s = s[strings.Index(s, "\npackage main\n"):]
		return regexp.MustCompile(`name    = "[a-z]+"`).ReplaceAllString(s, `name = ""`)
	}
	if body(demo) != body(tmpl) {
		t.Error("demo/main.go differs from minimal/main.go outside the package comment, the name and the SEEDED BUG block; copy the template again")
	}
}
