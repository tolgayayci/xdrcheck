package xdrcheckcorpus

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseExpectedFailures(t *testing.T) {
	list, err := ParseExpectedFailures(strings.NewReader("# comment\n\na/b testnet L0  # why\nc/d - unread\n"), "list")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].String() != "a/b testnet L0" || list[1].Variant != "" || list[1].Line != 4 {
		t.Fatalf("%+v", list)
	}
	for _, bad := range []string{"a/b testnet\n", "a/b testnet L0\na/b testnet L0\n"} {
		if _, err := ParseExpectedFailures(strings.NewReader(bad), "list"); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestCompareOutcomes(t *testing.T) {
	list, err := ParseExpectedFailures(strings.NewReader(strings.Join([]string{
		"still/failing testnet L0",
		"now/passing pubnet L0",
		"now/read none unread",
		"still/unread none unread",
		"selected/missing typo L0",
		"not/selected testnet L0",
	}, "\n")), "list")
	if err != nil {
		t.Fatal(err)
	}
	var r Results
	r.Fail("still/failing", "testnet", "L0", "refused")
	r.Pass("now/passing", "pubnet", "L0")
	r.Pass("now/read", "none", "L0")
	r.Unread("still/unread", "none", "type_not_generated")
	r.Fail("new/failure", "testnet", "L0", "accepted invalid input")
	r.Unread("new/unread", "none", "type_not_generated")
	r.Select("selected/missing")

	c := r.Compare(list, false)
	if c.Matched != 2 || len(c.New) != 1 || len(c.NowPassing) != 1 || len(c.NowRead) != 1 || len(c.NewUnread) != 0 || len(c.NotRun) != 1 || c.Passed() {
		t.Fatalf("%+v", c)
	}
	c = r.Compare(list, true)
	if len(c.NewUnread) != 1 || c.NewUnread[0].Entry != "new/unread" {
		t.Fatalf("require all read: %+v", c.NewUnread)
	}
	var out bytes.Buffer
	c.Print(&out, "sdk@1", "list.txt")
	for _, want := range []string{
		"NEW-FAILURE   new/failure testnet L0: accepted invalid input",
		"UNEXPECTED-PASS now/passing pubnet L0: listed as failing but now conforms; remove the line from list.txt",
		"UNEXPECTED-PASS now/read none unread: listed as unread but the column now reads it",
		"NEW-UNREAD    new/unread none: never read (type_not_generated)",
		"NOT-RUN       selected/missing typo L0 (list.txt line 5)",
		"expected failures sdk@1: 2 still as listed, 1 new failures, 1 new unread, 2 unexpected passes, 1 listed but not run",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}

	// A list written from the results passes against the same results.
	var w bytes.Buffer
	if n, err := r.WriteExpectedFailures(&w, "sdk@1", "30.0.0"); err != nil || n != 4 {
		t.Fatalf("%d lines, %v", n, err)
	}
	again, err := ParseExpectedFailures(&w, "written")
	if err != nil {
		t.Fatal(err)
	}
	if c := r.Compare(again, true); !c.Passed() {
		t.Fatalf("a written list does not pass: %+v", c)
	}
}
