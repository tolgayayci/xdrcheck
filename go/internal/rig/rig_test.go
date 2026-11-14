package rig

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseLedgers(t *testing.T) {
	got, err := ParseLedgers("10-12, 5,11,20")
	if err != nil {
		t.Fatal(err)
	}
	if want := []uint32{5, 10, 11, 12, 20}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	f := filepath.Join(t.TempDir(), "l.tsv")
	os.WriteFile(f, []byte("seq\tera\n7\tx\n3\ty\n"), 0o644)
	if got, err := ParseLedgers("@" + f); err != nil || !slices.Equal(got, []uint32{3, 7}) {
		t.Fatalf("file: %v %v", got, err)
	}
	if _, err := ParseLedgers("9-3"); err == nil {
		t.Fatal("inverted range accepted")
	}
}

func TestSegmentsAndShard(t *testing.T) {
	segs := Segments([]uint32{1, 2, 3, 7, 9, 10})
	if len(segs) != 3 || segs[0] != (Segment{1, 3}) || segs[1] != (Segment{7, 7}) || segs[2] != (Segment{9, 10}) {
		t.Fatalf("segments %v", segs)
	}
	parts := Shard(segs, 2)
	n := 0
	for _, p := range parts {
		for _, s := range p {
			n += s.Len()
		}
	}
	if len(parts) != 2 || n != 6 {
		t.Fatalf("shard %v", parts)
	}
	if got := Shard(segs, 8); len(got) != 3 {
		t.Fatalf("empty shards kept: %v", got)
	}
}

func TestRaw(t *testing.T) {
	for in, want := range map[string]string{"12.3456789": "123456789", "-0.0000001": "-1", "5": "50000000",
		"922337203685.4775807": "9223372036854775807", "30051117979.7070465": "300511179797070465"} {
		if got, ok := Raw(in, 7); !ok || got != want {
			t.Errorf("Raw(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	if _, ok := Raw("1.123456789", 7); ok {
		t.Error("eight decimals accepted")
	}
}
