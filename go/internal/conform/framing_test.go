package conform

import (
	"path/filepath"
	"testing"

	"github.com/tolgayayci/xdrcheck/go/internal/manifest"
)

// A record-mark error vector is sent to the driver as the record-marked stream it is, with its frame index.
func TestRequestFramesRecordMarkedVariants(t *testing.T) {
	c := loadCorpus(t)
	e, err := manifest.LoadEntry(filepath.Join("..", "..", "..", "corpus", "schema", "examples", "manifest-entry", "valid-05.json"))
	if err != nil {
		t.Fatal(err)
	}
	v := e.Variants[0]
	req, err := Request(c, &Cell{Entry: e, Variant: v, VariantKey: e.VariantKey(v), Level: "L0", Column: &Column{ID: "a@1"}})
	if err != nil {
		t.Fatal(err)
	}
	in := req.Input
	if in.Framing != "record-marked" || in.FrameIndex == nil || *in.FrameIndex != 0 {
		t.Errorf("framing %q frame %v", in.Framing, in.FrameIndex)
	}
}
