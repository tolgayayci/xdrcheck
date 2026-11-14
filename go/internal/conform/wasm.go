package conform

import (
	"bytes"
	"errors"
)

// specSection is the custom section that holds a contract interface (SEP-48).
var specSection = []byte("contractspecv0")

// SpecSections returns where each contractspecv0 custom section's payload lies in a Wasm module, in module
// order: the same reading as the corpus's section reader (crates/xdrcheck-xdr/src/spec.rs). It is handed to drivers
// whose SDK decodes entry streams but has no Wasm reader; it never judges anything.
func SpecSections(wasm []byte) ([]SpecSection, error) {
	if len(wasm) < 8 || !bytes.Equal(wasm[:4], []byte("\x00asm")) || !bytes.Equal(wasm[4:8], []byte{1, 0, 0, 0}) {
		return nil, errors.New("not a Wasm version 1 module")
	}
	var out []SpecSection
	i := 8
	for i < len(wasm) {
		id := wasm[i]
		size, j, err := leb32(wasm, i+1, len(wasm))
		if err != nil {
			return nil, err
		}
		end := j + int(size)
		if end > len(wasm) || end < j {
			return nil, errors.New("a section runs past the end of the module")
		}
		if id == 0 {
			n, k, err := leb32(wasm, j, end)
			if err != nil {
				return nil, err
			}
			nameEnd := k + int(n)
			if nameEnd > end || nameEnd < k {
				return nil, errors.New("a custom section name runs past its section")
			}
			if bytes.Equal(wasm[k:nameEnd], specSection) {
				out = append(out, SpecSection{Offset: nameEnd, Length: end - nameEnd})
			}
		}
		i = end
	}
	return out, nil
}

func leb32(b []byte, i, limit int) (uint32, int, error) {
	var r uint64
	for shift := 0; shift < 35; shift += 7 {
		if i >= limit {
			return 0, 0, errors.New("truncated LEB128 value")
		}
		x := b[i]
		i++
		r |= uint64(x&0x7f) << shift
		if x&0x80 == 0 {
			if r > 0xffffffff {
				return 0, 0, errors.New("LEB128 value exceeds u32")
			}
			return uint32(r), i, nil
		}
	}
	return 0, 0, errors.New("LEB128 value is longer than 5 bytes")
}
