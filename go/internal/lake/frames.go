package lake

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrame bounds one record of a meta stream (the largest corpus ledger is about 6.5 MB).
const MaxFrame = 256 << 20

// Frame is the position of one record of a record-marked stream: Offset is where its payload starts.
type Frame struct {
	Offset int64
	Length int64
}

// ScanFrames walks a stellar-core meta stream (RFC 5531 record marks, as `--metadata-output-stream` writes it)
// and calls fn with each record's position and payload. The payload slice is reused between calls.
func ScanFrames(r io.Reader, fn func(i int, f Frame, payload []byte) error) error {
	var (
		head [4]byte
		off  int64
		buf  []byte
	)
	for i := 0; ; i++ {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("record %d: %w", i, err)
		}
		off += 4
		mark := binary.BigEndian.Uint32(head[:])
		if mark&0x80000000 == 0 {
			return fmt.Errorf("record %d: fragmented records are not supported", i)
		}
		n := int64(mark & 0x7fffffff)
		if n > MaxFrame {
			return fmt.Errorf("record %d: %d bytes exceeds the %d-byte limit", i, n, MaxFrame)
		}
		if int64(cap(buf)) < n {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if err := fn(i, Frame{Offset: off, Length: n}, buf); err != nil {
			return err
		}
		off += n
	}
}
