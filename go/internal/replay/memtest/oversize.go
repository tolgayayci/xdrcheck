package memtest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// OversizeAdapter is the seeded adapter of T-mem-2: it stands between the harness and a real adapter (argv) and
// passes every line through, except that the first observe request any process of it sees — the one that
// creates marker — is answered with a response line of size bytes instead of the real adapter's answer. The
// harness must stop reading that line at its size cap, record a harness fault for the unit and go on with a
// fresh adapter process, which then behaves. It returns the exit code.
func OversizeAdapter(marker string, size int64, argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "oversize-adapter: no adapter command")
		return 2
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "oversize-adapter:", err)
		return 2
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "oversize-adapter:", err)
		return 2
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "oversize-adapter:", err)
		return 2
	}
	var mu sync.Mutex
	replace := map[int64]bool{} // request IDs whose response is replaced
	go func() {
		r := bufio.NewReaderSize(os.Stdin, 1<<20)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				var req struct {
					ID     int64  `json:"id"`
					Method string `json:"method"`
				}
				if json.Unmarshal(line, &req) == nil && req.Method == "observe" {
					if f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err == nil {
						fmt.Fprintf(f, "observe request %d answered with %d bytes\n", req.ID, size)
						f.Close()
						mu.Lock()
						replace[req.ID] = true
						mu.Unlock()
					}
				}
				in.Write(line)
			}
			if err != nil {
				in.Close()
				return
			}
		}
	}()
	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	r := bufio.NewReaderSize(out, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var resp struct {
				ID int64 `json:"id"`
			}
			json.Unmarshal(line, &resp)
			mu.Lock()
			big := replace[resp.ID]
			mu.Unlock()
			if big {
				if werr := writeOversize(w, resp.ID, size); werr != nil {
					return 0 // the harness stopped reading and killed the group
				}
			} else {
				w.Write(line)
			}
			if w.Flush() != nil {
				return 0
			}
		}
		if err != nil {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		return 1
	}
	return 0
}

// writeOversize writes an observe response of size bytes: valid JSON in shape, with the bulk in one string.
func writeOversize(w io.Writer, id int64, size int64) error {
	head := fmt.Sprintf(`{"xcc":"xcc.adapter/1","id":%d,"method":"observe","result":{"padding":"`, id)
	tail := "\"}}\n"
	if _, err := io.WriteString(w, head); err != nil {
		return err
	}
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for left := size - int64(len(head)+len(tail)); left > 0; {
		n := min(left, int64(len(chunk)))
		if _, err := w.Write(chunk[:n]); err != nil {
			return err
		}
		left -= n
	}
	_, err := io.WriteString(w, tail)
	return err
}
