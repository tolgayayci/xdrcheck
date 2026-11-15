package findings

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/report"
)

// FindReports returns every `xcc.report/v1` file under dir, recursively, in path order. Other JSON files in the
// directory (matrices, describe blocks, selftest results) are skipped; a JSON file that cannot be read far
// enough to see its schema is an error.
func FindReports(dir string) ([]string, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, errors.New(dir + " is not a directory")
	}
	var out []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		ok, err := IsReport(p)
		if err != nil {
			return err
		}
		if ok {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// IsReport reports whether the JSON file at path is an `xcc.report/v1` document. It reads top-level keys until
// it finds "schema", skipping other values token by token, so a large report is not loaded into memory.
func IsReport(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 64<<10))
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return false, nil
		}
		return false, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if tok != json.Delim('{') {
		return false, nil
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return false, &os.PathError{Op: "read", Path: path, Err: err}
		}
		if key == "schema" {
			var s any
			if err := dec.Decode(&s); err != nil {
				return false, &os.PathError{Op: "read", Path: path, Err: err}
			}
			return s == report.Schema, nil
		}
		if err := skipValue(dec); err != nil {
			return false, &os.PathError{Op: "read", Path: path, Err: err}
		}
	}
	return false, nil
}

func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return nil
		}
	}
}
