package dataset

import (
	"bufio"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tolgayayci/xdrcheck/go/internal/hunt"
)

// ScanTable streams the rows of a TSV table, file by file. fn gets the column index of the file's header and
// the row's fields; it returns false to stop. Columns named in the table's filename_columns are appended to
// each row from the file name.
func (m *Manifest) ScanTable(name string, fn func(cols map[string]int, row []string) bool) error {
	t := m.Tables[name]
	if t == nil {
		return fmt.Errorf("no table %q in dataset %s", name, m.Version)
	}
	if t.Missing != "" {
		return hunt.Missing("table "+name, t.Missing)
	}
	if t.Format != "tsv" {
		return fmt.Errorf("table %s is %s; only tsv tables are read without a query engine", name, t.Format)
	}
	paths, err := m.TablePaths(name)
	if err != nil {
		return err
	}
	type fc struct {
		col string
		re  *regexp.Regexp
	}
	var fcs []fc
	for c, p := range t.FilenameColumns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("table %s: filename column %s: %v", name, c, err)
		}
		fcs = append(fcs, fc{c, re})
	}
	for _, p := range paths {
		stop, err := scanFile(p, func(cols map[string]int, row []string) bool {
			return fn(cols, row)
		}, func(cols map[string]int) []string {
			var extra []string
			for _, f := range fcs {
				cols[f.col] = len(cols)
				v := ""
				if m := f.re.FindStringSubmatch(filepath.Base(p)); len(m) > 1 {
					v = m[1]
				}
				extra = append(extra, v)
			}
			return extra
		})
		if err != nil {
			return fmt.Errorf("%s: %v", p, err)
		}
		if stop {
			return nil
		}
	}
	return nil
}

func scanFile(path string, fn func(map[string]int, []string) bool, extra func(map[string]int) []string) (bool, error) {
	rc, err := OpenText(path)
	if err != nil {
		return false, err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 1<<20), 256<<20)
	var cols map[string]int
	var add []string
	for sc.Scan() {
		line := sc.Text()
		if cols == nil {
			cols = map[string]int{}
			for i, c := range strings.Split(line, "\t") {
				cols[c] = i
			}
			add = extra(cols)
			continue
		}
		row := strings.Split(line, "\t")
		if len(add) > 0 {
			row = append(row, add...)
		}
		if !fn(cols, row) {
			return true, nil
		}
	}
	return false, sc.Err()
}

// Col returns a row's value of a column, or "".
func Col(cols map[string]int, row []string, name string) string {
	if i, ok := cols[name]; ok && i < len(row) {
		return row[i]
	}
	return ""
}
