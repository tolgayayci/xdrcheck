package xdrdef

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

// The JSON definitions rs-stellar-xdr's generator writes (`xdr-definitions-json/xdr.json`, shipped in the
// `stellar-xdr` crate). They are already preprocessed (`resolved_features` lists the features that were on),
// so a set loaded from them carries no conditions.

type irFile struct {
	Version          int      `json:"version"`
	Files            []irName `json:"files"`
	ResolvedFeatures []string `json:"resolved_features"`
	Definitions      []irDef  `json:"definitions"`
}

type irName struct {
	Name string `json:"name"`
}

type irDef struct {
	Kind         string     `json:"kind"`
	Name         string     `json:"name"`
	Source       string     `json:"source"`
	FileIndex    int        `json:"file_index"`
	Value        *int64     `json:"value"`
	Type         *irType    `json:"type"`
	Members      []irMember `json:"members"`
	Fields       []irField  `json:"fields"`
	Discriminant *irField   `json:"discriminant"`
	Arms         []irArm    `json:"arms"`
}

type irType struct {
	Kind     string  `json:"kind"`
	Name     string  `json:"name"`
	Element  *irType `json:"element"`
	Size     *int64  `json:"size"`
	MaxSize  *int64  `json:"max_size"`
	MaxCount *int64  `json:"max_count"`
	Count    *int64  `json:"count"`
}

type irMember struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type irField struct {
	Name string  `json:"name"`
	Type *irType `json:"type"`
}

type irArm struct {
	Cases []struct {
		Value *int64 `json:"value"`
		Name  string `json:"name"`
	} `json:"cases"`
	Name string  `json:"name"`
	Type *irType `json:"type"`
}

// ReadMaybeZstd reads a file, decompressing it when its name ends in .zst.
func ReadMaybeZstd(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(path, ".zst") {
		return b, nil
	}
	r, err := zstd.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func num(p *int64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatInt(*p, 10)
}

func (t *irType) model() (*Type, error) {
	if t == nil {
		return nil, nil
	}
	out := &Type{}
	switch t.Kind {
	case "ref":
		out.Kind, out.Name = "ref", t.Name
	case "int", "hyper", "bool", "float", "double":
		out.Kind = t.Kind
	case "unsigned_int":
		out.Kind = "uint"
	case "unsigned_hyper":
		out.Kind = "uhyper"
	case "opaque_fixed":
		out.Kind, out.Size = "opaque_fixed", num(t.Size)
	case "opaque_var":
		out.Kind, out.Size = "opaque_var", num(t.MaxSize)
	case "string":
		out.Kind, out.Size = "string", num(t.MaxSize)
	case "array", "var_array", "optional":
		e, err := t.Element.model()
		if err != nil {
			return nil, err
		}
		out.Kind, out.Elem = t.Kind, e
		if t.Kind == "array" {
			out.Size = num(t.Count)
		} else if t.Kind == "var_array" {
			out.Size = num(t.MaxCount)
		}
	default:
		return nil, fmt.Errorf("unknown type kind %q", t.Kind)
	}
	return out, nil
}

// LoadIR reads the JSON definitions (optionally zstd-compressed) into a set.
func LoadIR(path string) (*Set, error) {
	b, err := ReadMaybeZstd(path)
	if err != nil {
		return nil, err
	}
	return ParseIR(b)
}

// ParseIR builds a set from the JSON definitions' bytes.
func ParseIR(b []byte) (*Set, error) {
	var f irFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("definitions JSON: %w", err)
	}
	var defs []*Def
	for _, d := range f.Definitions {
		file := ""
		if d.FileIndex >= 0 && d.FileIndex < len(f.Files) {
			file = strings.TrimPrefix(f.Files[d.FileIndex].Name, "xdr/")
		}
		out := &Def{Kind: d.Kind, Name: d.Name, File: file}
		var err error
		switch d.Kind {
		case "const":
			out.Value = num(d.Value)
		case "typedef":
			out.Type, err = d.Type.model()
		case "enum":
			for _, m := range d.Members {
				out.Members = append(out.Members, Member{Name: m.Name, Value: m.Value})
			}
		case "struct":
			for _, fl := range d.Fields {
				t, e := fl.Type.model()
				if e != nil {
					err = e
				}
				out.Fields = append(out.Fields, Field{Name: fl.Name, Type: t})
			}
		case "union":
			if d.Discriminant == nil {
				return nil, fmt.Errorf("%s: union without a discriminant", d.Name)
			}
			t, e := d.Discriminant.Type.model()
			if e != nil {
				return nil, fmt.Errorf("%s: %w", d.Name, e)
			}
			out.Disc = &Field{Name: d.Discriminant.Name, Type: t}
			for _, a := range d.Arms {
				arm := Arm{Name: a.Name}
				if arm.Type, err = a.Type.model(); err != nil {
					break
				}
				for _, c := range a.Cases {
					if c.Value == nil {
						arm.Cases = append(arm.Cases, Case{Default: true})
					} else {
						arm.Cases = append(arm.Cases, Case{Label: c.Name, Value: *c.Value})
					}
				}
				out.Arms = append(out.Arms, arm)
			}
		default:
			return nil, fmt.Errorf("%s: unknown definition kind %q", d.Name, d.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name, err)
		}
		defs = append(defs, out)
	}
	return NewSet(defs)
}
