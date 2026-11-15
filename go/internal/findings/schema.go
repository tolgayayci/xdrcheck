package findings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Schema is a JSON Schema (draft 2020-12) document, validated with the subset of keywords the kit's frozen
// schemas use. A keyword outside that subset is an error at load time, so a schema change cannot be skipped
// silently by this validator.
type Schema struct {
	root     map[string]any
	patterns map[string]*regexp.Regexp
}

// Keywords that carry no assertion.
var annotations = map[string]bool{"$schema": true, "$id": true, "$defs": true, "title": true, "description": true, "examples": true, "default": true}

// Keywords the validator implements.
var assertions = map[string]bool{
	"$ref": true, "type": true, "const": true, "enum": true, "pattern": true, "minLength": true, "maxLength": true,
	"format": true, "minimum": true, "minItems": true, "uniqueItems": true, "items": true, "required": true,
	"properties": true, "additionalProperties": true, "allOf": true, "oneOf": true, "if": true, "then": true, "else": true,
}

// LoadSchema reads and checks a schema file.
func LoadSchema(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := decodeJSON(data, &root); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &Schema{root: root, patterns: map[string]*regexp.Regexp{}}
	if err := s.compile(root, "#"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// decodeJSON decodes one JSON value, keeping numbers as json.Number, and rejects trailing data.
func decodeJSON(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the JSON value")
	}
	return nil
}

// compile walks every subschema once: it rejects unknown keywords and compiles the patterns.
func (s *Schema) compile(node any, at string) error {
	sch, ok := node.(map[string]any)
	if !ok {
		if _, isBool := node.(bool); isBool {
			return nil
		}
		return fmt.Errorf("%s: a schema must be an object or a boolean", at)
	}
	keys := make([]string, 0, len(sch))
	for k := range sch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := sch[k]
		switch {
		case annotations[k]:
			if k == "$defs" {
				defs, _ := v.(map[string]any)
				for name, d := range defs {
					if err := s.compile(d, at+"/$defs/"+name); err != nil {
						return err
					}
				}
			}
		case !assertions[k]:
			return fmt.Errorf("%s: keyword %q is not supported by this validator", at, k)
		case k == "pattern":
			p, _ := v.(string)
			re, err := regexp.Compile(p)
			if err != nil {
				return fmt.Errorf("%s: pattern %q: %w", at, p, err)
			}
			s.patterns[p] = re
		case k == "properties":
			props, _ := v.(map[string]any)
			for name, p := range props {
				if err := s.compile(p, at+"/properties/"+name); err != nil {
					return err
				}
			}
		case k == "items" || k == "additionalProperties" || k == "if" || k == "then" || k == "else":
			if err := s.compile(v, at+"/"+k); err != nil {
				return err
			}
		case k == "allOf" || k == "oneOf":
			list, _ := v.([]any)
			for i, sub := range list {
				if err := s.compile(sub, fmt.Sprintf("%s/%s/%d", at, k, i)); err != nil {
					return err
				}
			}
		case k == "format":
			if f, _ := v.(string); f != "date" && f != "uri" && f != "date-time" {
				return fmt.Errorf("%s: format %q is not supported", at, f)
			}
		}
	}
	return nil
}

// Validate returns every violation of the schema by doc, a value decoded with json.Number numbers. An empty
// result means the document is valid.
func (s *Schema) Validate(doc any) []string {
	var errs []string
	s.validate(s.root, doc, "$", &errs)
	return errs
}

// ValidateBytes decodes data and validates it.
func (s *Schema) ValidateBytes(data []byte) []string {
	var doc any
	if err := decodeJSON(data, &doc); err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	return s.Validate(doc)
}

func (s *Schema) valid(sch any, inst any) bool {
	var errs []string
	s.validate(sch, inst, "$", &errs)
	return len(errs) == 0
}

func (s *Schema) resolve(ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	var node any = s.root
	for _, part := range strings.Split(ref[2:], "/") {
		m, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return node, true
}

func (s *Schema) validate(node any, inst any, path string, errs *[]string) {
	add := func(format string, a ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(format, a...)) }
	if b, ok := node.(bool); ok {
		if !b {
			add("not allowed")
		}
		return
	}
	sch, _ := node.(map[string]any)
	if ref, ok := sch["$ref"].(string); ok {
		target, found := s.resolve(ref)
		if !found {
			add("unresolvable $ref %q", ref)
			return
		}
		s.validate(target, inst, path, errs)
	}
	if t, ok := sch["type"]; ok && !typeMatches(t, inst) {
		add("is %s, want %v", typeName(inst), t)
		return
	}
	if c, ok := sch["const"]; ok && !jsonEqual(c, inst) {
		add("must be %v", c)
	}
	if e, ok := sch["enum"].([]any); ok {
		found := false
		for _, v := range e {
			if jsonEqual(v, inst) {
				found = true
				break
			}
		}
		if !found {
			add("%v is not one of %v", inst, e)
		}
	}
	switch v := inst.(type) {
	case string:
		if p, ok := sch["pattern"].(string); ok && !s.patterns[p].MatchString(v) {
			add("%q does not match %s", v, p)
		}
		if n, ok := number(sch["minLength"]); ok && float64(utf8.RuneCountInString(v)) < n {
			add("shorter than %v characters", n)
		}
		if n, ok := number(sch["maxLength"]); ok && float64(utf8.RuneCountInString(v)) > n {
			add("longer than %v characters", n)
		}
		if f, ok := sch["format"].(string); ok && !formatOK(f, v) {
			add("%q is not a valid %s", v, f)
		}
	case json.Number:
		if n, ok := number(sch["minimum"]); ok {
			if f, err := v.Float64(); err == nil && f < n {
				add("%v is below the minimum %v", v, n)
			}
		}
	case []any:
		if n, ok := number(sch["minItems"]); ok && float64(len(v)) < n {
			add("has %d items, want at least %v", len(v), n)
		}
		if u, _ := sch["uniqueItems"].(bool); u {
			seen := map[string]bool{}
			for _, it := range v {
				k := canonical(it)
				if seen[k] {
					add("items are not unique (%s)", k)
					break
				}
				seen[k] = true
			}
		}
		if items, ok := sch["items"]; ok {
			for i, it := range v {
				s.validate(items, it, fmt.Sprintf("%s[%d]", path, i), errs)
			}
		}
	case map[string]any:
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				if name, _ := r.(string); name != "" {
					if _, present := v[name]; !present {
						add("%q is required", name)
					}
				}
			}
		}
		props, _ := sch["properties"].(map[string]any)
		names := make([]string, 0, len(v))
		for k := range v {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if p, ok := props[k]; ok {
				s.validate(p, v[k], path+"."+k, errs)
			} else if ap, ok := sch["additionalProperties"]; ok {
				if b, isBool := ap.(bool); isBool && !b {
					add("property %q is not allowed", k)
				} else {
					s.validate(ap, v[k], path+"."+k, errs)
				}
			}
		}
	}
	if all, ok := sch["allOf"].([]any); ok {
		for _, sub := range all {
			s.validate(sub, inst, path, errs)
		}
	}
	if one, ok := sch["oneOf"].([]any); ok {
		n := 0
		for _, sub := range one {
			if s.valid(sub, inst) {
				n++
			}
		}
		if n != 1 {
			add("matches %d of the oneOf alternatives, want exactly 1", n)
		}
	}
	if cond, ok := sch["if"]; ok {
		if s.valid(cond, inst) {
			if then, ok := sch["then"]; ok {
				s.validate(then, inst, path, errs)
			}
		} else if els, ok := sch["else"]; ok {
			s.validate(els, inst, path, errs)
		}
	}
}

func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func typeName(inst any) string {
	switch v := inst.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if isInteger(v) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", inst)
}

func isInteger(n json.Number) bool {
	if _, err := n.Int64(); err == nil {
		return true
	}
	f, err := n.Float64()
	return err == nil && f == float64(int64(f))
}

func typeMatches(t any, inst any) bool {
	one := func(name string) bool {
		got := typeName(inst)
		return got == name || (name == "number" && got == "integer")
	}
	switch v := t.(type) {
	case string:
		return one(v)
	case []any:
		for _, n := range v {
			if s, _ := n.(string); one(s) {
				return true
			}
		}
	}
	return false
}

func formatOK(format, v string) bool {
	switch format {
	case "date":
		_, err := time.Parse("2006-01-02", v)
		return err == nil
	case "date-time":
		_, err := time.Parse(time.RFC3339, v)
		return err == nil
	case "uri":
		u, err := url.Parse(v)
		return err == nil && u.Scheme != "" && !strings.ContainsAny(v, " \t\n")
	}
	return true
}

// canonical is a stable text form for equality: encoding/json sorts object keys and keeps json.Number text.
func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonEqual(a, b any) bool { return canonical(a) == canonical(b) }
