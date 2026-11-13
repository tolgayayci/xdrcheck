package adapterkit

// A small JSON Schema 2020-12 validator, enough for the two frozen protocol schemas (adapter-protocol and
// observation). It implements exactly the keywords those schemas use — $ref (local and cross-resource), $defs,
// type, const, enum, required, properties, additionalProperties, propertyNames, items, minItems, uniqueItems,
// minimum, maximum, exclusiveMinimum, minLength, maxLength, pattern, allOf, anyOf, oneOf, not, if/then/else —
// and refuses to load a schema that uses any other assertion keyword, so a schema change cannot be silently
// half-enforced. Annotations (title, description, default, $schema, $id) are ignored.
//
// Instances are the result of decoding JSON with UseNumber, so numbers are json.Number and are compared exactly
// (big.Rat), and "integer" means any number with no fractional part, as the specification says.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// SchemaError is one place where an instance does not satisfy a schema.
type SchemaError struct {
	Path    string // JSON Pointer into the instance
	Keyword string // the failing keyword: required, additionalProperties, type, enum, …
	Message string
}

func (e SchemaError) Error() string {
	p := e.Path
	if p == "" {
		p = "/"
	}
	return fmt.Sprintf("%s: %s", p, e.Message)
}

var knownKeywords = map[string]bool{
	"$schema": true, "$id": true, "$ref": true, "$defs": true, "title": true, "description": true, "default": true,
	"type": true, "const": true, "enum": true, "required": true, "properties": true, "additionalProperties": true,
	"propertyNames": true, "items": true, "minItems": true, "uniqueItems": true, "minimum": true, "maximum": true,
	"exclusiveMinimum": true, "minLength": true, "maxLength": true, "pattern": true, "allOf": true, "anyOf": true,
	"oneOf": true, "not": true, "if": true, "then": true, "else": true,
}

type resource struct {
	id   string
	root any
}

// schemaSet holds schema resources by $id.
type schemaSet struct {
	byID    map[string]*resource
	regexps map[string]*regexp.Regexp
}

func newSchemaSet(docs ...[]byte) (*schemaSet, error) {
	s := &schemaSet{byID: map[string]*resource{}, regexps: map[string]*regexp.Regexp{}}
	for _, d := range docs {
		v, err := decodeAny(d)
		if err != nil {
			return nil, err
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("schema is not an object")
		}
		id, _ := m["$id"].(string)
		if id == "" {
			return nil, fmt.Errorf("schema has no $id")
		}
		if err := s.check(v, id); err != nil {
			return nil, err
		}
		s.byID[id] = &resource{id: id, root: v}
	}
	return s, nil
}

// check walks a schema, rejecting unknown keywords and compiling patterns.
func (s *schemaSet) check(v any, where string) error {
	m, ok := v.(map[string]any)
	if !ok {
		if _, isBool := v.(bool); isBool {
			return nil
		}
		return fmt.Errorf("%s: schema is a %T", where, v)
	}
	for k, sub := range m {
		if !knownKeywords[k] {
			return fmt.Errorf("%s: unsupported schema keyword %q", where, k)
		}
		switch k {
		case "properties", "$defs":
			for name, p := range sub.(map[string]any) {
				if err := s.check(p, where+"/"+k+"/"+name); err != nil {
					return err
				}
			}
		case "additionalProperties", "propertyNames", "items", "not", "if", "then", "else":
			if err := s.check(sub, where+"/"+k); err != nil {
				return err
			}
		case "allOf", "anyOf", "oneOf":
			for i, p := range sub.([]any) {
				if err := s.check(p, fmt.Sprintf("%s/%s/%d", where, k, i)); err != nil {
					return err
				}
			}
		case "pattern":
			re, err := regexp.Compile(sub.(string))
			if err != nil {
				return fmt.Errorf("%s: pattern: %v", where, err)
			}
			s.regexps[sub.(string)] = re
		}
	}
	return nil
}

// resolve finds the schema a $ref names, relative to the resource it appears in.
func (s *schemaSet) resolve(ref string, base *resource) (any, *resource, error) {
	docID, frag, _ := strings.Cut(ref, "#")
	res := base
	if docID != "" {
		res = s.byID[docID]
		if res == nil {
			return nil, nil, fmt.Errorf("unknown schema %q", docID)
		}
	}
	cur := res.root
	if frag != "" {
		if !strings.HasPrefix(frag, "/") {
			return nil, nil, fmt.Errorf("unsupported $ref fragment %q", frag)
		}
		for _, part := range strings.Split(frag[1:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("$ref %q does not resolve", ref)
			}
			if cur, ok = m[part]; !ok {
				return nil, nil, fmt.Errorf("$ref %q does not resolve", ref)
			}
		}
	}
	return cur, res, nil
}

// validate checks inst against the schema at ref ("<id>#/$defs/x") and returns every error found.
func (s *schemaSet) validate(ref string, inst any) []SchemaError {
	sch, res, err := s.resolve(ref, nil)
	if err != nil {
		return []SchemaError{{Keyword: "$ref", Message: err.Error()}}
	}
	var errs []SchemaError
	s.eval(sch, res, inst, "", &errs)
	return errs
}

func (s *schemaSet) valid(sch any, res *resource, inst any, path string) bool {
	var errs []SchemaError
	s.eval(sch, res, inst, path, &errs)
	return len(errs) == 0
}

func (s *schemaSet) eval(sch any, res *resource, inst any, path string, errs *[]SchemaError) {
	add := func(kw, format string, a ...any) {
		*errs = append(*errs, SchemaError{Path: path, Keyword: kw, Message: fmt.Sprintf(format, a...)})
	}
	switch b := sch.(type) {
	case bool:
		if !b {
			add("false", "no value is allowed here")
		}
		return
	case map[string]any:
	default:
		add("schema", "bad schema node %T", sch)
		return
	}
	m := sch.(map[string]any)

	if ref, ok := m["$ref"].(string); ok {
		target, tres, err := s.resolve(ref, res)
		if err != nil {
			add("$ref", "%v", err)
		} else {
			s.eval(target, tres, inst, path, errs)
		}
	}
	if t, ok := m["type"]; ok {
		var types []string
		switch tv := t.(type) {
		case string:
			types = []string{tv}
		case []any:
			for _, x := range tv {
				types = append(types, x.(string))
			}
		}
		okType := false
		for _, ty := range types {
			if hasType(inst, ty) {
				okType = true
				break
			}
		}
		if !okType {
			add("type", "is %s, want %s", typeName(inst), strings.Join(types, " or "))
			return // the remaining keywords would only repeat the type error
		}
	}
	if c, ok := m["const"]; ok && !jsonEqual(c, inst) {
		add("const", "must be %s", compact(c))
	}
	if e, ok := m["enum"].([]any); ok {
		found := false
		for _, x := range e {
			if jsonEqual(x, inst) {
				found = true
				break
			}
		}
		if !found {
			var opts []string
			for _, x := range e {
				opts = append(opts, compact(x))
			}
			add("enum", "%s is not one of %s", compact(inst), strings.Join(opts, ", "))
		}
	}

	switch iv := inst.(type) {
	case map[string]any:
		if req, ok := m["required"].([]any); ok {
			for _, r := range req {
				if _, present := iv[r.(string)]; !present {
					add("required", "required property %q is missing", r.(string))
				}
			}
		}
		props, _ := m["properties"].(map[string]any)
		keys := sortedKeys(iv)
		for _, k := range keys {
			sub := path + "/" + escapePointer(k)
			if p, ok := props[k]; ok {
				s.eval(p, res, iv[k], sub, errs)
				continue
			}
			if ap, ok := m["additionalProperties"]; ok {
				if b, isBool := ap.(bool); isBool && !b {
					*errs = append(*errs, SchemaError{Path: path, Keyword: "additionalProperties", Message: fmt.Sprintf("unknown property %q", k)})
				} else {
					s.eval(ap, res, iv[k], sub, errs)
				}
			}
		}
		if pn, ok := m["propertyNames"]; ok {
			for _, k := range keys {
				if !s.valid(pn, res, k, path+"/"+escapePointer(k)) {
					*errs = append(*errs, SchemaError{Path: path, Keyword: "propertyNames", Message: fmt.Sprintf("property name %q is not allowed here", k)})
				}
			}
		}
	case []any:
		if n, ok := m["minItems"]; ok && big.NewInt(int64(len(iv))).Cmp(ratInt(n)) < 0 {
			add("minItems", "has %d items, want at least %s", len(iv), compact(n))
		}
		if u, ok := m["uniqueItems"].(bool); ok && u {
			for i := range iv {
				for j := i + 1; j < len(iv); j++ {
					if jsonEqual(iv[i], iv[j]) {
						add("uniqueItems", "items %d and %d are equal", i, j)
					}
				}
			}
		}
		if it, ok := m["items"]; ok {
			for i, x := range iv {
				s.eval(it, res, x, path+"/"+strconv.Itoa(i), errs)
			}
		}
	case string:
		n := utf8.RuneCountInString(iv)
		if v, ok := m["minLength"]; ok && big.NewInt(int64(n)).Cmp(ratInt(v)) < 0 {
			add("minLength", "is %d characters, want at least %s", n, compact(v))
		}
		if v, ok := m["maxLength"]; ok && big.NewInt(int64(n)).Cmp(ratInt(v)) > 0 {
			add("maxLength", "is %d characters, want at most %s", n, compact(v))
		}
		if p, ok := m["pattern"].(string); ok && !s.regexps[p].MatchString(iv) {
			add("pattern", "%s does not match %s", compact(iv), p)
		}
	case json.Number:
		r := ratOf(iv)
		if v, ok := m["minimum"]; ok && r.Cmp(ratOf(v.(json.Number))) < 0 {
			add("minimum", "%s is below the minimum %s", iv, v)
		}
		if v, ok := m["maximum"]; ok && r.Cmp(ratOf(v.(json.Number))) > 0 {
			add("maximum", "%s is above the maximum %s", iv, v)
		}
		if v, ok := m["exclusiveMinimum"]; ok && r.Cmp(ratOf(v.(json.Number))) <= 0 {
			add("exclusiveMinimum", "%s must be greater than %s", iv, v)
		}
	}

	if all, ok := m["allOf"].([]any); ok {
		for _, sub := range all {
			s.eval(sub, res, inst, path, errs)
		}
	}
	if anyOf, ok := m["anyOf"].([]any); ok {
		matched := false
		for _, sub := range anyOf {
			if s.valid(sub, res, inst, path) {
				matched = true
				break
			}
		}
		if !matched {
			add("anyOf", "matches none of the %d alternatives", len(anyOf))
		}
	}
	if oneOf, ok := m["oneOf"].([]any); ok {
		n := 0
		var best []SchemaError
		for _, sub := range oneOf {
			var e []SchemaError
			s.eval(sub, res, inst, path, &e)
			if len(e) == 0 {
				n++
			} else if best == nil || len(e) < len(best) {
				best = e
			}
		}
		switch {
		case n == 0:
			// Report the errors of the closest alternative: they say what is wrong in the usual case.
			*errs = append(*errs, best...)
			if len(best) == 0 {
				add("oneOf", "matches none of the %d alternatives", len(oneOf))
			}
		case n > 1:
			add("oneOf", "matches %d of the alternatives, want exactly one", n)
		}
	}
	if not, ok := m["not"]; ok && s.valid(not, res, inst, path) {
		add("not", "must not match the schema in \"not\"")
	}
	if cond, ok := m["if"]; ok {
		if s.valid(cond, res, inst, path) {
			if then, ok := m["then"]; ok {
				s.eval(then, res, inst, path, errs)
			}
		} else if els, ok := m["else"]; ok {
			s.eval(els, res, inst, path, errs)
		}
	}
}

func hasType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		return ok && ratOf(n).IsInt()
	}
	return false
}

func typeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	case json.Number:
		return "a number"
	}
	return fmt.Sprintf("%T", v)
}

func ratOf(n json.Number) *big.Rat {
	r, ok := new(big.Rat).SetString(string(n))
	if !ok {
		return new(big.Rat)
	}
	return r
}

func ratInt(v any) *big.Int {
	n, _ := v.(json.Number)
	r := ratOf(n)
	return new(big.Int).Quo(r.Num(), r.Denom())
}

// jsonEqual compares two decoded JSON values; numbers compare by value.
func jsonEqual(a, b any) bool {
	switch av := a.(type) {
	case json.Number:
		bv, ok := b.(json.Number)
		return ok && ratOf(av).Cmp(ratOf(bv)) == 0
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !jsonEqual(x, y) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return a == b
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > 80 {
		return string(b[:77]) + "..."
	}
	return string(b)
}

// decodeAny decodes one JSON value with numbers kept as json.Number and refuses trailing data.
func decodeAny(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}
