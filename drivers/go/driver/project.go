package driver

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// L2: the neutral value projection. The projection is the SEP-51 XDR-JSON the corpus oracle emits, as a value:
// structs are objects with snake_case keys in declaration order, unions an object with the arm name as the
// single key (a void arm the bare arm name), enums the arm-style name, 32-bit integers numbers, 64-bit
// integers and wider decimal strings, opaque data lower-case hex, strings escaped ASCII rendered from the raw
// bytes, optionals null or the value, and the address-like types their strkey text.
//
// The walker is generic over the SDK's generated types (reflection on the Go structs, union metadata from
// the generated SwitchFieldName/ArmForSwitch methods, enum names from the generated String methods) plus the
// small table of special types below. Every value is read from the decoded Go struct, and every strkey is
// produced by the SDK's own address methods.

// object is a JSON object that keeps its keys in declaration order.
type object struct {
	keys []string
	vals []any
}

func (o *object) set(k string, v any) {
	o.keys = append(o.keys, k)
	o.vals = append(o.vals, v)
}

func (o *object) get(k string) (any, bool) {
	for i, x := range o.keys {
		if x == k {
			return o.vals[i], true
		}
	}
	return nil, false
}

func (o *object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalValue(o.vals[i])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalValue(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// projectionError is a value the walker could not render (an address the SDK refuses to print); it is
// reported as the outcome's reason.
type projectionError struct {
	path string
	err  error
}

func (e *projectionError) Error() string { return fmt.Sprintf("%s: %v", e.path, e.err) }

// levelValues is L2.
func levelValues(in *input, raw []byte) result {
	v, rej := decodeStrict(in.XDRType, raw)
	if rej != nil {
		return *rej
	}
	// A panic inside the SDK's address methods is a fault; run reports it as crash.
	proj, perr := project(reflect.ValueOf(v).Elem(), "")
	if perr != nil {
		return reject("decode_error", "xdrcheck-driver-go projection", perr)
	}
	if len(in.Pinpoints) == 0 {
		return ok(map[string]any{"projection": proj})
	}
	pins := make([]map[string]any, 0, len(in.Pinpoints))
	for _, p := range in.Pinpoints {
		val, found := pointer(proj, p)
		e := map[string]any{"path": p, "found": found}
		if found {
			e["value"] = val
		}
		pins = append(pins, e)
	}
	return ok(map[string]any{"pinpoints": pins})
}

// pointer resolves a JSON Pointer (RFC 6901) in a projection.
func pointer(v any, p string) (any, bool) {
	if p == "" {
		return v, true
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	for _, tok := range strings.Split(p[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch t := v.(type) {
		case *object:
			x, found := t.get(tok)
			if !found {
				return nil, false
			}
			v = x
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) || (len(tok) > 1 && tok[0] == '0') {
				return nil, false
			}
			v = t[i]
		default:
			return nil, false
		}
	}
	return v, true
}

type unionType interface {
	SwitchFieldName() string
	ArmForSwitch(int32) (string, bool)
}

type enumType interface {
	ValidEnum(int32) bool
	String() string
}

var (
	unionIface = reflect.TypeOf((*unionType)(nil)).Elem()
	enumIface  = reflect.TypeOf((*enumType)(nil)).Elem()
	xdrPkg     = reflect.TypeOf(xdr.Hash{}).PkgPath()
)

// project renders one value. path is the JSON Pointer of the value, for error messages.
func project(v reflect.Value, path string) (any, error) {
	t := v.Type()
	if t.PkgPath() == xdrPkg {
		if out, handled, err := special(v, t.Name()); handled {
			if err != nil {
				return nil, &projectionError{path: orSlash(path), err: err}
			}
			return out, nil
		}
		if t.Implements(enumIface) && isIntKind(t.Kind()) {
			return enumName(v.Interface().(enumType)), nil
		}
	}
	switch t.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int32, reflect.Int16, reflect.Int8, reflect.Int:
		if t.Kind() == reflect.Int && t.Size() == 8 {
			return strconv.FormatInt(v.Int(), 10), nil
		}
		return json.Number(strconv.FormatInt(v.Int(), 10)), nil
	case reflect.Uint32, reflect.Uint16, reflect.Uint8, reflect.Uint:
		if t.Kind() == reflect.Uint && t.Size() == 8 {
			return strconv.FormatUint(v.Uint(), 10), nil
		}
		return json.Number(strconv.FormatUint(v.Uint(), 10)), nil
	case reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), nil
	case reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), nil
	case reflect.String:
		return escapeBytes([]byte(v.String())), nil
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return hex.EncodeToString(v.Bytes()), nil
		}
		out := make([]any, v.Len())
		for i := range out {
			x, err := project(v.Index(i), path+"/"+strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			out[i] = x
		}
		return out, nil
	case reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(b), v)
			return hex.EncodeToString(b), nil
		}
		out := make([]any, v.Len())
		for i := range out {
			x, err := project(v.Index(i), path+"/"+strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			out[i] = x
		}
		return out, nil
	case reflect.Pointer:
		if v.IsNil() {
			return nil, nil
		}
		return project(v.Elem(), path)
	case reflect.Struct:
		if t.Implements(unionIface) {
			return projectUnion(v, path)
		}
		o := &object{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			k := snake(f.Name)
			x, err := project(v.Field(i), path+"/"+k)
			if err != nil {
				return nil, err
			}
			o.set(k, x)
		}
		return o, nil
	}
	return nil, &projectionError{path: orSlash(path), err: fmt.Errorf("unsupported Go kind %s (%s)", t.Kind(), t)}
}

func orSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func isIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int32, reflect.Uint32, reflect.Int, reflect.Int64, reflect.Uint64:
		return true
	}
	return false
}

func projectUnion(v reflect.Value, path string) (any, error) {
	u := v.Interface().(unionType)
	sw := v.FieldByName(u.SwitchFieldName())
	var arm string
	var swVal int32
	if e, isEnum := sw.Interface().(enumType); isEnum {
		arm = enumName(e)
		swVal = int32(sw.Int())
	} else {
		swVal = int32(sw.Int())
		arm = "v" + strconv.Itoa(int(swVal))
	}
	field, valid := u.ArmForSwitch(swVal)
	if !valid {
		return nil, &projectionError{path: orSlash(path), err: fmt.Errorf("no arm for switch value %d", swVal)}
	}
	if field == "" {
		return arm, nil
	}
	x, err := project(v.FieldByName(field), path+"/"+arm)
	if err != nil {
		return nil, err
	}
	o := &object{}
	o.set(arm, x)
	return o, nil
}

// special renders the types SEP-51 does not render structurally. handled is false for every other type.
func special(v reflect.Value, name string) (any, bool, error) {
	switch name {
	case "AccountId", "PublicKey", "NodeId":
		var pk xdr.PublicKey
		reflect.ValueOf(&pk).Elem().Set(v.Convert(reflect.TypeOf(pk)))
		aid := xdr.AccountId(pk)
		s, err := aid.GetAddress()
		return s, true, err
	case "MuxedAccount":
		m := v.Interface().(xdr.MuxedAccount)
		s, err := m.GetAddress()
		return s, true, err
	case "ScAddress":
		s, err := v.Interface().(xdr.ScAddress).String()
		return s, true, err
	case "SignerKey":
		sk := v.Interface().(xdr.SignerKey)
		s, err := sk.GetAddress()
		return s, true, err
	case "ClaimableBalanceId":
		s, err := v.Interface().(xdr.ClaimableBalanceId).EncodeToStrkey()
		return s, true, err
	case "ContractId":
		b := make([]byte, v.Len())
		reflect.Copy(reflect.ValueOf(b), v)
		s, err := encodeStrkey("C", b)
		return s, true, err
	case "PoolId":
		b := make([]byte, v.Len())
		reflect.Copy(reflect.ValueOf(b), v)
		s, err := encodeStrkey("L", b)
		return s, true, err
	case "AssetCode4", "AssetCode12":
		b := make([]byte, v.Len())
		reflect.Copy(reflect.ValueOf(b), v)
		return escapeBytes(bytes.TrimRight(b, "\x00")), true, nil
	case "AssetCode":
		// the union of the two code lengths renders as the code alone
		c := v.Interface().(xdr.AssetCode)
		switch {
		case c.AssetCode4 != nil:
			return escapeBytes(bytes.TrimRight(c.AssetCode4[:], "\x00")), true, nil
		case c.AssetCode12 != nil:
			return escapeBytes(bytes.TrimRight(c.AssetCode12[:], "\x00")), true, nil
		}
		return nil, true, fmt.Errorf("AssetCode of type %d has no code", c.Type)
	case "Int128Parts":
		p := v.Interface().(xdr.Int128Parts)
		return parts(true, uint64(p.Hi), uint64(p.Lo)).String(), true, nil
	case "UInt128Parts":
		p := v.Interface().(xdr.UInt128Parts)
		return parts(false, uint64(p.Hi), uint64(p.Lo)).String(), true, nil
	case "Int256Parts":
		p := v.Interface().(xdr.Int256Parts)
		return parts(true, uint64(p.HiHi), uint64(p.HiLo), uint64(p.LoHi), uint64(p.LoLo)).String(), true, nil
	case "UInt256Parts":
		p := v.Interface().(xdr.UInt256Parts)
		return parts(false, uint64(p.HiHi), uint64(p.HiLo), uint64(p.LoHi), uint64(p.LoLo)).String(), true, nil
	}
	return nil, false, nil
}

// encodeStrkey renders a payload with the SDK's strkey encoder under the version byte a letter names.
func encodeStrkey(letter string, payload []byte) (string, error) {
	for _, s := range strkeyTypes {
		if s.letter == letter {
			return strkey.Encode(s.vb, payload)
		}
	}
	return "", fmt.Errorf("no strkey type has the letter %q", letter)
}

// parts combines big-endian 64-bit limbs into an integer, two's complement when signed.
func parts(signed bool, limbs ...uint64) *big.Int {
	n := new(big.Int)
	for _, l := range limbs {
		n.Lsh(n, 64)
		n.Or(n, new(big.Int).SetUint64(l))
	}
	bits := uint(64 * len(limbs))
	if signed && n.Bit(int(bits)-1) == 1 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), bits))
	}
	return n
}

// escapeBytes renders bytes as the oracle renders XDR strings: printable ASCII as is, backslash and the
// common control characters as escapes, every other byte as \xNN.
func escapeBytes(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c == 0:
			sb.WriteString(`\0`)
		case c == '\t':
			sb.WriteString(`\t`)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}

// snake converts a Go field name (the generator's camel case of the XDR name) to snake case: a new word at
// every upper-case letter that follows a lower-case letter or a digit, or that starts a capitalised word
// after an acronym.
func snake(s string) string {
	r := []rune(s)
	var sb strings.Builder
	for i, c := range r {
		if unicode.IsUpper(c) {
			if i > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]) ||
				(unicode.IsUpper(r[i-1]) && i+1 < len(r) && unicode.IsLower(r[i+1]))) {
				sb.WriteByte('_')
			}
			sb.WriteRune(unicode.ToLower(c))
			continue
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// enum names: the Go name of an enum value is the type name followed by the camel case of the XDR identifier
// (AssetTypeAssetTypeNative). The projection uses the identifier in snake case with the prefix that all of
// the enum's identifiers share removed (asset_type_native → native), as the oracle's generator does; an enum
// with a single identifier keeps it whole.
var (
	enumMu    sync.Mutex
	enumCache = map[reflect.Type]map[int32]string{}
)

const enumScanMin, enumScanMax = -256, 4096

// unprefixedEnums are the enums whose XDR identifiers carry their prefix in camel case (txSUCCESS, opINNER)
// rather than as an underscore-separated word; the oracle's generator finds no shared prefix in them and keeps
// the identifiers whole (tx_success, op_inner). The Go names no longer show where the underscores were, so
// they are listed here.
var unprefixedEnums = map[string]bool{"TransactionResultCode": true, "OperationResultCode": true}

func enumName(e enumType) string {
	t := reflect.TypeOf(e)
	enumMu.Lock()
	names, done := enumCache[t]
	if !done {
		names = enumNames(t)
		enumCache[t] = names
	}
	enumMu.Unlock()
	val := int32(reflect.ValueOf(e).Int())
	if n, found := names[val]; found {
		return n
	}
	return strconv.Itoa(int(val))
}

func enumNames(t reflect.Type) map[int32]string {
	words := map[int32][]string{}
	zero := reflect.Zero(t).Interface().(enumType)
	for i := int32(enumScanMin); i <= enumScanMax; i++ {
		if !zero.ValidEnum(i) {
			continue
		}
		v := reflect.New(t).Elem()
		v.SetInt(int64(i))
		goName := v.Interface().(enumType).String()
		words[i] = splitCamel(strings.TrimPrefix(goName, t.Name()))
	}
	prefix := 0
	if len(words) > 1 && !unprefixedEnums[t.Name()] {
		var first []string
		for _, w := range words {
			first = w
			break
		}
	scan:
		for prefix < len(first) {
			for _, w := range words {
				if len(w) <= prefix+1 || w[prefix] != first[prefix] {
					break scan
				}
			}
			prefix++
		}
	}
	out := map[int32]string{}
	for i, w := range words {
		out[i] = strings.Join(w[prefix:], "_")
	}
	return out
}

// splitCamel splits a camel-case identifier into lower-case words; digits stay with the word they follow.
func splitCamel(s string) []string {
	var words []string
	var cur []rune
	r := []rune(s)
	for i, c := range r {
		if unicode.IsUpper(c) && len(cur) > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]) ||
			(i+1 < len(r) && unicode.IsLower(r[i+1]))) {
			words = append(words, string(cur))
			cur = nil
		}
		cur = append(cur, unicode.ToLower(c))
	}
	if len(cur) > 0 {
		words = append(words, string(cur))
	}
	return words
}
