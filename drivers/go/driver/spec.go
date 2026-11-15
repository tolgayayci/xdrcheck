package driver

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/xdr"
	xdr3 "github.com/stellar/go-xdr/xdr3"
)

// The spec level. go-stellar-sdk decodes SCSpecEntry values but has no Wasm reader, so the driver hands it
// streams: a bare stream as it is, and for a Wasm module the one contractspecv0 section payload the
// orchestrator located (input.sections). A module with no section or several is n_a: which section to read is
// then the application's choice, not the SDK's. The stream is decoded one ScSpecEntry after another
// (ScSpecEntry.DecodeFrom on one go-xdr decoder at the SDK's default depth) until the bytes end; an entry that
// fails is the SDK's refusal. The entries are rendered in the neutral form of docs/conformance-protocol.md.

const specEntryPoint = "xdr.ScSpecEntry.DecodeFrom (stream)"

func levelSpec(in *input) result {
	raw, err := os.ReadFile(in.Path)
	if err != nil {
		return protocolError("cannot read the input: " + err.Error())
	}
	switch in.Container {
	case "xdr-stream":
	case "wasm":
		if len(in.Sections) != 1 {
			return notApplicable("no_object_layer", fmt.Sprintf("go-stellar-sdk has no Wasm reader; the module has %d contractspecv0 sections and the driver does not choose among them", len(in.Sections)))
		}
		s := in.Sections[0]
		if s.Offset < 0 || s.Length < 0 || s.Offset+s.Length > len(raw) {
			return protocolError("the section lies outside the module")
		}
		raw = raw[s.Offset : s.Offset+s.Length]
	default:
		return protocolError("unknown spec container " + in.Container)
	}
	d := xdr3.NewDecoder(bytes.NewReader(raw))
	var entries []map[string]any
	pos := 0
	for pos < len(raw) {
		var e xdr.ScSpecEntry
		n, err := e.DecodeFrom(d, xdr3.DecodeDefaultMaxDepth)
		if err != nil {
			return result{Outcome: "reject", Reason: &reason{Code: classifyDecode(err, len(raw)-pos, "ScSpecEntry"), Message: trim(err.Error()), EntryPoint: specEntryPoint}}
		}
		pos += n
		f, ferr := specFact(e)
		if ferr != nil {
			return result{Outcome: "crash", Reason: &reason{Code: "internal_error", Message: trim(ferr.Error())}}
		}
		entries = append(entries, f)
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	return result{Outcome: "ok", Actual: map[string]any{"spec": map[string]any{"entries": entries, "entry_point": specEntryPoint}}}
}

// nameText is a name's text: the string when it is UTF-8, else SEP-51 escaped (\xNN).
func nameText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	return b.String()
}

// typeText renders a type from its generated enum name (ScSpecTypeScSpecTypeU32 -> u32), so the code needs no
// constant a pinned SDK version may lack.
func typeText(t xdr.ScSpecTypeDef) (string, error) {
	name := strings.TrimPrefix(t.Type.String(), "ScSpecTypeScSpecType")
	switch name {
	case "Option":
		v, err := typeText(t.Option.ValueType)
		return "option<" + v + ">", err
	case "Result":
		a, err := typeText(t.Result.OkType)
		if err != nil {
			return "", err
		}
		b, err := typeText(t.Result.ErrorType)
		return "result<" + a + "," + b + ">", err
	case "Vec":
		v, err := typeText(t.Vec.ElementType)
		return "vec<" + v + ">", err
	case "Map":
		a, err := typeText(t.Map.KeyType)
		if err != nil {
			return "", err
		}
		b, err := typeText(t.Map.ValueType)
		return "map<" + a + "," + b + ">", err
	case "Tuple":
		s, err := typeList(t.Tuple.ValueTypes)
		return "tuple<" + s + ">", err
	case "BytesN":
		return fmt.Sprintf("bytes_n<%d>", uint32(t.BytesN.N)), nil
	case "Udt":
		return "udt:" + nameText(t.Udt.Name), nil
	case "MuxedAddress":
		return "muxed_address", nil
	case "":
		return "", fmt.Errorf("unnamed SCSpecTypeDef %d", int32(t.Type))
	}
	return strings.ToLower(name), nil
}

func typeList(ts []xdr.ScSpecTypeDef) (string, error) {
	out := make([]string, len(ts))
	for i, t := range ts {
		s, err := typeText(t)
		if err != nil {
			return "", err
		}
		out[i] = s
	}
	return strings.Join(out, ","), nil
}

func arg(name, ty string) map[string]any { return map[string]any{"name": nameText(name), "type": ty} }

func specFact(e xdr.ScSpecEntry) (map[string]any, error) {
	var args []map[string]any
	add := func(name string, t xdr.ScSpecTypeDef, suffix string) error {
		s, err := typeText(t)
		args = append(args, arg(name, s+suffix))
		return err
	}
	out := map[string]any{}
	switch {
	case e.FunctionV0 != nil:
		f := e.FunctionV0
		for _, i := range f.Inputs {
			if err := add(i.Name, i.Type, ""); err != nil {
				return nil, err
			}
		}
		outs := []string{}
		for _, o := range f.Outputs {
			s, err := typeText(o)
			if err != nil {
				return nil, err
			}
			outs = append(outs, s)
		}
		out["kind"], out["name"], out["outputs"] = "function", nameText(string(f.Name)), outs
	case e.UdtStructV0 != nil:
		for _, f := range e.UdtStructV0.Fields {
			if err := add(f.Name, f.Type, ""); err != nil {
				return nil, err
			}
		}
		out["kind"], out["name"] = "struct", nameText(e.UdtStructV0.Name)
	case e.UdtUnionV0 != nil:
		for _, c := range e.UdtUnionV0.Cases {
			switch {
			case c.VoidCase != nil:
				args = append(args, arg(c.VoidCase.Name, "void"))
			case c.TupleCase != nil:
				s, err := typeList(c.TupleCase.Type)
				if err != nil {
					return nil, err
				}
				args = append(args, arg(c.TupleCase.Name, "tuple<"+s+">"))
			}
		}
		out["kind"], out["name"] = "union", nameText(e.UdtUnionV0.Name)
	case e.UdtEnumV0 != nil:
		for _, c := range e.UdtEnumV0.Cases {
			args = append(args, arg(c.Name, fmt.Sprintf("=%d", uint32(c.Value))))
		}
		out["kind"], out["name"] = "enum", nameText(e.UdtEnumV0.Name)
	case e.UdtErrorEnumV0 != nil:
		for _, c := range e.UdtErrorEnumV0.Cases {
			args = append(args, arg(c.Name, fmt.Sprintf("=%d", uint32(c.Value))))
		}
		out["kind"], out["name"] = "error_enum", nameText(e.UdtErrorEnumV0.Name)
	case e.EventV0 != nil:
		for _, p := range e.EventV0.Params {
			loc := "@data"
			if p.Location == xdr.ScSpecEventParamLocationV0ScSpecEventParamLocationTopicList {
				loc = "@topic_list"
			}
			if err := add(p.Name, p.Type, loc); err != nil {
				return nil, err
			}
		}
		out["kind"], out["name"] = "event", nameText(fmt.Sprint(e.EventV0.Name)) // a symbol before XDR v30, a string since
	default:
		return nil, fmt.Errorf("SCSpecEntry kind %d has no arm", int32(e.Kind))
	}
	if args == nil {
		args = []map[string]any{}
	}
	out["args"] = args
	return out, nil
}
