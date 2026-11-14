package indexer

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// Result codes are reported in XDR-JSON (SEP-51) names, the names rs-stellar-xdr gives the union arms:
// `tx_success`, `tx_fee_bump_inner_failed`, `set_options.success`, `op_bad_auth`. go-stellar-sdk's generated
// names are Go identifiers (`TransactionResultCodeTxSuccess`, `SetOptionsResultCodeSetOptionsSuccess`); these
// helpers turn one into the other: drop the type-name prefix, drop the operation prefix that every arm of an
// operation's result code shares, and convert to snake case.

// snake converts a Go CamelCase identifier to snake_case.
func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// enumArm returns the XDR-JSON name of a generated enum value: its String() with the type name dropped.
func enumArm(v fmt.Stringer) string {
	name := reflect.TypeOf(v).Name()
	return snake(strings.TrimPrefix(v.String(), name))
}

// txResultCode is the transaction result arm: tx_success, tx_failed, tx_fee_bump_inner_success, …
func txResultCode(c xdr.TransactionResultCode) string { return enumArm(c) }

// opType is the operation type name: payment, set_options, invoke_host_function, …
func opType(t xdr.OperationType) string { return enumArm(t) }

// opResultCodes returns `<operation>.<code>` for each inner result, or the outer arm (op_bad_auth, …).
func opResultCodes(results []xdr.OperationResult) []string {
	out := make([]string, 0, len(results))
	for _, r := range results {
		if r.Code != xdr.OperationResultCodeOpInner || r.Tr == nil {
			out = append(out, enumArm(r.Code))
			continue
		}
		out = append(out, opType(r.Tr.Type)+"."+innerCode(*r.Tr))
	}
	return out
}

// innerCode finds the operation's own result (the one non-nil pointer of OperationResultTr) and names its code,
// for example SetOptionsResultCodeSetOptionsSuccess → success.
func innerCode(tr xdr.OperationResultTr) string {
	v := reflect.ValueOf(tr)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || f.IsNil() {
			continue
		}
		code := f.Elem().FieldByName("Code")
		if !code.IsValid() {
			continue
		}
		s, ok := code.Interface().(fmt.Stringer)
		if !ok {
			continue
		}
		typ := code.Type().Name()                 // SetOptionsResultCode
		base := strings.TrimSuffix(typ, "Code")   // SetOptionsResult
		base = strings.TrimSuffix(base, "Result") // SetOptions
		name := strings.TrimPrefix(s.String(), typ)
		name = strings.TrimPrefix(name, base)
		return snake(name)
	}
	return "unknown"
}
