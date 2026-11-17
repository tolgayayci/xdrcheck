package xdr103

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// validateTokenString checks length, UTF-8 and NUL before a value goes to a
// TEXT column (the shape of a SEP-41 metadata validator).
func validateTokenString(fieldName, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds %d byte cap", fieldName, maxLen)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", fieldName)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%s contains NUL byte", fieldName)
	}
	return nil
}

// (a) A validating helper whose error is checked.
func storeNameValidated(db *sql.DB, scv xdr.ScVal) error {
	name := string(scv.MustStr())
	if err := validateTokenString("name", name, 128); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, name)
	return err
}

// (b) Invalid UTF-8 replaced and NUL bytes stripped.
func storeMemoSanitised(db *sql.DB, memo xdr.Memo) error {
	text := strings.ReplaceAll(strings.ToValidUTF8(memo.MustText(), "�"), "\x00", "")
	_, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text)
	return err
}

// (c) A data value encoded before it is stored.
func storeDataEncoded(db *sql.DB, op xdr.ManageDataOp) error {
	if op.DataValue == nil {
		return nil
	}
	_, err := db.Exec(`INSERT INTO data (name, value) VALUES ($1, $2)`, string(op.DataName), base64.StdEncoding.EncodeToString(*op.DataValue))
	return err
}

// (d) A home domain: stellar-core accepts only printable ASCII.
func storeHomeDomain(db *sql.DB, op xdr.SetOptionsOp) error {
	if op.HomeDomain == nil {
		return nil
	}
	_, err := db.Exec(`UPDATE accounts SET home_domain = $1`, string(*op.HomeDomain))
	return err
}

// (e) Contract bytes kept as bytes, for a bytea column.
func storeBytes(db *sql.DB, scv xdr.ScVal) error {
	b, ok := scv.GetBytes()
	if !ok {
		return nil
	}
	_, err := db.Exec(`INSERT INTO blobs (value) VALUES ($1)`, []byte(b))
	return err
}

// (f) Both checks inline, on the value that is stored.
func tokenNameChecked(contract string, scv xdr.ScVal) (tokenRow, bool) {
	s := string(scv.MustStr())
	if !utf8.ValidString(s) || strings.Contains(s, "\x00") {
		return tokenRow{}, false
	}
	return tokenRow{Contract: contract, Name: s}, true
}

// (g) The sink only on the branch where both checks passed.
func storeIfClean(db *sql.DB, memo xdr.Memo) error {
	text := memo.MustText()
	if utf8.ValidString(text) && strings.IndexByte(text, 0) < 0 {
		_, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text)
		return err
	}
	return nil
}

// (h) A value that failed is replaced before the merge.
func storeOrBlank(db *sql.DB, scv xdr.ScVal) error {
	s := string(scv.MustStr())
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		s = ""
	}
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, s)
	return err
}

// (i) The verdict kept in a variable, and the failing case skipped.
func storeAll(db *sql.DB, memos []xdr.Memo) error {
	for _, memo := range memos {
		text := memo.MustText()
		ok := utf8.ValidString(text) && !strings.Contains(text, "\x00")
		if !ok {
			continue
		}
		if _, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text); err != nil {
			return err
		}
	}
	return nil
}

// (j) A helper that returns the verdict.
func cleanText(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) == -1
}

func storeWithHelper(db *sql.DB, memo xdr.Memo) error {
	text := memo.MustText()
	if !cleanText(text) {
		return fmt.Errorf("memo is not clean text")
	}
	_, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text)
	return err
}

// (k) A decoded entry returned by value: one field holds contract-supplied
// text, another a decimal amount. Reading the amount does not read the text
// (the shape of a ledger-entry decoder that routes a decoded value to
// per-kind stagers).
type decodedEntry struct {
	Kind   int
	Label  *labelData
	Amount string
}

type labelData struct{ Name string }

type queued struct {
	Amount string `json:"amount"`
}

func decodeEntry(v xdr.ScVal) (decodedEntry, error) {
	if s, ok := v.GetStr(); ok {
		return decodeLabel(string(s)), nil
	}
	return decodeAmount(v)
}

func decodeLabel(name string) decodedEntry {
	return decodedEntry{Kind: 1, Label: &labelData{Name: name}}
}

func decodeAmount(v xdr.ScVal) (decodedEntry, error) {
	parts, ok := v.GetI128()
	if !ok {
		return decodedEntry{}, fmt.Errorf("not an i128")
	}
	out := decodedEntry{Kind: 2}
	out.Amount = fmt.Sprint(parts.Hi, parts.Lo)
	return out, nil
}

func route(v xdr.ScVal) ([]queued, error) {
	d, err := decodeEntry(v)
	if err != nil {
		return nil, err
	}
	return stageAmount(d), nil
}

func stageAmount(d decodedEntry) []queued {
	return []queued{{Amount: d.Amount}}
}
