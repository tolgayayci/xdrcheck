// Package xdr103 holds the XDR103 fixtures: submitter- or contract-controlled
// bytes reaching text storage without UTF-8 and NUL handling.
package xdr103

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"unicode/utf8"

	"github.com/stellar/go-stellar-sdk/ingest"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type tokenRow struct {
	Contract string `db:"contract_id"`
	Name     string `db:"name"`
}

type exportRow struct {
	Memo     string `json:"memo"`
	DataName string `json:"data_name"`
}

// (a) Memo text into a database/sql parameter.
func storeMemo(db *sql.DB, memo xdr.Memo) error {
	text, ok := memo.GetText()
	if !ok {
		return nil
	}
	_, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text) // want `XDR103 \(error\): xdr.Memo.GetText\(\) \(line \d+\) carries submitter- or contract-controlled bytes into sql.DB.Exec\(\) without a UTF-8 and NUL check`
	return err
}

// (b) A contract string into a db-tagged field.
func tokenName(contract string, scv xdr.ScVal) tokenRow {
	row := tokenRow{Contract: contract}
	if s, ok := scv.GetStr(); ok {
		row.Name = string(s) // want `XDR103 \(error\): xdr.ScVal.GetStr\(\) .* into database field xdr103.tokenRow.Name`
	}
	return row
}

// noteRecord stands for a protobuf-generated message of the reader's own.
type noteRecord struct {
	Note string `protobuf:"bytes,1,opt,name=note,proto3"`
}

// (c) Memo text into a proto3 string field.
func memoRecord(memo xdr.Memo) *noteRecord {
	return &noteRecord{
		Note: *memo.Text, // want `XDR103 \(error\): xdr.Memo.Text .* into proto3 string field xdr103.noteRecord.Note`
	}
}

// (d) The ingest helper's memo string into a text column.
func storeTxMemo(ctx context.Context, tx *sql.Tx, ltx *ingest.LedgerTransaction) error {
	_, err := tx.ExecContext(ctx, `UPDATE txs SET memo = $1`, ltx.Memo()) // want `XDR103 \(error\): ingest.LedgerTransaction.Memo\(\)`
	return err
}

// (e) The executable tag of a contract instance (Protocol 28).
func executableTag(ctx context.Context, db *sql.DB, scv xdr.ScVal) *sql.Row {
	tag := scv.MustExecutableTag()
	return db.QueryRowContext(ctx, `SELECT 1 FROM tags WHERE tag = $1`, string(tag)) // want `XDR103 \(error\): xdr.ScVal.MustExecutableTag\(\)`
}

// (f) A data entry's value rendered as a string into JSON: a warning.
func exportData(entry xdr.DataEntry) exportRow {
	return exportRow{
		DataName: string(entry.DataName),
		Memo:     string(entry.DataValue), // want `XDR103 \(warning\): xdr.DataEntry.DataValue .* into JSON field xdr103.exportRow.Memo`
	}
}

// (g) The same bytes through the read-only View API.
func storeViewString(db *sql.DB, v xdr.ScValView) error {
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, string(v.MustStr().MustValue())) // want `XDR103 \(error\): xdr.ScValView.MustStr\(\)`
	return err
}

// (h) Only the UTF-8 half of the check.
func storeHalfChecked(db *sql.DB, scv xdr.ScVal) error {
	s := string(scv.MustStr())
	if !utf8.ValidString(s) {
		return nil
	}
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, s) // want `XDR103 \(error\): .* without a NUL check`
	return err
}

// (i) A symbol: the host restricts its characters, so info only.
func storeTopic(db *sql.DB, topic xdr.ScVal) error {
	_, err := db.Exec(`INSERT INTO topics (sym) VALUES ($1)`, string(topic.MustSym())) // want `XDR103 \(info\): xdr.ScVal.MustSym\(\)`
	return err
}

// (j) SQL built by concatenation.
func storeConcatenated(db *sql.DB, memo xdr.Memo) error {
	_, err := db.Exec(`INSERT INTO memos (text) VALUES ('` + memo.MustText() + `')`) // want `XDR103 \(error\): xdr.Memo.MustText\(\)`
	return err
}

// (k) A parameter of type xdr.ScString, called from another package.
func StoreName(db *sql.DB, name xdr.ScString) error {
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, string(name)) // want `XDR103 \(error\): parameter name of type xdr.ScString`
	return err
}

// (l) A field annotated as a text sink.
type labelRow struct {
	//xdrlint:sink text
	Name string
}

func labelName(scv xdr.ScVal) labelRow {
	var row labelRow
	row.Name = string(scv.MustStr()) // want `XDR103 \(error\): xdr.ScVal.MustStr\(\) .* into text field xdr103.labelRow.Name`
	return row
}

// (m) A check whose failing branch only logs: both branches reach the sink.
func storeNameLogged(db *sql.DB, scv xdr.ScVal) error {
	s := string(scv.MustStr())
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		log.Printf("token name is not clean text")
	}
	_, err := db.Exec(`INSERT INTO names (name) VALUES ($1)`, s) // want `XDR103 \(error\): xdr.ScVal.MustStr\(\) .* without a UTF-8 and NUL check`
	return err
}

// (n) The sink sits on the failing branch.
func storeOnlyBad(db *sql.DB, memo xdr.Memo) error {
	text := memo.MustText()
	if !utf8.ValidString(text) || strings.Contains(text, "\x00") {
		_, err := db.Exec(`INSERT INTO rejected (text) VALUES ($1)`, text) // want `XDR103 \(error\): xdr.Memo.MustText\(\)`
		return err
	}
	return nil
}

// (o) A helper that looks at the value but reports nothing: calling it is
// not a check.
func warnIfBad(s string) error {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		log.Printf("bad text %q", s)
	}
	return nil
}

func storeAfterWarning(db *sql.DB, memo xdr.Memo) error {
	text := memo.MustText()
	if err := warnIfBad(text); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO memos (text) VALUES ($1)`, text) // want `XDR103 \(error\): xdr.Memo.MustText\(\)`
	return err
}

// (p) The text field of a decoded entry (good.go (k)) stored in a text
// column: field-sensitive flow keeps this report while dropping the amount.
func routeName(v xdr.ScVal) (tokenRow, error) {
	d, err := decodeEntry(v)
	if err != nil || d.Label == nil {
		return tokenRow{}, err
	}
	return tokenRow{Name: d.Label.Name}, nil // want `XDR103 \(error\): xdr.ScVal.GetStr\(\) .* into database field xdr103.tokenRow.Name`
}
