// Package xdr204 holds the XDR204 fixtures (an opt-in rule): a serialised
// recursive value stored with no length check.
package xdr204

import (
	"database/sql"

	"github.com/stellar/go-stellar-sdk/xdr"
)

const maxStored = 1 << 16

func storeValue(db *sql.DB, v xdr.ScVal) error {
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO vals (v) VALUES ($1)", s) // want `XDR204 \(info\): serialised recursive xdr value s is stored with no length check`
	return err
}

func storeChecked(db *sql.DB, v xdr.ScVal) error {
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		return err
	}
	if len(s) > maxStored {
		return nil
	}
	_, err = db.Exec("INSERT INTO vals (v) VALUES ($1)", s)
	return err
}
