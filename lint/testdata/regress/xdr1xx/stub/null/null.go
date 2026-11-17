// Package null stands in for github.com/guregu/null in the regression
// fixtures: only the types and constructors the copied files use.
package null

import "database/sql"

// String is a nullable string.
type String struct{ sql.NullString }

// StringFrom returns a valid String holding s.
func StringFrom(s string) String { return String{sql.NullString{String: s, Valid: true}} }

// Int is a nullable int64.
type Int struct{ sql.NullInt64 }

// IntFrom returns a valid Int holding i.
func IntFrom(i int64) Int { return Int{sql.NullInt64{Int64: i, Valid: true}} }
