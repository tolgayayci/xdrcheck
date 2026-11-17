// Package utils stands in for github.com/stellar/wallet-backend/internal/utils
// in the regression fixtures: only the helper the copied files call.
package utils

import "reflect"

// IsEmpty reports whether v is its type's zero value.
func IsEmpty[T any](v T) bool {
	return reflect.ValueOf(&v).Elem().IsZero()
}
