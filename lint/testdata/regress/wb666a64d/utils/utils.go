// Package utils stands in for wallet-backend's internal/utils at commit
// 666a64d: the one function the trimmed processors call.
package utils

import "reflect"

// IsEmpty reports whether v is its type's zero value.
func IsEmpty[T any](v T) bool { return reflect.ValueOf(&v).Elem().IsZero() }
