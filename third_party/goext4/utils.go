package goext4

import "fmt"

// WrapError takes input of any type and wraps it in an error type and return.
func WrapError(v interface{}) error {
	switch v := v.(type) {
	case error:
		return v
	default:
		return fmt.Errorf("%v", v)
	}
}
