// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hostlayoutcheck checks for `structs.HostLayout` usage.
package hostlayoutcheck

import (
	"fmt"
	"reflect"
	"structs"
)

// Validate checks that t is a struct type and has _ structs.HostLayout as its first field.
// It recursively checks all struct-typed fields.
func Validate(t reflect.Type) error {
	if t.Kind() != reflect.Struct {
		return fmt.Errorf("type %v is not a struct", t)
	}

	if t.NumField() == 0 {
		return fmt.Errorf("struct %v is empty, expected first field to be `_ structs.HostLayout`", t)
	}

	f := t.Field(0)
	// We check if the type of the first field is structs.HostLayout.
	if f.Type != reflect.TypeOf(structs.HostLayout{}) {
		return fmt.Errorf("struct %v first field must be `structs.HostLayout`, got `%v`", t, f.Type)
	}

	if f.Name != "_" {
		return fmt.Errorf("struct %v first field must be named `_`, got `%s`", t, f.Name)
	}

	// Recursive check for all other fields.
	// We skip the first field as it is the marker itself.
	for i := 1; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip fields tagged with `hostlayout:"ignore"`.
		if tag := field.Tag.Get("hostlayout"); tag == "ignore" {
			continue
		}

		fieldType := field.Type
		switch fieldType.Kind() {
		case reflect.Struct:
			if err := Validate(fieldType); err != nil {
				return fmt.Errorf("field %s: %w", field.Name, err)
			}
		case reflect.Array:
			if fieldType.Elem().Kind() == reflect.Struct {
				if err := Validate(fieldType.Elem()); err != nil {
					return fmt.Errorf("field %s: %w", field.Name, err)
				}
			}
		case reflect.Ptr:
			if fieldType.Elem().Kind() == reflect.Struct {
				if err := Validate(fieldType.Elem()); err != nil {
					return fmt.Errorf("field %s: %w", field.Name, err)
				}
			}
		case reflect.Map:
			return fmt.Errorf("field %s: maps are not allowed in host-layout-controlled structs (use `hostlayout:\"ignore\"` to bypass)", field.Name)
		case reflect.Chan:
			return fmt.Errorf("field %s: channels are not allowed in host-layout-controlled structs (use `hostlayout:\"ignore\"` to bypass)", field.Name)
		case reflect.Func:
			return fmt.Errorf("field %s: functions are not allowed in host-layout-controlled structs (use `hostlayout:\"ignore\"` to bypass)", field.Name)
		case reflect.Interface:
			return fmt.Errorf("field %s: interfaces are not allowed in host-layout-controlled structs (use `hostlayout:\"ignore\"` to bypass)", field.Name)
		case reflect.Slice:
			return fmt.Errorf("field %s: slices are not allowed in host-layout-controlled structs (use `hostlayout:\"ignore\"` to bypass)", field.Name)
		case reflect.String:
			// Allow strings only if they are specifically named "CString".
			if fieldType.Name() != "CString" {
				return fmt.Errorf("field %s: strings are not allowed in host-layout-controlled structs; use the CString type or `hostlayout:\"ignore\"` if you know what you are doing", field.Name)
			}
		}
	}
	return nil
}
