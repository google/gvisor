// Copyright 2018 The gVisor Authors.
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

package serialization_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/sandbox"
)

// ignoreList is a list of field names that are ignored from the
// serializability check in this file.
// No gVisor-related field named should be here; instead, you can tag
// fields that are meant to be unserializable with `nojson:"true"`.
var ignoreList = map[string]struct{}{
	// Part of the OCI runtime spec, it uses an `interface{}` type which it
	// promises is JSON-serializable in the comments.
	"Container.Spec.Windows.CredentialSpec": struct{}{},
}

// implementsSerializableInterface returns true if the given type implements
// an interface which inherently provides serialization.
func implementsSerializableInterface(typ reflect.Type) bool {
	jsonMarshaler := reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	jsonUnmarshaler := reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	if typ.Implements(jsonMarshaler) && typ.Implements(jsonUnmarshaler) {
		return true
	}
	protoMessage := reflect.TypeOf((*proto.Message)(nil)).Elem()
	if typ.Implements(protoMessage) {
		return true
	}
	return false
}

// checkSerializable verifies that the given type is serializable.
func checkSerializable(typ reflect.Type, fieldName []string) error {
	if implementsSerializableInterface(typ) || implementsSerializableInterface(reflect.PointerTo(typ)) {
		return nil
	}
	field := func(s string) []string {
		return append(append(([]string)(nil), fieldName...), s)
	}
	fieldPath := strings.Join(fieldName, ".")
	if _, ignored := ignoreList[fieldPath]; ignored {
		return nil
	}
	switch typ.Kind() {
	case reflect.Bool:
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Float32, reflect.Float64:
		return nil
	case reflect.Complex64, reflect.Complex128:
		return nil
	case reflect.String:
		return nil
	case reflect.UnsafePointer:
		return fmt.Errorf("unsafe pointer %q not allowed in serializable struct", fieldPath)
	case reflect.Chan:
		return fmt.Errorf("channel %q not allowed in serializable struct", fieldPath)
	case reflect.Func:
		return fmt.Errorf("function %q not allowed in serializable struct", fieldPath)
	case reflect.Interface:
		return fmt.Errorf("interface %q not allowed in serializable struct", fieldPath)
	case reflect.Array:
		return fmt.Errorf("fixed-size array %q not allowed in serializable struct (use a slice instead)", fieldPath)
	case reflect.Slice:
		return checkSerializable(typ.Elem(), field("[]"))
	case reflect.Map:
		// We only allow a small subset of types as valid map key type.
		switch typ.Key().Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		case reflect.String:
		default:
			return fmt.Errorf("map key type %v of %q not allowed", typ.Key().Kind(), fieldPath)
		}
		// But all the value types are allowed.
		return checkSerializable(typ.Elem(), field("{}"))
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if _, noJSON := f.Tag.Lookup("nojson"); noJSON {
				if f.IsExported() {
					return fmt.Errorf("struct field %q must not be exported since it is marked `nojson:\"true\"` in a serializable struct", strings.Join(field(f.Name), "."))
				}
				continue
			}
			if !f.IsExported() {
				return fmt.Errorf("struct field %q must be exported or marked `nojson:\"true\"` since it is in a serializable struct", strings.Join(field(f.Name), "."))
			}
			if err := checkSerializable(f.Type, field(f.Name)); err != nil {
				return err
			}
		}
		return nil
	case reflect.Pointer:
		return checkSerializable(typ.Elem(), fieldName)
	default:
		return fmt.Errorf("unknown field type %v for %q", typ, fieldPath)
	}
}

// TestSerialization verifies that the Container struct only contains
// serializable fields.
func TestSerializable(t *testing.T) {
	for _, test := range []struct {
		name string
		obj  any
	}{
		{"Sandbox", sandbox.Sandbox{}},
		{"Container", container.Container{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkSerializable(reflect.TypeOf(test.obj), []string{test.name}); err != nil {
				t.Errorf("struct %v must be serializable: %v", test.name, err)
			}
		})
	}
}
