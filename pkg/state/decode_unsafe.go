// Copyright 2020 The gVisor Authors.
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

package state

import (
	"reflect"
	"unsafe"
)

// unsafePointerTo is logically equivalent to reflect.Value.Addr, but works on
// values representing unexported fields. This bypasses visibility, but not
// type safety.
func unsafePointerTo(obj reflect.Value) reflect.Value {
	return reflect.NewAt(obj.Type(), unsafe.Pointer(obj.UnsafeAddr()))
}
