// Copyright 2018 Google LLC
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

package log

import (
	"reflect"
	"unsafe"
)

// unsafeString returns a string that points to the given byte array.
// The byte array must be preserved until the string is disposed.
func unsafeString(data []byte) (s string) {
	if len(data) == 0 {
		return
	}

	(*reflect.StringHeader)(unsafe.Pointer(&s)).Data = uintptr(unsafe.Pointer(&data[0]))
	(*reflect.StringHeader)(unsafe.Pointer(&s)).Len = len(data)
	return
}
