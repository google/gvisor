// Copyright 2023 The gVisor Authors.
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

//go:build go1.20

package gohacks

import (
	"unsafe"
)

// ImmutableBytesFromString is equivalent to []byte(s), except that it uses the
// same memory backing s instead of making a heap-allocated copy. This is only
// valid if the returned slice is never mutated.
func ImmutableBytesFromString(s string) []byte {
	b := unsafe.StringData(s)
	return unsafe.Slice(b, len(s))
}

// StringFromImmutableBytes is equivalent to string(bs), except that it uses
// the same memory backing bs instead of making a heap-allocated copy. This is
// only valid if bs is never mutated after StringFromImmutableBytes returns.
func StringFromImmutableBytes(bs []byte) string {
	if len(bs) == 0 {
		return ""
	}
	return unsafe.String(&bs[0], len(bs))
}
