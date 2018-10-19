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

// Package template doesn't exist. This file must be instantiated using the
// go_template_instance rule in tools/go_generics/defs.bzl.
package template

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	ssync "gvisor.googlesource.com/gvisor/pkg/sync"
)

// Value is a required type parameter.
//
// Value must not contain any pointers, including interface objects, function
// objects, slices, maps, channels, unsafe.Pointer, and arrays or structs
// containing any of the above. An init() function will panic if this property
// does not hold.
type Value struct{}

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in sc.
func SeqAtomicLoad(sc *ssync.SeqCount, ptr *Value) Value {
	// This function doesn't use SeqAtomicTryLoad because doing so is
	// measurably, significantly (~20%) slower; Go is awful at inlining.
	var val Value
	for {
		epoch := sc.BeginRead()
		if ssync.RaceEnabled {
			// runtime.RaceDisable() doesn't actually stop the race detector,
			// so it can't help us here. Instead, call runtime.memmove
			// directly, which is not instrumented by the race detector.
			ssync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
		} else {
			// This is ~40% faster for short reads than going through memmove.
			val = *ptr
		}
		if sc.ReadOk(epoch) {
			break
		}
	}
	return val
}

// SeqAtomicTryLoad returns a copy of *ptr while in a reader critical section
// in sc initiated by a call to sc.BeginRead() that returned epoch. If the read
// would race with a writer critical section, SeqAtomicTryLoad returns
// (unspecified, false).
func SeqAtomicTryLoad(sc *ssync.SeqCount, epoch ssync.SeqCountEpoch, ptr *Value) (Value, bool) {
	var val Value
	if ssync.RaceEnabled {
		ssync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {
		val = *ptr
	}
	return val, sc.ReadOk(epoch)
}

func init() {
	var val Value
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := ssync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
