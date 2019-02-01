// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package template doesn't exist. This file must be instantiated using the
// go_template_instance rule in tools/go_generics/defs.bzl.
package template

import (
	"fmt"
	"reflect"
	"strings"
	"unsafe"

	"gvisor.googlesource.com/gvisor/third_party/gvsync"
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
func SeqAtomicLoad(sc *gvsync.SeqCount, ptr *Value) Value {
	// This function doesn't use SeqAtomicTryLoad because doing so is
	// measurably, significantly (~20%) slower; Go is awful at inlining.
	var val Value
	for {
		epoch := sc.BeginRead()
		if gvsync.RaceEnabled {
			// runtime.RaceDisable() doesn't actually stop the race detector,
			// so it can't help us here. Instead, call runtime.memmove
			// directly, which is not instrumented by the race detector.
			gvsync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
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
func SeqAtomicTryLoad(sc *gvsync.SeqCount, epoch gvsync.SeqCountEpoch, ptr *Value) (Value, bool) {
	var val Value
	if gvsync.RaceEnabled {
		gvsync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {
		val = *ptr
	}
	return val, sc.ReadOk(epoch)
}

func init() {
	var val Value
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := gvsync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
