// Copyright 2019 The gVisor Authors.
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

	"gvisor.dev/gvisor/pkg/sync"
)

// Value is a required type parameter.
//
// Value must not contain any pointers, including interface objects, function
// objects, slices, maps, channels, unsafe.Pointer, and arrays or structs
// containing any of the above. An init() function will panic if this property
// does not hold.
type Value struct{}

// SeqAtomicLoad returns a copy of *ptr, ensuring that the read does not race
// with any writer critical sections in seq.
//
//go:nosplit
func SeqAtomicLoad(seq *sync.SeqCount, ptr *Value) Value {
	for {
		if val, ok := SeqAtomicTryLoad(seq, seq.BeginRead(), ptr); ok {
			return val
		}
	}
}

// SeqAtomicTryLoad returns a copy of *ptr while in a reader critical section
// in seq initiated by a call to seq.BeginRead() that returned epoch. If the
// read would race with a writer critical section, SeqAtomicTryLoad returns
// (unspecified, false).
//
//go:nosplit
func SeqAtomicTryLoad(seq *sync.SeqCount, epoch sync.SeqCountEpoch, ptr *Value) (val Value, ok bool) {
	if sync.RaceEnabled {
		// runtime.RaceDisable() doesn't actually stop the race detector, so it
		// can't help us here. Instead, call runtime.memmove directly, which is
		// not instrumented by the race detector.
		sync.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {
		// This is ~40% faster for short reads than going through memmove.
		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}

func init() {
	var val Value
	typ := reflect.TypeOf(val)
	name := typ.Name()
	if ptrs := sync.PointersInType(typ, name); len(ptrs) != 0 {
		panic(fmt.Sprintf("SeqAtomicLoad<%s> is invalid since values %s of type %s contain pointers:\n%s", typ, name, typ, strings.Join(ptrs, "\n")))
	}
}
