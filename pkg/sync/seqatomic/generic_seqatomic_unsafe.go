// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

// Package seqatomic doesn't exist. This file must be instantiated using the
// go_template_instance rule in tools/go_generics/defs.bzl.
package seqatomic

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sync"
)

// Value is a required type parameter.
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
		gohacks.Memmove(unsafe.Pointer(&val), unsafe.Pointer(ptr), unsafe.Sizeof(val))
	} else {
		// This is ~40% faster for short reads than going through memmove.
		val = *ptr
	}
	ok = seq.ReadOk(epoch)
	return
}

// SeqAtomicStore sets *ptr to a copy of val, ensuring that any racing reader
// critical sections are forced to retry.
//
//go:nosplit
func SeqAtomicStore(seq *sync.SeqCount, ptr *Value, val Value) {
	seq.BeginWrite()
	SeqAtomicStoreSeqed(ptr, val)
	seq.EndWrite()
}

// SeqAtomicStoreSeqed sets *ptr to a copy of val.
//
// Preconditions: ptr is protected by a SeqCount that will be in a writer
// critical section throughout the call to SeqAtomicStore.
//
//go:nosplit
func SeqAtomicStoreSeqed(ptr *Value, val Value) {
	if sync.RaceEnabled {
		gohacks.Memmove(unsafe.Pointer(ptr), unsafe.Pointer(&val), unsafe.Sizeof(val))
	} else {
		*ptr = val
	}
}
