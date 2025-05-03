// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// //go:linkname directives type-checked by checklinkname.
// Runtime type copies checked by checkoffset.

package sync

import (
	"fmt"
	"reflect"
	"unsafe"
)

// Goyield is runtime.goyield, which is similar to runtime.Gosched but only
// yields the processor to other goroutines already on the processor's
// runqueue.
//
//go:nosplit
func Goyield() {
	goyield()
}

// Gopark is runtime.gopark. Gopark calls unlockf(pointer to runtime.g, lock);
// if unlockf returns true, Gopark blocks until Goready(pointer to runtime.g)
// is called. unlockf and its callees must be nosplit and norace, since stack
// splitting and race context are not available where it is called.
//
//go:nosplit
func Gopark(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceReason TraceBlockReason, traceskip int) {
	gopark(unlockf, lock, reason, traceReason, traceskip)
}

//go:linkname gopark runtime.gopark
func gopark(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceReason TraceBlockReason, traceskip int)

// TraceBlockReason is equivalent to runtime.traceBlockReason.
type TraceBlockReason uint8

//go:linkname wakep runtime.wakep
func wakep()

// Wakep is runtime.wakep.
//
//go:nosplit
func Wakep() {
	// This is only supported if we can suppress the wakep called
	// from  Goready below, which is in certain architectures only.
	if supportsWakeSuppression {
		wakep()
	}
}

//go:linkname goready runtime.goready
func goready(gp uintptr, traceskip int)

// Goready is runtime.goready.
//
// The additional wakep argument controls whether a new thread will be kicked to
// execute the P. This should be true in most circumstances. However, if the
// current thread is about to sleep, then this can be false for efficiency.
//
//go:nosplit
func Goready(gp uintptr, traceskip int, wakep bool) {
	if supportsWakeSuppression && !wakep {
		preGoReadyWakeSuppression()
	}
	goready(gp, traceskip)
	if supportsWakeSuppression && !wakep {
		postGoReadyWakeSuppression()
	}
}

// MapKeyHasher returns a hash function for pointers of m's key type.
//
// Preconditions: m must be a map.
func MapKeyHasher(m any) func(unsafe.Pointer, uintptr) uintptr {
	if rtyp := reflect.TypeOf(m); rtyp.Kind() != reflect.Map {
		panic(fmt.Sprintf("sync.MapKeyHasher: m is %v, not map", rtyp))
	}
	mtyp := *(**maptype)(unsafe.Pointer(&m))
	return mtyp.Hasher
}

// maptype is equivalent to the beginning of internal/abi.MapType.
type maptype struct {
	size       uintptr
	ptrdata    uintptr
	hash       uint32
	tflag      uint8
	align      uint8
	fieldAlign uint8
	kind       uint8
	equal      func(unsafe.Pointer, unsafe.Pointer) bool
	gcdata     *byte
	str        int32
	ptrToThis  int32
	key        unsafe.Pointer
	elem       unsafe.Pointer
	bucket     unsafe.Pointer
	Hasher     func(unsafe.Pointer, uintptr) uintptr
	// more fields
}

// These functions are only used within the sync package.

//go:linkname semacquire sync.runtime_Semacquire
func semacquire(addr *uint32)

//go:linkname semrelease sync.runtime_Semrelease
func semrelease(addr *uint32, handoff bool, skipframes int)

//go:linkname canSpin sync.runtime_canSpin
func canSpin(i int) bool

//go:linkname doSpin sync.runtime_doSpin
func doSpin()
