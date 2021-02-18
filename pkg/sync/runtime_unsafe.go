// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13
// +build !go1.18

// Check go:linkname function signatures, type definitions, and constants when
// updating Go version.

package sync

import (
	"fmt"
	"reflect"
	"unsafe"
)

// Note that go:linkname silently doesn't work if the local name is exported,
// necessitating an indirection for exported functions.

// Memmove is runtime.memmove, exported for SeqAtomicLoad/SeqAtomicTryLoad<T>.
//
//go:nosplit
func Memmove(to, from unsafe.Pointer, n uintptr) {
	memmove(to, from, n)
}

//go:linkname memmove runtime.memmove
//go:noescape
func memmove(to, from unsafe.Pointer, n uintptr)

// Gopark is runtime.gopark. Gopark calls unlockf(pointer to runtime.g, lock);
// if unlockf returns true, Gopark blocks until Goready(pointer to runtime.g)
// is called. unlockf and its callees must be nosplit and norace, since stack
// splitting and race context are not available where it is called.
//
//go:nosplit
func Gopark(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceEv byte, traceskip int) {
	gopark(unlockf, lock, reason, traceEv, traceskip)
}

//go:linkname gopark runtime.gopark
func gopark(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceEv byte, traceskip int)

// Goready is runtime.goready.
//
//go:nosplit
func Goready(gp uintptr, traceskip int) {
	goready(gp, traceskip)
}

//go:linkname goready runtime.goready
func goready(gp uintptr, traceskip int)

// Values for the reason argument to gopark, from Go's src/runtime/runtime2.go.
const (
	WaitReasonSelect uint8 = 9
)

// Values for the traceEv argument to gopark, from Go's src/runtime/trace.go.
const (
	TraceEvGoBlockSelect byte = 24
)

// Rand32 returns a non-cryptographically-secure random uint32.
func Rand32() uint32 {
	return fastrand()
}

// Rand64 returns a non-cryptographically-secure random uint64.
func Rand64() uint64 {
	return uint64(fastrand())<<32 | uint64(fastrand())
}

//go:linkname fastrand runtime.fastrand
func fastrand() uint32

// RandUintptr returns a non-cryptographically-secure random uintptr.
func RandUintptr() uintptr {
	if unsafe.Sizeof(uintptr(0)) == 4 {
		return uintptr(Rand32())
	}
	return uintptr(Rand64())
}

// MapKeyHasher returns a hash function for pointers of m's key type.
//
// Preconditions: m must be a map.
func MapKeyHasher(m interface{}) func(unsafe.Pointer, uintptr) uintptr {
	if rtyp := reflect.TypeOf(m); rtyp.Kind() != reflect.Map {
		panic(fmt.Sprintf("sync.MapKeyHasher: m is %v, not map", rtyp))
	}
	mtyp := *(**maptype)(unsafe.Pointer(&m))
	return mtyp.hasher
}

// maptype is equivalent to the beginning of runtime.maptype.
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
	hasher     func(unsafe.Pointer, uintptr) uintptr
	// more fields
}

// These functions are only used within the sync package.

//go:linkname semacquire sync.runtime_Semacquire
func semacquire(s *uint32)

//go:linkname semrelease sync.runtime_Semrelease
func semrelease(s *uint32, handoff bool, skipframes int)

//go:linkname canSpin sync.runtime_canSpin
func canSpin(i int) bool

//go:linkname doSpin sync.runtime_doSpin
func doSpin()
