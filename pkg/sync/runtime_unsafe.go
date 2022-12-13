// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.13 && !go1.22
// +build go1.13,!go1.22

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

// Check type definitions and constants when updating Go version.
//
// TODO(b/165820485): add these checks to checklinkname.

package sync

import (
	"fmt"
	"reflect"
	"unsafe"
)

// YieldToGoPreemption yields the caller's P if it has been preempted by the Go
// runtime.
//
// YieldToGoPreemption is used when invoking long-running syscalls using
// RawSyscall in a tight loop; in this case, the Go runtime will send
// preemption signals, but the signal handler won't inject a call to
// runtime.goyield() and the preempted goroutine might not check for preemption
// within the loop, requiring explicit calls to YieldToGoPreemption when the
// syscall returns EINTR.
//
//go:noinline
func YieldToGoPreemption() {
	// All we need is a stack split check.
	yieldToGoPreemption2()
}

//go:noinline
func yieldToGoPreemption2() {
}

// Goyield is runtime.goyield, which is similar to runtime.Gosched but enqueues
// the caller on its current P's runqueue rather than the global runqueue.
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
//go:linkname Gopark runtime.gopark
func Gopark(unlockf func(uintptr, unsafe.Pointer) bool, lock unsafe.Pointer, reason uint8, traceEv byte, traceskip int)

// Goready is runtime.goready.
//
//go:linkname Goready runtime.goready
func Goready(gp uintptr, traceskip int)

// Wakep is runtime.wakep.
//
//go:linkname Wakep runtime.wakep
func Wakep()

// ProcPin is runtime.procPin. It disables Go runtime preemption and returns
// the caller's P's ID. Blocking in Go while runtime preemption is disabled is
// not permitted. The caller must call ProcUnpin to re-enable preemption.
//
//go:linkname ProcPin sync.runtime_procPin
func ProcPin() int

// ProcUnpin is runtime.procUnpin. It ends the effect of a previous call to
// ProcPin.
//
//go:linkname ProcUnpin sync.runtime_procUnpin
func ProcUnpin()

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
func MapKeyHasher(m any) func(unsafe.Pointer, uintptr) uintptr {
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
func semacquire(addr *uint32)

//go:linkname semrelease sync.runtime_Semrelease
func semrelease(addr *uint32, handoff bool, skipframes int)

//go:linkname canSpin sync.runtime_canSpin
func canSpin(i int) bool

//go:linkname doSpin sync.runtime_doSpin
func doSpin()
