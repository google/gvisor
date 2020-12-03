// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13
// +build !go1.17

// Check function signatures and constants when updating Go version.

package sync

import (
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

// These functions are only used within the sync package.

//go:linkname semacquire sync.runtime_Semacquire
func semacquire(s *uint32)

//go:linkname semrelease sync.runtime_Semrelease
func semrelease(s *uint32, handoff bool, skipframes int)

//go:linkname canSpin sync.runtime_canSpin
func canSpin(i int) bool

//go:linkname doSpin sync.runtime_doSpin
func doSpin()
