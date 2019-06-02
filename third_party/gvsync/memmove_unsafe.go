// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.12
// +build !go1.14

// Check go:linkname function signatures when updating Go version.

package gvsync

import (
	"unsafe"
)

//go:linkname memmove runtime.memmove
//go:noescape
func memmove(to, from unsafe.Pointer, n uintptr)

// Memmove is exported for SeqAtomicLoad/SeqAtomicTryLoad<T>, which can't
// define it because go_generics can't update the go:linkname annotation.
// Furthermore, go:linkname silently doesn't work if the local name is exported
// (this is of course undocumented), which is why this indirection is
// necessary.
func Memmove(to, from unsafe.Pointer, n uintptr) {
	memmove(to, from, n)
}
