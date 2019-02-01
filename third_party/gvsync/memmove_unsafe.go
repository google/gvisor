// Copyright 2019 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gvsync

import (
	"unsafe"
)

// Memmove is exported for SeqAtomicLoad/SeqAtomicTryLoad<T>, which can't
// define it because go_generics can't update the go:linkname annotation.
// Furthermore, go:linkname silently doesn't work if the local name is exported
// (this is of course undocumented), which is why this indirection is
// necessary.
func Memmove(to, from unsafe.Pointer, n uintptr) {
	memmove(to, from, n)
}

//go:linkname memmove runtime.memmove
//go:noescape
func memmove(to, from unsafe.Pointer, n uintptr)
