// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.13
// +build !go1.14

package sync

import (
	"runtime"
	_ "unsafe" // for go:linkname
)

//go:linkname canSpin sync.runtime_canSpin
func canSpin(i int) bool

//go:linkname doSpin sync.runtime_doSpin
func doSpin()

func goyield() {
	// goyield is not available until Go 1.14.
	runtime.Gosched()
}
