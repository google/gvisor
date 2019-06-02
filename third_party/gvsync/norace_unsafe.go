// Copyright 2019 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !race

package gvsync

import (
	"unsafe"
)

// RaceEnabled is true if the Go data race detector is enabled.
const RaceEnabled = false

// RaceDisable has the same semantics as runtime.RaceDisable.
func RaceDisable() {
}

// RaceEnable has the same semantics as runtime.RaceEnable.
func RaceEnable() {
}

// RaceAcquire has the same semantics as runtime.RaceAcquire.
func RaceAcquire(addr unsafe.Pointer) {
}

// RaceRelease has the same semantics as runtime.RaceRelease.
func RaceRelease(addr unsafe.Pointer) {
}

// RaceReleaseMerge has the same semantics as runtime.RaceReleaseMerge.
func RaceReleaseMerge(addr unsafe.Pointer) {
}
