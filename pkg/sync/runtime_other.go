// Copyright 2020 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !amd64
// +build !amd64

package sync

// HaveNMSpinning is true if the IncNMSpinning and DecNMSpinning functions are
// implemented. Calls to these functions panic if HaveNMSpinning is false.
const HaveNMSpinning = false

// IncNMSpinning is unimplemented.
func IncNMSpinning() {
	panic("unimplemented")
}

// DecNMSpinning is unimplemented.
func DecNMSpinning() {
	panic("unimplemented")
}
