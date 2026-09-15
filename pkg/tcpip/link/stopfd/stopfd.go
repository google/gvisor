// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

// Package stopfd provides an type that can be used to signal the stop of a dispatcher.
package stopfd

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// StopFD is an eventfd used to signal the stop of a dispatcher.
//
// +stateify savable
type StopFD struct {
	// EFD is the eventfd, or -1 once closed. It is not saved: a restored
	// StopFD would otherwise hold a stale fd number that Close would close.
	EFD int `state:"nosave"`
}

// afterLoad is invoked by stateify.
func (sf *StopFD) afterLoad(context.Context) {
	sf.EFD = -1
}

// New returns a new, initialized StopFD.
func New() (StopFD, error) {
	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		return StopFD{EFD: -1}, fmt.Errorf("failed to create eventfd: %w", err)
	}
	return StopFD{EFD: efd}, nil
}

// Stop writes to the eventfd and notifies the dispatcher to stop. It does not
// block.
func (sf *StopFD) Stop() {
	if sf.EFD < 0 {
		return
	}
	increment := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if n, err := unix.Write(sf.EFD, increment); n != len(increment) || err != nil {
		// There are two possible errors documented in eventfd(2) for writing:
		// 1. We are writing 8 bytes and not 0xffffffffffffff, thus no EINVAL.
		// 2. stop is only supposed to be called once, it can't reach the limit,
		// thus no EAGAIN.
		panic(fmt.Sprintf("write(EFD) = (%d, %s), want (%d, nil)", n, err, len(increment)))
	}
}

// Close releases the eventfd. It must not be called while a dispatcher may
// still be polling the eventfd. Calling it more than once is a no-op.
func (sf *StopFD) Close() {
	if sf.EFD < 0 {
		return
	}
	unix.Close(sf.EFD)
	sf.EFD = -1
}
