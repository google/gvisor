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

//go:build (linux && amd64) || (linux && arm64)
// +build linux,amd64 linux,arm64

// Package stopfd provides an type that can be used to signal the stop of a dispatcher.
package stopfd

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// StopFD is an eventfd used to signal the stop of a dispatcher.
type StopFD struct {
	EFD int
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
	increment := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	if n, err := unix.Write(sf.EFD, increment); n != len(increment) || err != nil {
		// There are two possible errors documented in eventfd(2) for writing:
		// 1. We are writing 8 bytes and not 0xffffffffffffff, thus no EINVAL.
		// 2. stop is only supposed to be called once, it can't reach the limit,
		// thus no EAGAIN.
		panic(fmt.Sprintf("write(EFD) = (%d, %s), want (%d, nil)", n, err, len(increment)))
	}
}
