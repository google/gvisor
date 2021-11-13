// Copyright 2021 The gVisor Authors.
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

//go:build !linux && !windows
// +build !linux,!windows

package sighandling

import (
	"errors"

	"golang.org/x/sys/unix"
)

// IgnoreChildStop sets the SA_NOCLDSTOP flag, causing child processes to not
// generate SIGCHLD when they stop.
// TODO(gvisor.dev/issue/1270): Implement on Darwin.
func IgnoreChildStop() error {
	return errors.New("IgnoreChildStop only supported on Linux")
}

// ReplaceSignalHandler replaces the existing signal handler for the provided
// signal with the function pointer at `handler`. This bypasses the Go runtime
// signal handlers, and should only be used for low-level signal handlers where
// use of signal.Notify is not appropriate.
//
// It stores the value of the previously set handler in previous.
// TODO(gvisor.dev/issue/1270): Implement on Darwin.
func ReplaceSignalHandler(sig unix.Signal, handler uintptr, previous *uintptr) error {
	return errors.New("ReplaceSignalHandler only supported on Linux")
}
