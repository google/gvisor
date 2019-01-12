// Copyright 2018 Google LLC
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

// +build linux,amd64
// +build !go1.13

// This must be validated with Go 1.13 and future releases.

package rawfile

import (
	"syscall"
	_ "unsafe" // for go:linkname
)

//go:noescape
func blockingPoll(fds *pollEvent, nfds int, timeout int64) (int, syscall.Errno)

// Use go:linkname to call into the runtime. As of Go 1.12 this has to
// be done from Go code so that we make an ABIInternal call to an
// ABIInternal function; see https://golang.org/issue/27539.

// We need to call both entersyscallblock and exitsyscall this way so
// that the runtime's check on the stack pointer lines up.

// Note that calling an unexported function in the runtime package is
// unsafe and this hack is likely to break in future Go releases.

//go:linkname entersyscallblock runtime.entersyscallblock
func entersyscallblock()

//go:linkname exitsyscall runtime.exitsyscall
func exitsyscall()

// These forwarding functions must be nosplit because 1) we must
// disallow preemption between entersyscallblock and exitsyscall, and
// 2) we have an untyped assembly frame on the stack which can not be
// grown or moved.

//go:nosplit
func callEntersyscallblock() {
	entersyscallblock()
}

//go:nosplit
func callExitsyscall() {
	exitsyscall()
}
