// Copyright 2023 The gVisor Authors.
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

//go:build amd64 || i386
// +build amd64 i386

package safecopy

import (
	"unsafe"
)

var (
	checkXstateBegin uintptr
	checkXstateEnd   uintptr
)

func initializeArchAddresses() {
	checkXstateBegin = addrOfCheckXstate()
	checkXstateEnd = FindEndAddress(checkXstateBegin)
}

//go:noescape
func checkXstate(addr uintptr) (fault uintptr, sig int32, mxcsr uint32, cw uint16)
func addrOfCheckXstate() uintptr

// CheckXstate verifies that xstate can be restored by the xrstor instruction.
func CheckXstate(state *byte) error {
	_, sig, _, _ := checkXstate(uintptr(unsafe.Pointer(state)))
	return errorFromFaultSignal(uintptr(unsafe.Pointer(state)), sig)
}
