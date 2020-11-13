// Copyright 2018 The gVisor Authors.
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

package kernel

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// syscallTableInfo is used to reload the SyscallTable.
//
// +stateify savable
type syscallTableInfo struct {
	OS   abi.OS
	Arch arch.Arch
}

// saveSt saves the SyscallTable.
func (image *TaskImage) saveSt() syscallTableInfo {
	return syscallTableInfo{
		OS:   image.st.OS,
		Arch: image.st.Arch,
	}
}

// loadSt loads the SyscallTable.
func (image *TaskImage) loadSt(sti syscallTableInfo) {
	st, ok := LookupSyscallTable(sti.OS, sti.Arch)
	if !ok {
		panic(fmt.Sprintf("syscall table not found for OS %v, Arch %v", sti.OS, sti.Arch))
	}
	image.st = st // Save the table reference.
}
