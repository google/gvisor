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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// Sysinfo implements Linux syscall sysinfo(2).
func Sysinfo(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	mf := t.Kernel().MemoryFile()
	mfUsage, err := mf.TotalUsage()
	if err != nil {
		return 0, nil, err
	}
	memStats, _ := usage.MemoryAccounting.Copy()
	totalUsage := mfUsage + memStats.Mapped
	totalSize := usage.TotalMemory(mf.TotalSize(), totalUsage)
	memFree := totalSize - totalUsage
	if memFree > totalSize {
		// Underflow.
		memFree = 0
	}

	// Only a subset of the fields in sysinfo_t make sense to return.
	si := linux.Sysinfo{
		Procs:    uint16(t.Kernel().TaskSet().Root.NumTasks()),
		Uptime:   t.Kernel().MonotonicClock().Now().Seconds(),
		TotalRAM: totalSize,
		FreeRAM:  memFree,
		Unit:     1,
	}
	_, err = si.CopyOut(t, addr)
	return 0, nil, err
}
