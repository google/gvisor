// Copyright 2026 The gVisor Authors.
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

//go:build amd64
// +build amd64

package kernel

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
)

// syncFPStateSize grows t's FP state once its thread group has been granted
// AMX, so that it holds tile data state. It returns false if t must exit.
func (t *Task) syncFPStateSize() bool {
	if t.tg.xcompPerm.Load()&cpuid.XCR0AmxDataMask == 0 {
		return true
	}
	return t.syncFPStateSizeAMX()
}

// syncFPStateSizeAMX implements syncFPStateSize for a thread group that has
// been granted AMX.
func (t *Task) syncFPStateSizeAMX() bool {
	fp := t.Arch().FloatingPointData()
	if fp.HasAMX() {
		return true
	}
	// The platform may hold newer state than t. After growing it, give all of
	// it to the platform, so that the platform does not keep stale data where
	// the tile data state now is.
	if err := t.p.PullFullState(t.MemoryManager().AddressSpace(), t.Arch()); err != nil {
		t.Warningf("Unable to pull a full state: %v", err)
		t.PrepareExit(linux.WaitStatusExit(int32(ExtractErrno(err, -1))))
		return false
	}
	fp.EnableAMX()
	t.p.FullStateChanged()
	return true
}

// fpStateNeedsResize returns true if syncFPStateSize will grow t's FP state.
func (t *Task) fpStateNeedsResize() bool {
	return t.tg.xcompPerm.Load()&cpuid.XCR0AmxDataMask != 0 && !t.Arch().FloatingPointData().HasAMX()
}
