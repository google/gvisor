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

package arch

import (
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/log"
)

// warnOnce is used to warn about truncated state only once.
var warnOnce sync.Once

// afterLoad is invoked by stateify.
func (s *State) afterLoad() {
	old := s.x86FPState

	// Recreate the slice. This is done to ensure that it is aligned
	// appropriately in memory, and large enough to accommodate any new
	// state that may be saved by the new CPU. Even if extraneous new state
	// is saved, the state we care about is guaranteed to be a subset of
	// new state. Later optimizations can use less space when using a
	// smaller state component bitmap. Intel SDM section 13 has more info.
	s.x86FPState = newX86FPState()

	// x86FPState always contains all the FP state supported by the host.
	// We may have come from a newer machine that supports additional state
	// which we cannot restore.
	//
	// The x86 FP state areas are backwards compatible, so we can simply
	// truncate the additional floating point state. Applications should
	// not depend on the truncated state because it should relate only to
	// features that were not exposed in the app FeatureSet.
	if len(s.x86FPState) < len(old) {
		warnOnce.Do(func() {
			// This will occur on every instance of state, don't
			// bother warning more than once.
			log.Infof("dropping %d bytes of floating point state; the application should not depend on this state", len(old)-len(s.x86FPState))
		})
	}

	// Copy to the new, aligned location.
	copy(s.x86FPState, old)
}

// +stateify savable
type syscallPtraceRegs struct {
	R15      uint64
	R14      uint64
	R13      uint64
	R12      uint64
	Rbp      uint64
	Rbx      uint64
	R11      uint64
	R10      uint64
	R9       uint64
	R8       uint64
	Rax      uint64
	Rcx      uint64
	Rdx      uint64
	Rsi      uint64
	Rdi      uint64
	Orig_rax uint64
	Rip      uint64
	Cs       uint64
	Eflags   uint64
	Rsp      uint64
	Ss       uint64
	Fs_base  uint64
	Gs_base  uint64
	Ds       uint64
	Es       uint64
	Fs       uint64
	Gs       uint64
}

// saveRegs is invoked by stateify.
func (s *State) saveRegs() syscallPtraceRegs {
	return syscallPtraceRegs(s.Regs)
}

// loadRegs is invoked by stateify.
func (s *State) loadRegs(r syscallPtraceRegs) {
	s.Regs = syscall.PtraceRegs(r)
}
