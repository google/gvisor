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

package mm

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/shm"
)

// DetachShm unmaps a sysv shared memory segment.
func (mm *MemoryManager) DetachShm(ctx context.Context, addr hostarch.Addr) error {
	if addr != addr.RoundDown() {
		// "... shmaddr is not aligned on a page boundary." - man shmdt(2)
		return linuxerr.EINVAL
	}

	var detached *shm.Shm
	mm.mappingMu.Lock()
	defer mm.mappingMu.Unlock()

	// Find and remove the first vma containing an address >= addr that maps a
	// segment originally attached at addr.
	vseg := mm.vmas.LowerBoundSegment(addr)
	for vseg.Ok() {
		vma := vseg.ValuePtr()
		if shm, ok := vma.mappable.(*shm.Shm); ok && vseg.Start() >= addr && uint64(vseg.Start()-addr) == vma.off {
			detached = shm
			vseg = mm.unmapLocked(ctx, vseg.Range()).NextSegment()
			break
		} else {
			vseg = vseg.NextSegment()
		}
	}

	if detached == nil {
		// There is no shared memory segment attached at addr.
		return linuxerr.EINVAL
	}

	// Remove all vmas that could have been created by the same attach.
	end := addr + hostarch.Addr(detached.EffectiveSize())
	for vseg.Ok() && vseg.End() <= end {
		vma := vseg.ValuePtr()
		if vma.mappable == detached && uint64(vseg.Start()-addr) == vma.off {
			vseg = mm.unmapLocked(ctx, vseg.Range()).NextSegment()
		} else {
			vseg = vseg.NextSegment()
		}
	}

	return nil
}
