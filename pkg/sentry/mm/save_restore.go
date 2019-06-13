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
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
)

// InvalidateUnsavable invokes memmap.Mappable.InvalidateUnsavable on all
// Mappables mapped by mm.
func (mm *MemoryManager) InvalidateUnsavable(ctx context.Context) error {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	for vseg := mm.vmas.FirstSegment(); vseg.Ok(); vseg = vseg.NextSegment() {
		if vma := vseg.ValuePtr(); vma.mappable != nil {
			if err := vma.mappable.InvalidateUnsavable(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// beforeSave is invoked by stateify.
func (mm *MemoryManager) beforeSave() {
	mf := mm.mfp.MemoryFile()
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		if pma := pseg.ValuePtr(); pma.file != mf {
			// InvalidateUnsavable should have caused all such pmas to be
			// invalidated.
			panic(fmt.Sprintf("Can't save pma %#v with non-MemoryFile of type %T:\n%s", pseg.Range(), pma.file, mm))
		}
	}
}

// afterLoad is invoked by stateify.
func (mm *MemoryManager) afterLoad() {
	mm.haveASIO = mm.p.SupportsAddressSpaceIO()
	mf := mm.mfp.MemoryFile()
	for pseg := mm.pmas.FirstSegment(); pseg.Ok(); pseg = pseg.NextSegment() {
		pseg.ValuePtr().file = mf
	}
}
