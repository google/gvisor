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
	goContext "context"
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
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

// afterLoad is invoked by stateify.
func (mm *MemoryManager) afterLoad(ctx goContext.Context) {
	mm.mf = pgalloc.MemoryFileFromContext(ctx)
	mm.haveASIO = mm.p.SupportsAddressSpaceIO()
}

// afterLoad is invoked by stateify.
func (m *SpecialMappable) afterLoad(ctx goContext.Context) {
	m.mf = pgalloc.MemoryFileFromContext(ctx)
}

const (
	vmaRealPermsRead = 1 << iota
	vmaRealPermsWrite
	vmaRealPermsExecute
	vmaEffectivePermsRead
	vmaEffectivePermsWrite
	vmaEffectivePermsExecute
	vmaMaxPermsRead
	vmaMaxPermsWrite
	vmaMaxPermsExecute
	vmaPrivate
	vmaGrowsDown
	vmaIsStack
)

func (v *vma) saveRealPerms() int {
	var b int
	if v.realPerms.Read {
		b |= vmaRealPermsRead
	}
	if v.realPerms.Write {
		b |= vmaRealPermsWrite
	}
	if v.realPerms.Execute {
		b |= vmaRealPermsExecute
	}
	if v.effectivePerms.Read {
		b |= vmaEffectivePermsRead
	}
	if v.effectivePerms.Write {
		b |= vmaEffectivePermsWrite
	}
	if v.effectivePerms.Execute {
		b |= vmaEffectivePermsExecute
	}
	if v.maxPerms.Read {
		b |= vmaMaxPermsRead
	}
	if v.maxPerms.Write {
		b |= vmaMaxPermsWrite
	}
	if v.maxPerms.Execute {
		b |= vmaMaxPermsExecute
	}
	if v.private {
		b |= vmaPrivate
	}
	if v.growsDown {
		b |= vmaGrowsDown
	}
	if v.isStack {
		b |= vmaIsStack
	}
	return b
}

func (v *vma) loadRealPerms(_ goContext.Context, b int) {
	if b&vmaRealPermsRead > 0 {
		v.realPerms.Read = true
	}
	if b&vmaRealPermsWrite > 0 {
		v.realPerms.Write = true
	}
	if b&vmaRealPermsExecute > 0 {
		v.realPerms.Execute = true
	}
	if b&vmaEffectivePermsRead > 0 {
		v.effectivePerms.Read = true
	}
	if b&vmaEffectivePermsWrite > 0 {
		v.effectivePerms.Write = true
	}
	if b&vmaEffectivePermsExecute > 0 {
		v.effectivePerms.Execute = true
	}
	if b&vmaMaxPermsRead > 0 {
		v.maxPerms.Read = true
	}
	if b&vmaMaxPermsWrite > 0 {
		v.maxPerms.Write = true
	}
	if b&vmaMaxPermsExecute > 0 {
		v.maxPerms.Execute = true
	}
	if b&vmaPrivate > 0 {
		v.private = true
	}
	if b&vmaGrowsDown > 0 {
		v.growsDown = true
	}
	if b&vmaIsStack > 0 {
		v.isStack = true
	}
}

func (p *pma) saveFile() string {
	mf, ok := p.file.(*pgalloc.MemoryFile)
	if !ok {
		// InvalidateUnsavable should have caused all such pmas to be
		// invalidated.
		panic(fmt.Sprintf("Can't save pma with non-MemoryFile of type %T", p.file))
	}
	if !mf.IsSavable() {
		panic(fmt.Sprintf("Can't save pma because its MemoryFile is not savable: %v", mf))
	}
	return mf.RestoreID()
}

func (p *pma) loadFile(ctx goContext.Context, restoreID string) {
	if restoreID == "" {
		p.file = pgalloc.MemoryFileFromContext(ctx)
		return
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	mf, ok := mfmap[restoreID]
	if !ok {
		panic(fmt.Sprintf("can't restore pma because its MemoryFile's restore ID %q was not found in CtxMemoryFileMap", restoreID))
	}
	p.file = mf
}
