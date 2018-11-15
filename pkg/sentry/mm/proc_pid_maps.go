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

package mm

import (
	"bytes"
	"fmt"
	"strings"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/seqfile"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

const (
	// devMinorBits is the number of minor bits in a device number. Linux:
	// include/linux/kdev_t.h:MINORBITS
	devMinorBits = 20
)

// NeedsUpdate implements seqfile.SeqSource.NeedsUpdate.
func (mm *MemoryManager) NeedsUpdate(generation int64) bool {
	return true
}

// ReadSeqFileData is called by fs/proc.mapsData.ReadSeqFileData.
func (mm *MemoryManager) ReadSeqFileData(ctx context.Context, handle seqfile.SeqHandle) ([]seqfile.SeqData, int64) {
	mm.mappingMu.RLock()
	defer mm.mappingMu.RUnlock()
	var data []seqfile.SeqData
	var start usermem.Addr
	if handle != nil {
		start = *handle.(*usermem.Addr)
	}
	for vseg := mm.vmas.LowerBoundSegment(start); vseg.Ok(); vseg = vseg.NextSegment() {
		// FIXME: If we use a usermem.Addr for the handle, we get
		// "panic: autosave error: type usermem.Addr is not registered".
		vmaAddr := vseg.End()
		data = append(data, seqfile.SeqData{
			Buf:    mm.vmaMapsEntryLocked(ctx, vseg),
			Handle: &vmaAddr,
		})
	}

	// We always emulate vsyscall, so advertise it here. Everything about a
	// vsyscall region is static, so just hard code the maps entry since we
	// don't have a real vma backing it. The vsyscall region is at the end of
	// the virtual address space so nothing should be mapped after it (if
	// something is really mapped in the tiny ~10 MiB segment afterwards, we'll
	// get the sorting on the maps file wrong at worst; but that's not possible
	// on any current platform).
	//
	// Artifically adjust the seqfile handle so we only output vsyscall entry once.
	if vsyscallEnd := usermem.Addr(0xffffffffff601000); start != vsyscallEnd {
		data = append(data, seqfile.SeqData{
			Buf:    []byte("ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\n"),
			Handle: &vsyscallEnd,
		})
	}
	return data, 1
}

// vmaMapsEntryLocked returns a /proc/[pid]/maps entry for the vma iterated by
// vseg, including the trailing newline.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) vmaMapsEntryLocked(ctx context.Context, vseg vmaIterator) []byte {
	vma := vseg.ValuePtr()
	private := "p"
	if !vma.private {
		private = "s"
	}

	var dev, ino uint64
	if vma.id != nil {
		dev = vma.id.DeviceID()
		ino = vma.id.InodeID()
	}
	devMajor := uint32(dev >> devMinorBits)
	devMinor := uint32(dev & ((1 << devMinorBits) - 1))

	var b bytes.Buffer
	// Do not include the guard page: fs/proc/task_mmu.c:show_map_vma() =>
	// stack_guard_page_start().
	fmt.Fprintf(&b, "%08x-%08x %s%s %08x %02x:%02x %d ",
		vseg.Start(), vseg.End(), vma.realPerms, private, vma.off, devMajor, devMinor, ino)

	// Figure out our filename or hint.
	var s string
	if vma.hint != "" {
		s = vma.hint
	} else if vma.id != nil {
		// FIXME: We are holding mm.mappingMu here, which is
		// consistent with Linux's holding mmap_sem in
		// fs/proc/task_mmu.c:show_map_vma() => fs/seq_file.c:seq_file_path().
		// However, it's not clear that fs.File.MappedName() is actually
		// consistent with this lock order.
		s = vma.id.MappedName(ctx)
	}
	if s != "" {
		// Per linux, we pad until the 74th character.
		if pad := 73 - b.Len(); pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteString(s)
	}
	b.WriteString("\n")
	return b.Bytes()
}
