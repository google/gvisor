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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

const (
	// devMinorBits is the number of minor bits in a device number. Linux:
	// include/linux/kdev_t.h:MINORBITS
	devMinorBits = 20

	vsyscallEnd        = hostarch.Addr(0xffffffffff601000)
	vsyscallMapsEntry  = "ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]\n"
	vsyscallSmapsEntry = vsyscallMapsEntry +
		"Size:                  4 kB\n" +
		"Rss:                   0 kB\n" +
		"Pss:                   0 kB\n" +
		"Shared_Clean:          0 kB\n" +
		"Shared_Dirty:          0 kB\n" +
		"Private_Clean:         0 kB\n" +
		"Private_Dirty:         0 kB\n" +
		"Referenced:            0 kB\n" +
		"Anonymous:             0 kB\n" +
		"AnonHugePages:         0 kB\n" +
		"Shared_Hugetlb:        0 kB\n" +
		"Private_Hugetlb:       0 kB\n" +
		"Swap:                  0 kB\n" +
		"SwapPss:               0 kB\n" +
		"KernelPageSize:        4 kB\n" +
		"MMUPageSize:           4 kB\n" +
		"Locked:                0 kB\n" +
		"VmFlags: rd ex \n"
)

// MapsCallbackFuncForBuffer creates a /proc/[pid]/maps entry including the trailing newline.
func (mm *MemoryManager) MapsCallbackFuncForBuffer(buf *bytes.Buffer) MapsCallbackFunc {
	return func(start, end hostarch.Addr, permissions hostarch.AccessType, private string, offset uint64, devMajor, devMinor uint32, inode uint64, path string) {
		// Do not include the guard page: fs/proc/task_mmu.c:show_map_vma() =>
		// stack_guard_page_start().
		lineLen, err := fmt.Fprintf(buf, "%08x-%08x %s%s %08x %02x:%02x %d ",
			start, end, permissions, private, offset, devMajor, devMinor, inode)
		if err != nil {
			log.Warningf("Failed to write to buffer with error: %v", err)
			return
		}

		if path != "" {
			// Per linux, we pad until the 74th character.
			for pad := 73 - lineLen; pad > 0; pad-- {
				buf.WriteByte(' ') // never returns a non-nil error
			}
			buf.WriteString(path) // never returns a non-nil error
		}
		buf.WriteByte('\n') // never returns a non-nil error
	}
}

// ReadMapsDataInto is called by fsimpl/proc.mapsData.Generate to
// implement /proc/[pid]/maps.
func (mm *MemoryManager) ReadMapsDataInto(ctx context.Context, fn MapsCallbackFunc) {
	// FIXME(b/235153601): Need to replace RLockBypass with RLockBypass
	// after fixing b/235153601.
	mm.mappingMu.RLockBypass()
	defer mm.mappingMu.RUnlockBypass()
	var start hostarch.Addr

	for vseg := mm.vmas.LowerBoundSegment(start); vseg.Ok(); vseg = vseg.NextSegment() {
		mm.appendVMAMapsEntryLocked(ctx, vseg, fn)
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
	if start != vsyscallEnd {
		fn(hostarch.Addr(0xffffffffff600000), hostarch.Addr(0xffffffffff601000), hostarch.ReadExecute, "p", 0, 0, 0, 0, "[vsyscall]")
	}
}

// vmaMapsEntryLocked returns a /proc/[pid]/maps entry for the vma iterated by
// vseg, including the trailing newline.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) vmaMapsEntryLocked(ctx context.Context, vseg vmaIterator) []byte {
	var b bytes.Buffer
	mm.appendVMAMapsEntryLocked(ctx, vseg, mm.MapsCallbackFuncForBuffer(&b))
	return b.Bytes()
}

// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) appendVMAMapsEntryLocked(ctx context.Context, vseg vmaIterator, fn MapsCallbackFunc) {
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

	// Figure out our filename or hint.
	var path string
	if vma.hint != "" {
		path = vma.hint
	} else if vma.id != nil {
		// FIXME(jamieliu): We are holding mm.mappingMu here, which is
		// consistent with Linux's holding mmap_sem in
		// fs/proc/task_mmu.c:show_map_vma() => fs/seq_file.c:seq_file_path().
		// However, it's not clear that fs.File.MappedName() is actually
		// consistent with this lock order.
		path = vma.id.MappedName(ctx)
	}
	fn(vseg.Start(), vseg.End(), vma.realPerms, private, vma.off, devMajor, devMinor, ino, path)
}

// ReadSmapsDataInto is called by fsimpl/proc.smapsData.Generate to
// implement /proc/[pid]/maps.
func (mm *MemoryManager) ReadSmapsDataInto(ctx context.Context, buf *bytes.Buffer) {
	// FIXME(b/235153601): Need to replace RLockBypass with RLockBypass
	// after fixing b/235153601.
	mm.mappingMu.RLockBypass()
	defer mm.mappingMu.RUnlockBypass()
	var start hostarch.Addr

	for vseg := mm.vmas.LowerBoundSegment(start); vseg.Ok(); vseg = vseg.NextSegment() {
		mm.vmaSmapsEntryIntoLocked(ctx, vseg, buf)
	}

	// We always emulate vsyscall, so advertise it here. See
	// ReadMapsSeqFileData for additional commentary.
	if start != vsyscallEnd {
		buf.WriteString(vsyscallSmapsEntry)
	}
}

// vmaSmapsEntryLocked returns a /proc/[pid]/smaps entry for the vma iterated
// by vseg, including the trailing newline.
//
// Preconditions: mm.mappingMu must be locked.
func (mm *MemoryManager) vmaSmapsEntryLocked(ctx context.Context, vseg vmaIterator) []byte {
	var b bytes.Buffer
	mm.vmaSmapsEntryIntoLocked(ctx, vseg, &b)
	return b.Bytes()
}

func (mm *MemoryManager) vmaSmapsEntryIntoLocked(ctx context.Context, vseg vmaIterator, b *bytes.Buffer) {
	mm.appendVMAMapsEntryLocked(ctx, vseg, mm.MapsCallbackFuncForBuffer(b))
	vma := vseg.ValuePtr()

	// We take mm.activeMu here in each call to vmaSmapsEntryLocked, instead of
	// requiring it to be locked as a precondition, to reduce the latency
	// impact of reading /proc/[pid]/smaps on concurrent performance-sensitive
	// operations requiring activeMu for writing like faults.
	mm.activeMu.RLock()
	var rss uint64
	var anon uint64
	vsegAR := vseg.Range()
	for pseg := mm.pmas.LowerBoundSegment(vsegAR.Start); pseg.Ok() && pseg.Start() < vsegAR.End; pseg = pseg.NextSegment() {
		psegAR := pseg.Range().Intersect(vsegAR)
		size := uint64(psegAR.Length())
		rss += size
		if pseg.ValuePtr().private {
			anon += size
		}
	}
	mm.activeMu.RUnlock()

	fmt.Fprintf(b, "Size:           %8d kB\n", vseg.Range().Length()/1024)
	fmt.Fprintf(b, "Rss:            %8d kB\n", rss/1024)
	// Currently we report PSS = RSS, i.e. we pretend each page mapped by a pma
	// is only mapped by that pma. This avoids having to query memmap.Mappables
	// for reference count information on each page. As a corollary, all pages
	// are accounted as "private" whether or not the vma is private; compare
	// Linux's fs/proc/task_mmu.c:smaps_account().
	fmt.Fprintf(b, "Pss:            %8d kB\n", rss/1024)
	fmt.Fprintf(b, "Shared_Clean:   %8d kB\n", 0)
	fmt.Fprintf(b, "Shared_Dirty:   %8d kB\n", 0)
	// Pretend that all pages are dirty if the vma is writable, and clean otherwise.
	clean := rss
	if vma.effectivePerms.Write {
		clean = 0
	}
	fmt.Fprintf(b, "Private_Clean:  %8d kB\n", clean/1024)
	fmt.Fprintf(b, "Private_Dirty:  %8d kB\n", (rss-clean)/1024)
	// Pretend that all pages are "referenced" (recently touched).
	fmt.Fprintf(b, "Referenced:     %8d kB\n", rss/1024)
	fmt.Fprintf(b, "Anonymous:      %8d kB\n", anon/1024)
	// Hugepages (hugetlb and THP) are not implemented.
	fmt.Fprintf(b, "AnonHugePages:  %8d kB\n", 0)
	fmt.Fprintf(b, "Shared_Hugetlb: %8d kB\n", 0)
	fmt.Fprintf(b, "Private_Hugetlb: %7d kB\n", 0)
	// Swap is not implemented.
	fmt.Fprintf(b, "Swap:           %8d kB\n", 0)
	fmt.Fprintf(b, "SwapPss:        %8d kB\n", 0)
	fmt.Fprintf(b, "KernelPageSize: %8d kB\n", hostarch.PageSize/1024)
	fmt.Fprintf(b, "MMUPageSize:    %8d kB\n", hostarch.PageSize/1024)
	locked := rss
	if vma.mlockMode == memmap.MLockNone {
		locked = 0
	}
	fmt.Fprintf(b, "Locked:         %8d kB\n", locked/1024)

	b.WriteString("VmFlags: ")
	if vma.realPerms.Read {
		b.WriteString("rd ")
	}
	if vma.realPerms.Write {
		b.WriteString("wr ")
	}
	if vma.realPerms.Execute {
		b.WriteString("ex ")
	}
	if vma.canWriteMappableLocked() { // VM_SHARED
		b.WriteString("sh ")
	}
	if vma.maxPerms.Read {
		b.WriteString("mr ")
	}
	if vma.maxPerms.Write {
		b.WriteString("mw ")
	}
	if vma.maxPerms.Execute {
		b.WriteString("me ")
	}
	if !vma.private { // VM_MAYSHARE
		b.WriteString("ms ")
	}
	if vma.growsDown {
		b.WriteString("gd ")
	}
	if vma.mlockMode != memmap.MLockNone { // VM_LOCKED
		b.WriteString("lo ")
	}
	if vma.mlockMode == memmap.MLockLazy { // VM_LOCKONFAULT
		b.WriteString("?? ") // no explicit encoding in fs/proc/task_mmu.c:show_smap_vma_flags()
	}
	if vma.private && vma.effectivePerms.Write { // VM_ACCOUNT
		b.WriteString("ac ")
	}
	b.WriteString("\n")
}
