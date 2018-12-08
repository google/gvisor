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

package loader

import (
	"debug/elf"
	"fmt"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/anon"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/mm"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// byteReaderFileOperations implements fs.FileOperations for reading
// from a []byte source.
type byteReader struct {
	fsutil.NoopRelease
	fsutil.PipeSeek
	fsutil.NotDirReaddir
	fsutil.NoFsync
	fsutil.NoopFlush
	fsutil.NoMMap
	fsutil.NoIoctl
	fsutil.NoSplice
	waiter.AlwaysReady
	data []byte
}

type fileContext struct {
	context.Context
}

func (f *fileContext) Value(key interface{}) interface{} {
	switch key {
	case uniqueid.CtxGlobalUniqueID:
		return uint64(0)
	default:
		return f.Context.Value(key)
	}
}

// newByteReaderFile creates a fake file to read data from.
func newByteReaderFile(data []byte) *fs.File {
	// Create a fake inode.
	inode := fs.NewInode(fsutil.NewSimpleInodeOperations(fsutil.InodeSimpleAttributes{
		FSType: linux.ANON_INODE_FS_MAGIC,
	}), fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{}), fs.StableAttr{
		Type:      fs.Anonymous,
		DeviceID:  anon.PseudoDevice.DeviceID(),
		InodeID:   anon.PseudoDevice.NextIno(),
		BlockSize: usermem.PageSize,
	})

	// Use the fake inode to create a fake dirent.
	dirent := fs.NewTransientDirent(inode)
	defer dirent.DecRef()

	// Use the fake dirent to make a fake file.
	flags := fs.FileFlags{Read: true, Pread: true}
	return fs.NewFile(&fileContext{Context: context.Background()}, dirent, flags, &byteReader{
		data: data,
	})
}

func (b *byteReader) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	if offset >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n, err := dst.CopyOut(ctx, b.data[offset:])
	return int64(n), err
}

func (b *byteReader) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	panic("Write not supported")
}

// validateVDSO checks that the VDSO can be loaded by loadVDSO.
//
// VDSOs are special (see below). Since we are going to map the VDSO directly
// rather than using a normal loading process, we require that the PT_LOAD
// segments have the same layout in the ELF as they expect to have in memory.
//
// Namely, this means that we must verify:
// * PT_LOAD file offsets are equivalent to the memory offset from the first
//   segment.
// * No extra zeroed space (memsz) is required.
// * PT_LOAD segments are in order.
// * No two PT_LOAD segments occupy parts of the same page.
// * PT_LOAD segments don't extend beyond the end of the file.
//
// ctx may be nil if f does not need it.
func validateVDSO(ctx context.Context, f *fs.File, size uint64) (elfInfo, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		log.Infof("Unable to parse VDSO header: %v", err)
		return elfInfo{}, err
	}

	var first *elf.ProgHeader
	var prev *elf.ProgHeader
	var prevEnd usermem.Addr
	for i, phdr := range info.phdrs {
		if phdr.Type != elf.PT_LOAD {
			continue
		}

		if first == nil {
			first = &info.phdrs[i]
			if phdr.Off != 0 {
				log.Warningf("First PT_LOAD segment has non-zero file offset")
				return elfInfo{}, syserror.ENOEXEC
			}
		}

		memoryOffset := phdr.Vaddr - first.Vaddr
		if memoryOffset != phdr.Off {
			log.Warningf("PT_LOAD segment memory offset %#x != file offset %#x", memoryOffset, phdr.Off)
			return elfInfo{}, syserror.ENOEXEC
		}

		// memsz larger than filesz means that extra zeroed space should be
		// provided at the end of the segment. Since we are mapping the ELF
		// directly, we don't want to just overwrite part of the ELF with
		// zeroes.
		if phdr.Memsz != phdr.Filesz {
			log.Warningf("PT_LOAD segment memsz %#x != filesz %#x", phdr.Memsz, phdr.Filesz)
			return elfInfo{}, syserror.ENOEXEC
		}

		start := usermem.Addr(memoryOffset)
		end, ok := start.AddLength(phdr.Memsz)
		if !ok {
			log.Warningf("PT_LOAD segment size overflows: %#x + %#x", start, end)
			return elfInfo{}, syserror.ENOEXEC
		}
		if uint64(end) > size {
			log.Warningf("PT_LOAD segment end %#x extends beyond end of file %#x", end, size)
			return elfInfo{}, syserror.ENOEXEC
		}

		if prev != nil {
			if start < prevEnd {
				log.Warningf("PT_LOAD segments out of order")
				return elfInfo{}, syserror.ENOEXEC
			}

			// We mprotect entire pages, so each segment must be in
			// its own page.
			prevEndPage := prevEnd.RoundDown()
			startPage := start.RoundDown()
			if prevEndPage >= startPage {
				log.Warningf("PT_LOAD segments share a page: %#x", prevEndPage)
				return elfInfo{}, syserror.ENOEXEC
			}
		}
		prev = &info.phdrs[i]
		prevEnd = end
	}

	return info, nil
}

// VDSO describes a VDSO.
//
// NOTE: to support multiple architectures or operating systems, this
// would need to contain a VDSO for each.
//
// +stateify savable
type VDSO struct {
	// ParamPage is the VDSO parameter page. This page should be updated to
	// inform the VDSO for timekeeping data.
	ParamPage *mm.SpecialMappable

	// vdso is the VDSO ELF itself.
	vdso *mm.SpecialMappable

	// os is the operating system targeted by the VDSO.
	os abi.OS

	// arch is the architecture targeted by the VDSO.
	arch arch.Arch

	// phdrs are the VDSO ELF phdrs.
	phdrs []elf.ProgHeader `state:".([]elfProgHeader)"`
}

// PrepareVDSO validates the system VDSO and returns a VDSO, containing the
// param page for updating by the kernel.
func PrepareVDSO(p platform.Platform) (*VDSO, error) {
	vdsoFile := newByteReaderFile(vdsoBin)

	// First make sure the VDSO is valid. vdsoFile does not use ctx, so a
	// nil context can be passed.
	info, err := validateVDSO(nil, vdsoFile, uint64(len(vdsoBin)))
	vdsoFile.DecRef()
	if err != nil {
		return nil, err
	}

	// Then copy it into a VDSO mapping.
	size, ok := usermem.Addr(len(vdsoBin)).RoundUp()
	if !ok {
		return nil, fmt.Errorf("VDSO size overflows? %#x", len(vdsoBin))
	}

	vdso, err := p.Memory().Allocate(uint64(size), usage.System)
	if err != nil {
		return nil, fmt.Errorf("unable to allocate VDSO memory: %v", err)
	}

	ims, err := p.Memory().MapInternal(vdso, usermem.ReadWrite)
	if err != nil {
		p.Memory().DecRef(vdso)
		return nil, fmt.Errorf("unable to map VDSO memory: %v", err)
	}

	_, err = safemem.CopySeq(ims, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(vdsoBin)))
	if err != nil {
		p.Memory().DecRef(vdso)
		return nil, fmt.Errorf("unable to copy VDSO into memory: %v", err)
	}

	// Finally, allocate a param page for this VDSO.
	paramPage, err := p.Memory().Allocate(usermem.PageSize, usage.System)
	if err != nil {
		p.Memory().DecRef(vdso)
		return nil, fmt.Errorf("unable to allocate VDSO param page: %v", err)
	}

	return &VDSO{
		ParamPage: mm.NewSpecialMappable("[vvar]", p, paramPage),
		// TODO: Don't advertise the VDSO, as some applications may
		// not be able to handle multiple [vdso] hints.
		vdso:  mm.NewSpecialMappable("", p, vdso),
		phdrs: info.phdrs,
	}, nil
}

// loadVDSO loads the VDSO into m.
//
// VDSOs are special.
//
// VDSOs are fully position independent. However, instead of loading a VDSO
// like a normal ELF binary, mapping only the PT_LOAD segments, the Linux
// kernel simply directly maps the entire file into process memory, with very
// little real ELF parsing.
//
// NOTE: This means that userspace can, and unfortunately does,
// depend on parts of the ELF that would normally not be mapped.  To maintain
// compatibility with such binaries, we load the VDSO much like Linux.
//
// loadVDSO takes a reference on the VDSO and parameter page FrameRegions.
func loadVDSO(ctx context.Context, m *mm.MemoryManager, v *VDSO, bin loadedELF) (usermem.Addr, error) {
	if v.os != bin.os {
		ctx.Warningf("Binary ELF OS %v and VDSO ELF OS %v differ", bin.os, v.os)
		return 0, syserror.ENOEXEC
	}
	if v.arch != bin.arch {
		ctx.Warningf("Binary ELF arch %v and VDSO ELF arch %v differ", bin.arch, v.arch)
		return 0, syserror.ENOEXEC
	}

	// Reserve address space for the VDSO and its parameter page, which is
	// mapped just before the VDSO.
	mapSize := v.vdso.Length() + v.ParamPage.Length()
	addr, err := m.MMap(ctx, memmap.MMapOpts{
		Length:  mapSize,
		Private: true,
	})
	if err != nil {
		ctx.Infof("Unable to reserve VDSO address space: %v", err)
		return 0, err
	}

	// Now map the param page.
	_, err = m.MMap(ctx, memmap.MMapOpts{
		Length:          v.ParamPage.Length(),
		MappingIdentity: v.ParamPage,
		Mappable:        v.ParamPage,
		Addr:            addr,
		Fixed:           true,
		Unmap:           true,
		Private:         true,
		Perms:           usermem.Read,
		MaxPerms:        usermem.Read,
	})
	if err != nil {
		ctx.Infof("Unable to map VDSO param page: %v", err)
		return 0, err
	}

	// Now map the VDSO itself.
	vdsoAddr, ok := addr.AddLength(v.ParamPage.Length())
	if !ok {
		panic(fmt.Sprintf("Part of mapped range overflows? %#x + %#x", addr, v.ParamPage.Length()))
	}
	_, err = m.MMap(ctx, memmap.MMapOpts{
		Length:          v.vdso.Length(),
		MappingIdentity: v.vdso,
		Mappable:        v.vdso,
		Addr:            vdsoAddr,
		Fixed:           true,
		Unmap:           true,
		Private:         true,
		Perms:           usermem.Read,
		MaxPerms:        usermem.AnyAccess,
	})
	if err != nil {
		ctx.Infof("Unable to map VDSO: %v", err)
		return 0, err
	}

	vdsoEnd, ok := vdsoAddr.AddLength(v.vdso.Length())
	if !ok {
		panic(fmt.Sprintf("VDSO mapping overflows? %#x + %#x", vdsoAddr, v.vdso.Length()))
	}

	// Set additional protections for the individual segments.
	var first *elf.ProgHeader
	for i, phdr := range v.phdrs {
		if phdr.Type != elf.PT_LOAD {
			continue
		}

		if first == nil {
			first = &v.phdrs[i]
		}

		memoryOffset := phdr.Vaddr - first.Vaddr
		segAddr, ok := vdsoAddr.AddLength(memoryOffset)
		if !ok {
			ctx.Warningf("PT_LOAD segment address overflows: %#x + %#x", segAddr, memoryOffset)
			return 0, syserror.ENOEXEC
		}
		segPage := segAddr.RoundDown()
		segSize := usermem.Addr(phdr.Memsz)
		segSize, ok = segSize.AddLength(segAddr.PageOffset())
		if !ok {
			ctx.Warningf("PT_LOAD segment memsize %#x + offset %#x overflows", phdr.Memsz, segAddr.PageOffset())
			return 0, syserror.ENOEXEC
		}
		segSize, ok = segSize.RoundUp()
		if !ok {
			ctx.Warningf("PT_LOAD segment size overflows: %#x", phdr.Memsz+segAddr.PageOffset())
			return 0, syserror.ENOEXEC
		}
		segEnd, ok := segPage.AddLength(uint64(segSize))
		if !ok {
			ctx.Warningf("PT_LOAD segment range overflows: %#x + %#x", segAddr, segSize)
			return 0, syserror.ENOEXEC
		}
		if segEnd > vdsoEnd {
			ctx.Warningf("PT_LOAD segment ends beyond VDSO: %#x > %#x", segEnd, vdsoEnd)
			return 0, syserror.ENOEXEC
		}

		perms := progFlagsAsPerms(phdr.Flags)
		if perms != usermem.Read {
			if err := m.MProtect(segPage, uint64(segSize), perms, false); err != nil {
				ctx.Warningf("Unable to set PT_LOAD segment protections %+v at [%#x, %#x): %v", perms, segAddr, segEnd, err)
				return 0, syserror.ENOEXEC
			}
		}
	}

	return vdsoAddr, nil
}
