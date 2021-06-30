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

package loader

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// elfMagic identifies an ELF file.
	elfMagic = "\x7fELF"

	// maxTotalPhdrSize is the maximum combined size of all program
	// headers.  Linux limits this to one page.
	maxTotalPhdrSize = hostarch.PageSize
)

var (
	// header64Size is the size of elf.Header64.
	header64Size = (*linux.ElfHeader64)(nil).SizeBytes()

	// Prog64Size is the size of elf.Prog64.
	prog64Size = (*linux.ElfProg64)(nil).SizeBytes()
)

func progFlagsAsPerms(f elf.ProgFlag) hostarch.AccessType {
	var p hostarch.AccessType
	if f&elf.PF_R == elf.PF_R {
		p.Read = true
	}
	if f&elf.PF_W == elf.PF_W {
		p.Write = true
	}
	if f&elf.PF_X == elf.PF_X {
		p.Execute = true
	}
	return p
}

// elfInfo contains the metadata needed to load an ELF binary.
type elfInfo struct {
	// os is the target OS of the ELF.
	os abi.OS

	// arch is the target architecture of the ELF.
	arch arch.Arch

	// entry is the program entry point.
	entry hostarch.Addr

	// phdrs are the program headers.
	phdrs []elf.ProgHeader

	// phdrSize is the size of a single program header in the ELF.
	phdrSize int

	// phdrOff is the offset of the program headers in the file.
	phdrOff uint64

	// sharedObject is true if the ELF represents a shared object.
	sharedObject bool
}

// fullReader interface extracts the ReadFull method from fsbridge.File so that
// client code does not need to define an entire fsbridge.File when only read
// functionality is needed.
//
// TODO(gvisor.dev/issue/1035): Once VFS2 ships, rewrite this to wrap
// vfs.FileDescription's PRead/Read instead.
type fullReader interface {
	// ReadFull is the same as fsbridge.File.ReadFull.
	ReadFull(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error)
}

// parseHeader parse the ELF header, verifying that this is a supported ELF
// file and returning the ELF program headers.
//
// This is similar to elf.NewFile, except that it is more strict about what it
// accepts from the ELF, and it doesn't parse unnecessary parts of the file.
func parseHeader(ctx context.Context, f fullReader) (elfInfo, error) {
	// Check ident first; it will tell us the endianness of the rest of the
	// structs.
	var ident [elf.EI_NIDENT]byte
	_, err := f.ReadFull(ctx, usermem.BytesIOSequence(ident[:]), 0)
	if err != nil {
		log.Infof("Error reading ELF ident: %v", err)
		// The entire ident array always exists.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}

	// Only some callers pre-check the ELF magic.
	if !bytes.Equal(ident[:len(elfMagic)], []byte(elfMagic)) {
		log.Infof("File is not an ELF")
		return elfInfo{}, syserror.ENOEXEC
	}

	// We only support 64-bit, little endian binaries
	if class := elf.Class(ident[elf.EI_CLASS]); class != elf.ELFCLASS64 {
		log.Infof("Unsupported ELF class: %v", class)
		return elfInfo{}, syserror.ENOEXEC
	}
	if endian := elf.Data(ident[elf.EI_DATA]); endian != elf.ELFDATA2LSB {
		log.Infof("Unsupported ELF endianness: %v", endian)
		return elfInfo{}, syserror.ENOEXEC
	}

	if version := elf.Version(ident[elf.EI_VERSION]); version != elf.EV_CURRENT {
		log.Infof("Unsupported ELF version: %v", version)
		return elfInfo{}, syserror.ENOEXEC
	}
	// EI_OSABI is ignored by Linux, which is the only OS supported.
	os := abi.Linux

	var hdr linux.ElfHeader64
	hdrBuf := make([]byte, header64Size)
	_, err = f.ReadFull(ctx, usermem.BytesIOSequence(hdrBuf), 0)
	if err != nil {
		log.Infof("Error reading ELF header: %v", err)
		// The entire header always exists.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}
	hdr.UnmarshalUnsafe(hdrBuf)

	// We support amd64 and arm64.
	var a arch.Arch
	switch machine := elf.Machine(hdr.Machine); machine {
	case elf.EM_X86_64:
		a = arch.AMD64
	case elf.EM_AARCH64:
		a = arch.ARM64
	default:
		log.Infof("Unsupported ELF machine %d", machine)
		return elfInfo{}, syserror.ENOEXEC
	}

	var sharedObject bool
	elfType := elf.Type(hdr.Type)
	switch elfType {
	case elf.ET_EXEC:
		sharedObject = false
	case elf.ET_DYN:
		sharedObject = true
	default:
		log.Infof("Unsupported ELF type %v", elfType)
		return elfInfo{}, syserror.ENOEXEC
	}

	if int(hdr.Phentsize) != prog64Size {
		log.Infof("Unsupported phdr size %d", hdr.Phentsize)
		return elfInfo{}, syserror.ENOEXEC
	}
	totalPhdrSize := prog64Size * int(hdr.Phnum)
	if totalPhdrSize < prog64Size {
		log.Warningf("No phdrs or total phdr size overflows: prog64Size: %d phnum: %d", prog64Size, int(hdr.Phnum))
		return elfInfo{}, syserror.ENOEXEC
	}
	if totalPhdrSize > maxTotalPhdrSize {
		log.Infof("Too many phdrs (%d): total size %d > %d", hdr.Phnum, totalPhdrSize, maxTotalPhdrSize)
		return elfInfo{}, syserror.ENOEXEC
	}
	if int64(hdr.Phoff) < 0 || int64(hdr.Phoff+uint64(totalPhdrSize)) < 0 {
		ctx.Infof("Unsupported phdr offset %d", hdr.Phoff)
		return elfInfo{}, syserror.ENOEXEC
	}

	phdrBuf := make([]byte, totalPhdrSize)
	_, err = f.ReadFull(ctx, usermem.BytesIOSequence(phdrBuf), int64(hdr.Phoff))
	if err != nil {
		log.Infof("Error reading ELF phdrs: %v", err)
		// If phdrs were specified, they should all exist.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = syserror.ENOEXEC
		}
		return elfInfo{}, err
	}

	phdrs := make([]elf.ProgHeader, hdr.Phnum)
	for i := range phdrs {
		var prog64 linux.ElfProg64
		prog64.UnmarshalUnsafe(phdrBuf[:prog64Size])
		phdrBuf = phdrBuf[prog64Size:]
		phdrs[i] = elf.ProgHeader{
			Type:   elf.ProgType(prog64.Type),
			Flags:  elf.ProgFlag(prog64.Flags),
			Off:    prog64.Off,
			Vaddr:  prog64.Vaddr,
			Paddr:  prog64.Paddr,
			Filesz: prog64.Filesz,
			Memsz:  prog64.Memsz,
			Align:  prog64.Align,
		}
	}

	return elfInfo{
		os:           os,
		arch:         a,
		entry:        hostarch.Addr(hdr.Entry),
		phdrs:        phdrs,
		phdrOff:      hdr.Phoff,
		phdrSize:     prog64Size,
		sharedObject: sharedObject,
	}, nil
}

// mapSegment maps a phdr into the Task. offset is the offset to apply to
// phdr.Vaddr.
func mapSegment(ctx context.Context, m *mm.MemoryManager, f fsbridge.File, phdr *elf.ProgHeader, offset hostarch.Addr) error {
	// We must make a page-aligned mapping.
	adjust := hostarch.Addr(phdr.Vaddr).PageOffset()

	addr, ok := offset.AddLength(phdr.Vaddr)
	if !ok {
		// If offset != 0 we should have ensured this would fit.
		ctx.Warningf("Computed segment load address overflows: %#x + %#x", phdr.Vaddr, offset)
		return syserror.ENOEXEC
	}
	addr -= hostarch.Addr(adjust)

	fileSize := phdr.Filesz + adjust
	if fileSize < phdr.Filesz {
		ctx.Infof("Computed segment file size overflows: %#x + %#x", phdr.Filesz, adjust)
		return syserror.ENOEXEC
	}
	ms, ok := hostarch.Addr(fileSize).RoundUp()
	if !ok {
		ctx.Infof("fileSize %#x too large", fileSize)
		return syserror.ENOEXEC
	}
	mapSize := uint64(ms)

	if mapSize > 0 {
		// This must result in a page-aligned offset. i.e., the original
		// phdr.Off must have the same alignment as phdr.Vaddr. If that is not
		// true, MMap will reject the mapping.
		fileOffset := phdr.Off - adjust

		prot := progFlagsAsPerms(phdr.Flags)
		mopts := memmap.MMapOpts{
			Length: mapSize,
			Offset: fileOffset,
			Addr:   addr,
			Fixed:  true,
			// Linux will happily allow conflicting segments to map over
			// one another.
			Unmap:    true,
			Private:  true,
			Perms:    prot,
			MaxPerms: hostarch.AnyAccess,
		}
		defer func() {
			if mopts.MappingIdentity != nil {
				mopts.MappingIdentity.DecRef(ctx)
			}
		}()
		if err := f.ConfigureMMap(ctx, &mopts); err != nil {
			ctx.Infof("File is not memory-mappable: %v", err)
			return err
		}
		if _, err := m.MMap(ctx, mopts); err != nil {
			ctx.Infof("Error mapping PT_LOAD segment %+v at %#x: %v", phdr, addr, err)
			return err
		}

		// We need to clear the end of the last page that exceeds fileSize so
		// we don't map part of the file beyond fileSize.
		//
		// Note that Linux *does not* clear the portion of the first page
		// before phdr.Off.
		if mapSize > fileSize {
			zeroAddr, ok := addr.AddLength(fileSize)
			if !ok {
				panic(fmt.Sprintf("successfully mmaped address overflows? %#x + %#x", addr, fileSize))
			}
			zeroSize := int64(mapSize - fileSize)
			if zeroSize < 0 {
				panic(fmt.Sprintf("zeroSize too big? %#x", uint64(zeroSize)))
			}
			if _, err := m.ZeroOut(ctx, zeroAddr, zeroSize, usermem.IOOpts{IgnorePermissions: true}); err != nil {
				ctx.Warningf("Failed to zero end of page [%#x, %#x): %v", zeroAddr, zeroAddr+hostarch.Addr(zeroSize), err)
				return err
			}
		}
	}

	memSize := phdr.Memsz + adjust
	if memSize < phdr.Memsz {
		ctx.Infof("Computed segment mem size overflows: %#x + %#x", phdr.Memsz, adjust)
		return syserror.ENOEXEC
	}

	// Allocate more anonymous pages if necessary.
	if mapSize < memSize {
		anonAddr, ok := addr.AddLength(mapSize)
		if !ok {
			panic(fmt.Sprintf("anonymous memory doesn't fit in pre-sized range? %#x + %#x", addr, mapSize))
		}
		anonSize, ok := hostarch.Addr(memSize - mapSize).RoundUp()
		if !ok {
			ctx.Infof("extra anon pages too large: %#x", memSize-mapSize)
			return syserror.ENOEXEC
		}

		// N.B. Linux uses vm_brk_flags to map these pages, which only
		// honors the X bit, always mapping at least RW. ignoring These
		// pages are not included in the final brk region.
		prot := hostarch.ReadWrite
		if phdr.Flags&elf.PF_X == elf.PF_X {
			prot.Execute = true
		}

		if _, err := m.MMap(ctx, memmap.MMapOpts{
			Length: uint64(anonSize),
			Addr:   anonAddr,
			// Fixed without Unmap will fail the mmap if something is
			// already at addr.
			Fixed:    true,
			Private:  true,
			Perms:    prot,
			MaxPerms: hostarch.AnyAccess,
		}); err != nil {
			ctx.Infof("Error mapping PT_LOAD segment %v anonymous memory: %v", phdr, err)
			return err
		}
	}

	return nil
}

// loadedELF describes an ELF that has been successfully loaded.
type loadedELF struct {
	// os is the target OS of the ELF.
	os abi.OS

	// arch is the target architecture of the ELF.
	arch arch.Arch

	// entry is the entry point of the ELF.
	entry hostarch.Addr

	// start is the end of the ELF.
	start hostarch.Addr

	// end is the end of the ELF.
	end hostarch.Addr

	// interpter is the path to the ELF interpreter.
	interpreter string

	// phdrAddr is the address of the ELF program headers.
	phdrAddr hostarch.Addr

	// phdrSize is the size of a single program header in the ELF.
	phdrSize int

	// phdrNum is the number of program headers.
	phdrNum int

	// auxv contains a subset of ELF-specific auxiliary vector entries:
	// * AT_PHDR
	// * AT_PHENT
	// * AT_PHNUM
	// * AT_BASE
	// * AT_ENTRY
	auxv arch.Auxv
}

// loadParsedELF loads f into mm.
//
// info is the parsed elfInfo from the header.
//
// It does not load the ELF interpreter, or return any auxv entries.
//
// Preconditions: f is an ELF file.
func loadParsedELF(ctx context.Context, m *mm.MemoryManager, f fsbridge.File, info elfInfo, sharedLoadOffset hostarch.Addr) (loadedELF, error) {
	first := true
	var start, end hostarch.Addr
	var interpreter string
	for _, phdr := range info.phdrs {
		switch phdr.Type {
		case elf.PT_LOAD:
			vaddr := hostarch.Addr(phdr.Vaddr)
			if first {
				first = false
				start = vaddr
			}
			if vaddr < end {
				// NOTE(b/37474556): Linux allows out-of-order
				// segments, in violation of the spec.
				ctx.Infof("PT_LOAD headers out-of-order. %#x < %#x", vaddr, end)
				return loadedELF{}, syserror.ENOEXEC
			}
			var ok bool
			end, ok = vaddr.AddLength(phdr.Memsz)
			if !ok {
				ctx.Infof("PT_LOAD header size overflows. %#x + %#x", vaddr, phdr.Memsz)
				return loadedELF{}, syserror.ENOEXEC
			}

		case elf.PT_INTERP:
			if phdr.Filesz < 2 {
				ctx.Infof("PT_INTERP path too small: %v", phdr.Filesz)
				return loadedELF{}, syserror.ENOEXEC
			}
			if phdr.Filesz > linux.PATH_MAX {
				ctx.Infof("PT_INTERP path too big: %v", phdr.Filesz)
				return loadedELF{}, syserror.ENOEXEC
			}
			if int64(phdr.Off) < 0 || int64(phdr.Off+phdr.Filesz) < 0 {
				ctx.Infof("Unsupported PT_INTERP offset %d", phdr.Off)
				return loadedELF{}, syserror.ENOEXEC
			}

			path := make([]byte, phdr.Filesz)
			_, err := f.ReadFull(ctx, usermem.BytesIOSequence(path), int64(phdr.Off))
			if err != nil {
				// If an interpreter was specified, it should exist.
				ctx.Infof("Error reading PT_INTERP path: %v", err)
				return loadedELF{}, syserror.ENOEXEC
			}

			if path[len(path)-1] != 0 {
				ctx.Infof("PT_INTERP path not NUL-terminated: %v", path)
				return loadedELF{}, syserror.ENOEXEC
			}

			// Strip NUL-terminator and everything beyond from
			// string. Note that there may be a NUL-terminator
			// before len(path)-1.
			interpreter = string(path[:bytes.IndexByte(path, '\x00')])
			if interpreter == "" {
				// Linux actually attempts to open_exec("\0").
				// open_exec -> do_open_execat fails to check
				// that name != '\0' before calling
				// do_filp_open, which thus opens the working
				// directory.  do_open_execat returns EACCES
				// because the directory is not a regular file.
				//
				// We bypass that nonsense and simply
				// short-circuit with EACCES. Those this does
				// mean that there may be some edge cases where
				// the open path would return a different
				// error.
				ctx.Infof("PT_INTERP path is empty: %v", path)
				return loadedELF{}, linuxerr.EACCES
			}
		}
	}

	// Shared objects don't have fixed load addresses. We need to pick a
	// base address big enough to fit all segments, so we first create a
	// mapping for the total size just to find a region that is big enough.
	//
	// It is safe to unmap it immediately without racing with another mapping
	// because we are the only one in control of the MemoryManager.
	//
	// Note that the vaddr of the first PT_LOAD segment is ignored when
	// choosing the load address (even if it is non-zero). The vaddr does
	// become an offset from that load address.
	var offset hostarch.Addr
	if info.sharedObject {
		totalSize := end - start
		totalSize, ok := totalSize.RoundUp()
		if !ok {
			ctx.Infof("ELF PT_LOAD segments too big")
			return loadedELF{}, syserror.ENOEXEC
		}

		var err error
		offset, err = m.MMap(ctx, memmap.MMapOpts{
			Length:  uint64(totalSize),
			Addr:    sharedLoadOffset,
			Private: true,
		})
		if err != nil {
			ctx.Infof("Error allocating address space for shared object: %v", err)
			return loadedELF{}, err
		}
		if err := m.MUnmap(ctx, offset, uint64(totalSize)); err != nil {
			panic(fmt.Sprintf("Failed to unmap base address: %v", err))
		}

		start, ok = start.AddLength(uint64(offset))
		if !ok {
			ctx.Infof(fmt.Sprintf("Start %#x + offset %#x overflows?", start, offset))
			return loadedELF{}, linuxerr.EINVAL
		}

		end, ok = end.AddLength(uint64(offset))
		if !ok {
			ctx.Infof(fmt.Sprintf("End %#x + offset %#x overflows?", end, offset))
			return loadedELF{}, linuxerr.EINVAL
		}

		info.entry, ok = info.entry.AddLength(uint64(offset))
		if !ok {
			ctx.Infof("Entrypoint %#x + offset %#x overflows? Is the entrypoint within a segment?", info.entry, offset)
			return loadedELF{}, err
		}
	}

	// Map PT_LOAD segments.
	for _, phdr := range info.phdrs {
		switch phdr.Type {
		case elf.PT_LOAD:
			if phdr.Memsz == 0 {
				// No need to load segments with size 0, but
				// they exist in some binaries.
				continue
			}

			if err := mapSegment(ctx, m, f, &phdr, offset); err != nil {
				ctx.Infof("Failed to map PT_LOAD segment: %+v", phdr)
				return loadedELF{}, err
			}
		}
	}

	// This assumes that the first segment contains the ELF headers. This
	// may not be true in a malformed ELF, but Linux makes the same
	// assumption.
	phdrAddr, ok := start.AddLength(info.phdrOff)
	if !ok {
		ctx.Warningf("ELF start address %#x + phdr offset %#x overflows", start, info.phdrOff)
		phdrAddr = 0
	}

	return loadedELF{
		os:          info.os,
		arch:        info.arch,
		entry:       info.entry,
		start:       start,
		end:         end,
		interpreter: interpreter,
		phdrAddr:    phdrAddr,
		phdrSize:    info.phdrSize,
		phdrNum:     len(info.phdrs),
	}, nil
}

// loadInitialELF loads f into mm.
//
// It creates an arch.Context for the ELF and prepares the mm for this arch.
//
// It does not load the ELF interpreter, or return any auxv entries.
//
// Preconditions:
// * f is an ELF file.
// * f is the first ELF loaded into m.
func loadInitialELF(ctx context.Context, m *mm.MemoryManager, fs *cpuid.FeatureSet, f fsbridge.File) (loadedELF, arch.Context, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		ctx.Infof("Failed to parse initial ELF: %v", err)
		return loadedELF{}, nil, err
	}

	// Check Image Compatibility.
	if arch.Host != info.arch {
		ctx.Warningf("Found mismatch for platform %s with ELF type %s", arch.Host.String(), info.arch.String())
		return loadedELF{}, nil, syserror.ENOEXEC
	}

	// Create the arch.Context now so we can prepare the mmap layout before
	// mapping anything.
	ac := arch.New(info.arch, fs)

	l, err := m.SetMmapLayout(ac, limits.FromContext(ctx))
	if err != nil {
		ctx.Warningf("Failed to set mmap layout: %v", err)
		return loadedELF{}, nil, err
	}

	// PIELoadAddress tries to move the ELF out of the way of the default
	// mmap base to ensure that the initial brk has sufficient space to
	// grow.
	le, err := loadParsedELF(ctx, m, f, info, ac.PIELoadAddress(l))
	return le, ac, err
}

// loadInterpreterELF loads f into mm.
//
// The interpreter must be for the same OS/Arch as the initial ELF.
//
// It does not return any auxv entries.
//
// Preconditions: f is an ELF file.
func loadInterpreterELF(ctx context.Context, m *mm.MemoryManager, f fsbridge.File, initial loadedELF) (loadedELF, error) {
	info, err := parseHeader(ctx, f)
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOEXEC, err) {
			// Bad interpreter.
			err = syserror.ELIBBAD
		}
		return loadedELF{}, err
	}

	if info.os != initial.os {
		ctx.Infof("Initial ELF OS %v and interpreter ELF OS %v differ", initial.os, info.os)
		return loadedELF{}, syserror.ELIBBAD
	}
	if info.arch != initial.arch {
		ctx.Infof("Initial ELF arch %v and interpreter ELF arch %v differ", initial.arch, info.arch)
		return loadedELF{}, syserror.ELIBBAD
	}

	// The interpreter is not given a load offset, as its location does not
	// affect brk.
	return loadParsedELF(ctx, m, f, info, 0)
}

// loadELF loads args.File into the Task address space.
//
// If loadELF returns ErrSwitchFile it should be called again with the returned
// path and argv.
//
// Preconditions: args.File is an ELF file.
func loadELF(ctx context.Context, args LoadArgs) (loadedELF, arch.Context, error) {
	bin, ac, err := loadInitialELF(ctx, args.MemoryManager, args.Features, args.File)
	if err != nil {
		ctx.Infof("Error loading binary: %v", err)
		return loadedELF{}, nil, err
	}

	var interp loadedELF
	if bin.interpreter != "" {
		// Even if we do not allow the final link of the script to be
		// resolved, the interpreter should still be resolved if it is
		// a symlink.
		args.ResolveFinal = true
		// Refresh the traversal limit.
		*args.RemainingTraversals = linux.MaxSymlinkTraversals
		args.Filename = bin.interpreter
		intFile, err := openPath(ctx, args)
		if err != nil {
			ctx.Infof("Error opening interpreter %s: %v", bin.interpreter, err)
			return loadedELF{}, nil, err
		}
		defer intFile.DecRef(ctx)

		interp, err = loadInterpreterELF(ctx, args.MemoryManager, intFile, bin)
		if err != nil {
			ctx.Infof("Error loading interpreter: %v", err)
			return loadedELF{}, nil, err
		}

		if interp.interpreter != "" {
			// No recursive interpreters!
			ctx.Infof("Interpreter requires an interpreter")
			return loadedELF{}, nil, syserror.ENOEXEC
		}
	}

	// ELF-specific auxv entries.
	bin.auxv = arch.Auxv{
		arch.AuxEntry{linux.AT_PHDR, bin.phdrAddr},
		arch.AuxEntry{linux.AT_PHENT, hostarch.Addr(bin.phdrSize)},
		arch.AuxEntry{linux.AT_PHNUM, hostarch.Addr(bin.phdrNum)},
		arch.AuxEntry{linux.AT_ENTRY, bin.entry},
	}
	if bin.interpreter != "" {
		bin.auxv = append(bin.auxv, arch.AuxEntry{linux.AT_BASE, interp.start})

		// Start in the interpreter.
		// N.B. AT_ENTRY above contains the *original* entry point.
		bin.entry = interp.entry
	} else {
		// Always add AT_BASE even if there is no interpreter.
		bin.auxv = append(bin.auxv, arch.AuxEntry{linux.AT_BASE, 0})
	}

	return bin, ac, nil
}
