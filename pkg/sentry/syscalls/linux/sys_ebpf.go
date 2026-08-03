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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/ebpf"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ebpffd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// cgroupBPFAttachCheckAncestors checks that the attachment is not blocked by eBPF flags in parent cgroups.
//
// It is analogous to kernel/bpf/cgroup.c:hierarchy_allows_attach() in Linux.
func cgroupBPFAttachCheckAncestors(ancestors []*kernel.Cgroup2BPF, attachType ebpf.CgroupAttachType) error {
	for _, a := range ancestors {
		var flags uint8
		var numProgs int
		if a != nil {
			flags = a.Slots[attachType].Flags
			numProgs = len(a.Slots[attachType].Progs)
		}

		// Parent must either allow multi...
		if (flags & linux.BPF_F_ALLOW_MULTI) == linux.BPF_F_ALLOW_MULTI {
			return nil
		}
		// or, for the first parent we see with a program, it must allow override.
		if numProgs > 0 {
			if (flags & linux.BPF_F_ALLOW_OVERRIDE) == linux.BPF_F_ALLOW_OVERRIDE {
				return nil
			}
			return linuxerr.EPERM
		}
	}

	return nil
}

func bpfProgLoad(t *kernel.Task, attr *linux.BPFAttrProgLoad) (uintptr, error) {
	hasBpf := t.Credentials().HasRootCapability(linux.CAP_BPF)
	hasSysAdmin := t.Credentials().HasRootCapability(linux.CAP_SYS_ADMIN)
	hasNetAdmin := t.Credentials().HasRootCapability(linux.CAP_NET_ADMIN)

	// BPF_PROG_LOAD requires either CAP_BPF or CAP_SYS_ADMIN
	if !hasBpf && !hasSysAdmin {
		return 0, linuxerr.EPERM
	}

	progType := linux.BPFProgramType(attr.ProgType)

	// Extra per-program-type capability checks
	switch progType {
	case linux.BPF_PROG_TYPE_CGROUP_DEVICE:
		if !hasSysAdmin && !hasNetAdmin {
			return 0, linuxerr.EPERM
		}
	default:
		// Unsupported program type
		return 0, linuxerr.EINVAL
	}

	if attr.ProgFlags != 0 {
		// No program flags are supported
		return 0, linuxerr.EINVAL
	}

	if attr.AttachBTFID != 0 || attr.AttachFD != 0 {
		// AttachBTFID and AttachFD are not supported
		return 0, linuxerr.EINVAL
	}

	if attr.InstructionCount == 0 || attr.InstructionCount > linux.BPF_COMPLEXITY_LIMIT_INSNS {
		// Instruction count out of range
		return 0, linuxerr.E2BIG
	}

	// Load the program
	instructionsAddr := hostarch.Addr(attr.Instructions)
	instructions := make([]linux.EBPFInstruction, attr.InstructionCount)
	if _, err := linux.CopyEBPFInstructionSliceIn(t, instructionsAddr, instructions); err != nil {
		return 0, err
	}

	unverifiedProg := ebpf.NewUnverifiedProgram(instructions)

	// TODO: assign each eBPF program an independent ID.
	//
	// The ID must be recycled when an eBPF program is destroyed, so this will
	// require programs to be refcounted.
	prog, err := unverifiedProg.Validate(0, progType)
	if err != nil {
		return 0, err
	}

	// Make a file descriptor referring to the newly-loaded program
	file, err := ebpffd.New(t, t.Kernel().VFS(), uint32(linux.O_RDWR), &prog)
	if err != nil {
		return 0, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, err
	}

	return uintptr(fd), nil
}

func bpfProgQuery(t *kernel.Task, attr *linux.BPFAttrProgQuery, attrAddr hostarch.Addr, size int) (uintptr, error) {
	// BPF_PROG_QUERY requires either CAP_NET_ADMIN or CAP_SYS_ADMIN
	if !t.Credentials().HasRootCapability(linux.CAP_NET_ADMIN) && !t.Credentials().HasRootCapability(linux.CAP_SYS_ADMIN) {
		return 0, linuxerr.EPERM
	}

	if attr.QueryFlags != 0 {
		// We currently support no flags.
		return 0, linuxerr.EINVAL
	}

	if attr.ProgAttachFlags != 0 {
		// We currently support no prog attach flags.
		return 0, linuxerr.EINVAL
	}

	attachType := ebpf.ParseAttachmentType(linux.BPFAttachType(attr.AttachType))
	if attachType == nil {
		// Invalid attach type
		return 0, linuxerr.EINVAL
	}

	switch attachType := attachType.(type) {
	case ebpf.CgroupAttachType:
		// cgroup v2 eBPF program: first, fetch the cgroup
		cgroup, err := t.GetCgroup2NodeFromFD(uint64(attr.Target))
		if err != nil {
			return 0, err
		}

		count := attr.Count

		// then, access the filters
		var accessErr error
		var outProgs []*kernel.Cgroup2BPFProgram
		var flags uint32
		var revision uint64
		var progCount uint32
		cgroup.IfBPF(func(bpf *kernel.Cgroup2BPF) {
			slot := &bpf.Slots[attachType]
			flags = uint32(slot.Flags)
			revision = slot.Revision
			progCount = uint32(len(slot.Progs))

			if count > progCount {
				// User requested too many programs: clamp
				count = progCount
			} else if count < progCount && (count != 0 && attr.ProgIDs != 0) {
				// User requested too few programs: indicate that there were more
				// (but we will still copy out what we can)
				accessErr = linuxerr.ENOSPC
			}

			outProgs = append(outProgs, slot.Progs[:count]...)
		})

		// Update the attach flags, count, and revision for userspace
		attr.AttachFlags = flags
		attr.Count = progCount
		attr.Revision = revision + 1
		if _, err := attr.CopyOutN(t, attrAddr, int(size)); err != nil {
			return 0, err
		}

		if attr.ProgIDs != 0 {
			// If requested, copy out the program IDs
			progIDsAddr := hostarch.Addr(attr.ProgIDs)
			for i, prog := range outProgs {
				if _, err := primitive.CopyUint32Out(t, progIDsAddr+hostarch.Addr(i*4), uint32(prog.Prog.ID())); err != nil {
					return 0, err
				}
			}
		}

		return 0, accessErr
	default:
		// Unsupported attach type
		return 0, linuxerr.EINVAL
	}
}

func bpfProgAttach(t *kernel.Task, attr *linux.BPFAttrProgAttach) (uintptr, error) {
	// Note the lack of a capability check. A caller needs privilege to open a
	// BPF program fd, but attaching one does not require privilege.

	flags := attr.AttachFlags
	slotFlags := uint8(flags & (linux.BPF_F_ALLOW_OVERRIDE | linux.BPF_F_ALLOW_MULTI))

	attachType := ebpf.ParseAttachmentType(linux.BPFAttachType(attr.AttachType))
	if attachType == nil {
		// Invalid attach type
		return 0, linuxerr.EINVAL
	}

	if attr.ExpectedRevision != 0 {
		// ExpectedRevision currently unsupported
		return 0, linuxerr.EINVAL
	}

	if attr.Relative != 0 {
		// relative_fd and relative_id are currently unsupported
		return 0, linuxerr.EINVAL
	}

	// Per-attachment type attach flags validation
	switch attachType.(type) {
	case ebpf.CgroupAttachType:
		if flags&^(linux.BPF_F_ALLOW_MULTI|linux.BPF_F_ALLOW_OVERRIDE) != 0 {
			// Only BPF_F_ALLOW_MULTI and BPF_F_ALLOW_OVERRIDE are supported.
			return 0, linuxerr.EINVAL
		}
		if flags&linux.BPF_F_ALLOW_MULTI != 0 && flags&linux.BPF_F_ALLOW_OVERRIDE != 0 {
			// BPF_F_ALLW_MULTI and BPF_F_ALLOW_OVERRIDE are mutually exclusive.
			return 0, linuxerr.EINVAL
		}
	default:
		// Unsupported attach type
		return 0, linuxerr.EINVAL
	}

	// Fetch the eBPF program from the specified file descriptor
	ebpfFile := t.GetFile(int32(attr.AttachBPFFD))
	if ebpfFile == nil {
		return 0, linuxerr.EBADF
	}
	defer ebpfFile.DecRef(t)
	ebpfFD, ok := ebpfFile.Impl().(*ebpffd.ProgramFD)
	if !ok {
		// Not an eBPF program fd
		return 0, linuxerr.EINVAL
	}
	prog := ebpfFD.Program()

	matchingProgType := attachType.MatchingProgType()
	if prog.ProgType() != matchingProgType {
		// Program type not valid for this attachment type
		return 0, linuxerr.EINVAL
	}

	switch attachType := attachType.(type) {
	case ebpf.CgroupAttachType:
		// cgroup v2 eBPF program: first, fetch the referenced cgroup
		cgroup, err := t.GetCgroup2NodeFromFD(uint64(attr.Target))
		if err != nil {
			return 0, err
		}

		// Take the cgroup tree lock
		err = cgroup.WriteBPF(func(bpf *kernel.Cgroup2BPF, ancestors []*kernel.Cgroup2BPF) error {
			// check if the cgroup's parent(s) allow the attach
			if err := cgroupBPFAttachCheckAncestors(ancestors, attachType); err != nil {
				return err
			}

			slot := &bpf.Slots[attachType]

			if len(slot.Progs) > 0 && slot.Flags != slotFlags {
				// Slot-level flags don't match what userspace requested
				return linuxerr.EPERM
			}

			if len(slot.Progs) >= linux.BPF_CGROUP_MAX_PROGS {
				// Slot is already full
				return linuxerr.E2BIG
			}

			if flags&linux.BPF_F_ALLOW_MULTI == 0 && len(slot.Progs) != 0 {
				// If allow-multi wasn't requested, the attachment slot must be empty to attach
				return linuxerr.EINVAL
			}

			// Disallow attaching the same program twice at the same attachment slot
			for _, existingProg := range slot.Progs {
				if prog == existingProg.Prog {
					return linuxerr.EINVAL
				}
			}

			// Now, we can do the attachment.
			newProg := &kernel.Cgroup2BPFProgram{
				Prog:  prog,
				Flags: flags,
			}
			slot.Progs = append(slot.Progs, newProg)
			slot.Flags = slotFlags
			slot.Revision++

			return nil
		})
		return 0, err

	default:
		// Unsupported attachment type
		return 0, linuxerr.EINVAL

	}
}

// Bpf implements Linux syscall bpf(2).
func Bpf(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	cmd := args[0].Int()
	attrAddr := args[1].Pointer()
	size := args[2].Uint()

	// Copy in BPF attr struct from userspace
	attr, err := copyInBPFAttr(t, cmd, attrAddr, int(size))
	if err != nil {
		return 0, nil, err
	}

	switch attr := attr.(type) {
	case *linux.BPFAttrProgLoad:
		fd, err := bpfProgLoad(t, attr)
		return fd, nil, err

	case *linux.BPFAttrProgQuery:
		size := min(int(size), attr.SizeBytes())
		ret, err := bpfProgQuery(t, attr, attrAddr, size)
		return ret, nil, err

	case *linux.BPFAttrProgAttach:
		ret, err := bpfProgAttach(t, attr)
		return ret, nil, err

	default:
		// Unsupported command.
		if !t.HasRootCapability(linux.CAP_SYS_ADMIN) {
			return 0, nil, linuxerr.EPERM
		}
		return 0, nil, linuxerr.EINVAL
	}
}

// copyInBPFAttr fetches and returns a BPFAttr of the type specified by cmd from userspace.
//
// If cmd is invalid or unsupported, the nil BPFAttr is returned (along with no error).
func copyInBPFAttr(t *kernel.Task, cmd int32, addr hostarch.Addr, size int) (linux.BPFAttr, error) {
	// Invalid size. Negative size here would indicate overflow
	if size < 0 || size > hostarch.PageSize {
		return nil, linuxerr.E2BIG
	}

	var bpfAttr linux.BPFAttr
	switch cmd {
	case linux.BPF_PROG_LOAD:
		bpfAttr = &linux.BPFAttrProgLoad{}
	case linux.BPF_PROG_QUERY:
		bpfAttr = &linux.BPFAttrProgQuery{}
	case linux.BPF_PROG_ATTACH:
		bpfAttr = &linux.BPFAttrProgAttach{}
	default:
		return nil, nil
	}

	// Copy in the valid fields of the BPFAttr structure
	copySize := min(int(size), bpfAttr.SizeBytes())
	if _, err := bpfAttr.CopyInN(t, addr, copySize); err != nil {
		return nil, err
	}

	if size > linux.BPF_ATTR_SIZE {
		// Userspace has a newer union version. Check that the fields we don't
		// know about are zeroed out.
		buf := make([]byte, size-linux.BPF_ATTR_SIZE)
		if _, err := t.CopyInBytes(addr+hostarch.Addr(linux.BPF_ATTR_SIZE), buf); err != nil {
			return nil, err
		}

		for _, b := range buf {
			if b != 0 {
				return nil, linuxerr.E2BIG
			}
		}
	}

	if size > bpfAttr.SizeBytes() {
		// Check that the fields after this union *variant* (but still within
		// the overall union) are zeroed out.
		buf := make([]byte, min(size, linux.BPF_ATTR_SIZE)-bpfAttr.SizeBytes())
		if _, err := t.CopyInBytes(addr+hostarch.Addr(bpfAttr.SizeBytes()), buf); err != nil {
			return nil, err
		}

		for _, b := range buf {
			if b != 0 {
				return nil, linuxerr.EINVAL
			}
		}
	}

	return bpfAttr, nil
}
