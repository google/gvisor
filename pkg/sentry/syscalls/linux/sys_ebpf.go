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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ebpffd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

func cgroupCheckBpfAttach(cgroup kernel.Cgroup2, attachType ebpf.CgroupBpfAttachType) error {
	parent := cgroup.Parent()
	if parent == nil {
		return nil
	}

	for parent != nil {
		var flags uint8
		var numProgs int
		parent.AccessBPF(func(bpf *kernel.Cgroup2BPF) {
			flags = bpf.Slots[attachType].Flags
			numProgs = len(bpf.Slots[attachType].Progs)
		})

		if (flags & linux.BPF_F_ALLOW_MULTI) == linux.BPF_F_ALLOW_MULTI {
			return nil
		}
		if numProgs > 0 {
			if (flags & linux.BPF_F_ALLOW_OVERRIDE) == linux.BPF_F_ALLOW_OVERRIDE {
				return nil
			}
			return linuxerr.EPERM
		}

		parent = parent.Parent()
	}

	return nil
}

func bpfProgLoad(t *kernel.Task, attr *linux.BpfAttrProgLoad) (uintptr, error) {
	if !t.Credentials().HasRootCapability(linux.CAP_BPF) && !t.Credentials().HasRootCapability(linux.CAP_SYS_ADMIN) {
		return 0, linuxerr.EPERM
	}

	// Extra per-program-type capability checks
	switch attr.ProgType {
	case linux.BPF_PROG_TYPE_CGROUP_DEVICE:
		if !t.Credentials().HasRootCapability(linux.CAP_NET_ADMIN) {
			return 0, linuxerr.EPERM
		}
	default:
		// Unsupported program type
		return 0, linuxerr.EINVAL
	}

	if attr.ProgFlags != 0 {
		log.Warningf("ERROR PATH 4 (ProgFlags = %v)", attr.ProgFlags)
		return 0, linuxerr.EINVAL
	}

	if attr.AttachBTFID != 0 || attr.AttachFD != 0 {
		return 0, linuxerr.EINVAL
	}

	if attr.InstructionCount == 0 || attr.InstructionCount > linux.BPF_COMPLEXITY_LIMIT_INSNS {
		log.Warningf("ERROR PATH 5")
		return 0, linuxerr.E2BIG
	}

	log.Warningf("BPFAttr: %#+v", attr)

	// Load the program
	instructionsAddr := hostarch.Addr(attr.Instructions)
	instructions := make([]linux.EbpfInstruction, attr.InstructionCount)
	for i := range attr.InstructionCount {
		var instruction linux.EbpfInstruction
		if _, err := instruction.CopyIn(t, instructionsAddr+hostarch.Addr(i*linux.BPF_INSTRUCTION_SIZE)); err != nil {
			return 0, err
		}
		instructions[i] = instruction
	}

	unverifiedProg := ebpf.NewUnverifiedProgram(instructions)

	// TODO: assign each eBPF program an independent ID.
	//
	// The ID must be recycled when an eBPF program is destroyed, so this will
	// require programs to be refcounted.
	prog, err := unverifiedProg.Validate(0)
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

func bpfProgQuery(t *kernel.Task, attr *linux.BpfAttrProgQuery, attrAddr hostarch.Addr, size int) (uintptr, error) {
	if !t.Credentials().HasRootCapability(linux.CAP_NET_ADMIN) && !t.Credentials().HasRootCapability(linux.CAP_SYS_ADMIN) {
		return 0, linuxerr.EPERM
	}

	log.Warningf("BPFAttr: %#+v", attr)

	if attr.QueryFlags != 0 {
		// We currently support no flags.
		return 0, linuxerr.EINVAL
	}

	if attr.ProgAttachFlags != 0 {
		// We currently support no prog attach flags.
		return 0, linuxerr.EINVAL
	}

	attachType := ebpf.ParseAttachmentType(linux.BpfAttachType(attr.AttachType))
	if attachType == nil {
		// Invalid attach type
		return 0, linuxerr.EINVAL
	}

	switch attachType := attachType.(type) {
	case ebpf.CgroupBpfAttachType:
		cgroup, err := t.GetCgroup2NodeFromFD(uint64(attr.Target))
		if err != nil {
			return 0, err
		}

		count := attr.Count

		var flags uint32
		var revision uint64
		var progs []*kernel.Cgroup2BPFProgram

		cgroup.AccessBPF(func(bpf *kernel.Cgroup2BPF) {
			slot := &bpf.Slots[attachType]
			flags = uint32(slot.Flags)
			revision = slot.Revision

			progs = slot.Progs
		})

		// Update the attach flags, count, and revision for userspace
		attr.AttachFlags = flags
		attr.Count = uint32(len(progs))
		attr.Revision = revision
		if _, err := attr.CopyOutN(t, attrAddr, int(size)); err != nil {
			return 0, err
		}

		if count > 0 && attr.ProgIDs != 0 && progs != nil {
			// If requested, copy out the program ID
			progIDsAddr := hostarch.Addr(attr.ProgIDs)
			for i, prog := range progs {
				if _, err := primitive.CopyUint32Out(t, progIDsAddr+hostarch.Addr(i*4), uint32(prog.Prog.ID())); err != nil {
					return 0, err
				}
			}
		}

		return 0, nil
	default:
		// Unsupported attach type
		return 0, linuxerr.EINVAL
	}
}

func bpfProgAttach(t *kernel.Task, attr *linux.BpfAttrProgAttach) (uintptr, error) {
	log.Warningf("BPFAttr: %#+v", attr)

	flags := attr.AttachFlags
	slotFlags := uint8(flags & (linux.BPF_F_ALLOW_OVERRIDE | linux.BPF_F_ALLOW_MULTI))

	attachType := ebpf.ParseAttachmentType(linux.BpfAttachType(attr.AttachType))
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
	case ebpf.CgroupBpfAttachType:
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
	ebpfFile := t.GetFile(int32(attr.AttachBpfFD))
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

	switch attachType := attachType.(type) {
	case ebpf.CgroupBpfAttachType:
		cgroup, err := t.GetCgroup2NodeFromFD(uint64(attr.Target))
		if err != nil {
			return 0, err
		}

		if err := cgroupCheckBpfAttach(cgroup, attachType); err != nil {
			return 0, err
		}

		// Take the cgroup bpf lock
		var accessErr error
		cgroup.AccessBPF(func(bpf *kernel.Cgroup2BPF) {
			slot := &bpf.Slots[attachType]
			if len(slot.Progs) > 0 && slot.Flags != slotFlags {
				accessErr = linuxerr.EPERM
				return
			}

			if len(slot.Progs) >= linux.BPF_CGROUP_MAX_PROGS {
				accessErr = linuxerr.E2BIG
				return
			}

			// If allow-multi wasn't requested, the attachment slot must be empty to attach
			if flags&linux.BPF_F_ALLOW_MULTI == 0 && len(slot.Progs) != 0 {
				accessErr = linuxerr.EINVAL
				return
			}

			// Disallow attaching the same program twice at the same attachment slot
			for _, existingProg := range slot.Progs {
				if prog == existingProg.Prog {
					accessErr = linuxerr.EINVAL
					return
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
		})
		return 0, accessErr

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
	attr, err := copyInBpfAttr(t, cmd, attrAddr, int(size))
	if err != nil {
		return 0, nil, err
	}

	switch cmd {
	case linux.BPF_PROG_LOAD:
		fd, err := bpfProgLoad(t, attr.(*linux.BpfAttrProgLoad))
		return fd, nil, err

	case linux.BPF_PROG_QUERY:
		attr := attr.(*linux.BpfAttrProgQuery)
		size := min(int(size), attr.SizeBytes())
		ret, err := bpfProgQuery(t, attr, attrAddr, size)
		return ret, nil, err

	case linux.BPF_PROG_ATTACH:
		ret, err := bpfProgAttach(t, attr.(*linux.BpfAttrProgAttach))
		return ret, nil, err

	default:
		log.Warningf("ERROR PATH 6")
		return 0, nil, linuxerr.EINVAL
	}

	return 0, nil, nil
}

func copyInBpfAttr(t *kernel.Task, cmd int32, addr hostarch.Addr, size int) (linux.BpfAttr, error) {
	if size < 0 || size > hostarch.PageSize {
		return nil, linuxerr.E2BIG
	}

	var bpfAttr linux.BpfAttr
	switch cmd {
	case linux.BPF_PROG_LOAD:
		bpfAttr = &linux.BpfAttrProgLoad{}
	case linux.BPF_PROG_QUERY:
		bpfAttr = &linux.BpfAttrProgQuery{}
	case linux.BPF_PROG_ATTACH:
		bpfAttr = &linux.BpfAttrProgAttach{}
	default:
		return nil, linuxerr.EINVAL
	}

	size = min(int(size), bpfAttr.SizeBytes())
	if _, err := bpfAttr.CopyInN(t, addr, size); err != nil {
		log.Warningf("ERROR PATH 1")
		return nil, err
	}

	if size > bpfAttr.SizeBytes() {
		// Userspace has a newer struct version. Check that the fields we don't
		// know about are zeroed out.
		buf := make([]byte, size-bpfAttr.SizeBytes())
		if _, err := t.CopyInBytes(addr+hostarch.Addr(bpfAttr.SizeBytes()), buf); err != nil {
			log.Warningf("ERROR PATH 2")
			return nil, err
		}

		for _, b := range buf {
			if b != 0 {
				log.Warningf("ERROR PATH 3")
				return nil, linuxerr.E2BIG
			}
		}
	}

	return bpfAttr, nil
}
