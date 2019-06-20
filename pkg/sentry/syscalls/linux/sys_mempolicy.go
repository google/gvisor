// Copyright 2019 The gVisor Authors.
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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
)

// We unconditionally report a single NUMA node. This also means that our
// "nodemask_t" is a single unsigned long (uint64).
const (
	maxNodes        = 1
	allowedNodemask = (1 << maxNodes) - 1
)

func copyInNodemask(t *kernel.Task, addr usermem.Addr, maxnode uint32) (uint64, error) {
	// "nodemask points to a bit mask of node IDs that contains up to maxnode
	// bits. The bit mask size is rounded to the next multiple of
	// sizeof(unsigned long), but the kernel will use bits only up to maxnode.
	// A NULL value of nodemask or a maxnode value of zero specifies the empty
	// set of nodes. If the value of maxnode is zero, the nodemask argument is
	// ignored." - set_mempolicy(2). Unfortunately, most of this is inaccurate
	// because of what appears to be a bug: mm/mempolicy.c:get_nodes() uses
	// maxnode-1, not maxnode, as the number of bits.
	bits := maxnode - 1
	if bits > usermem.PageSize*8 { // also handles overflow from maxnode == 0
		return 0, syserror.EINVAL
	}
	if bits == 0 {
		return 0, nil
	}
	// Copy in the whole nodemask.
	numUint64 := (bits + 63) / 64
	buf := t.CopyScratchBuffer(int(numUint64) * 8)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return 0, err
	}
	val := usermem.ByteOrder.Uint64(buf)
	// Check that only allowed bits in the first unsigned long in the nodemask
	// are set.
	if val&^allowedNodemask != 0 {
		return 0, syserror.EINVAL
	}
	// Check that all remaining bits in the nodemask are 0.
	for i := 8; i < len(buf); i++ {
		if buf[i] != 0 {
			return 0, syserror.EINVAL
		}
	}
	return val, nil
}

func copyOutNodemask(t *kernel.Task, addr usermem.Addr, maxnode uint32, val uint64) error {
	// mm/mempolicy.c:copy_nodes_to_user() also uses maxnode-1 as the number of
	// bits.
	bits := maxnode - 1
	if bits > usermem.PageSize*8 { // also handles overflow from maxnode == 0
		return syserror.EINVAL
	}
	if bits == 0 {
		return nil
	}
	// Copy out the first unsigned long in the nodemask.
	buf := t.CopyScratchBuffer(8)
	usermem.ByteOrder.PutUint64(buf, val)
	if _, err := t.CopyOutBytes(addr, buf); err != nil {
		return err
	}
	// Zero out remaining unsigned longs in the nodemask.
	if bits > 64 {
		remAddr, ok := addr.AddLength(8)
		if !ok {
			return syserror.EFAULT
		}
		remUint64 := (bits - 1) / 64
		if _, err := t.MemoryManager().ZeroOut(t, remAddr, int64(remUint64)*8, usermem.IOOpts{
			AddressSpaceActive: true,
		}); err != nil {
			return err
		}
	}
	return nil
}

// GetMempolicy implements the syscall get_mempolicy(2).
func GetMempolicy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	mode := args[0].Pointer()
	nodemask := args[1].Pointer()
	maxnode := args[2].Uint()
	addr := args[3].Pointer()
	flags := args[4].Uint()

	if flags&^(linux.MPOL_F_NODE|linux.MPOL_F_ADDR|linux.MPOL_F_MEMS_ALLOWED) != 0 {
		return 0, nil, syserror.EINVAL
	}
	nodeFlag := flags&linux.MPOL_F_NODE != 0
	addrFlag := flags&linux.MPOL_F_ADDR != 0
	memsAllowed := flags&linux.MPOL_F_MEMS_ALLOWED != 0

	// "EINVAL: The value specified by maxnode is less than the number of node
	// IDs supported by the system." - get_mempolicy(2)
	if nodemask != 0 && maxnode < maxNodes {
		return 0, nil, syserror.EINVAL
	}

	// "If flags specifies MPOL_F_MEMS_ALLOWED [...], the mode argument is
	// ignored and the set of nodes (memories) that the thread is allowed to
	// specify in subsequent calls to mbind(2) or set_mempolicy(2) (in the
	// absence of any mode flags) is returned in nodemask."
	if memsAllowed {
		// "It is not permitted to combine MPOL_F_MEMS_ALLOWED with either
		// MPOL_F_ADDR or MPOL_F_NODE."
		if nodeFlag || addrFlag {
			return 0, nil, syserror.EINVAL
		}
		if err := copyOutNodemask(t, nodemask, maxnode, allowedNodemask); err != nil {
			return 0, nil, err
		}
		return 0, nil, nil
	}

	// "If flags specifies MPOL_F_ADDR, then information is returned about the
	// policy governing the memory address given in addr. ... If the mode
	// argument is not NULL, then get_mempolicy() will store the policy mode
	// and any optional mode flags of the requested NUMA policy in the location
	// pointed to by this argument. If nodemask is not NULL, then the nodemask
	// associated with the policy will be stored in the location pointed to by
	// this argument."
	if addrFlag {
		policy, nodemaskVal, err := t.MemoryManager().NumaPolicy(addr)
		if err != nil {
			return 0, nil, err
		}
		if nodeFlag {
			// "If flags specifies both MPOL_F_NODE and MPOL_F_ADDR,
			// get_mempolicy() will return the node ID of the node on which the
			// address addr is allocated into the location pointed to by mode.
			// If no page has yet been allocated for the specified address,
			// get_mempolicy() will allocate a page as if the thread had
			// performed a read (load) access to that address, and return the
			// ID of the node where that page was allocated."
			buf := t.CopyScratchBuffer(1)
			_, err := t.CopyInBytes(addr, buf)
			if err != nil {
				return 0, nil, err
			}
			policy = 0 // maxNodes == 1
		}
		if mode != 0 {
			if _, err := t.CopyOut(mode, policy); err != nil {
				return 0, nil, err
			}
		}
		if nodemask != 0 {
			if err := copyOutNodemask(t, nodemask, maxnode, nodemaskVal); err != nil {
				return 0, nil, err
			}
		}
		return 0, nil, nil
	}

	// "EINVAL: ... flags specified MPOL_F_ADDR and addr is NULL, or flags did
	// not specify MPOL_F_ADDR and addr is not NULL." This is partially
	// inaccurate: if flags specifies MPOL_F_ADDR,
	// mm/mempolicy.c:do_get_mempolicy() doesn't special-case NULL; it will
	// just (usually) fail to find a VMA at address 0 and return EFAULT.
	if addr != 0 {
		return 0, nil, syserror.EINVAL
	}

	// "If flags is specified as 0, then information about the calling thread's
	// default policy (as set by set_mempolicy(2)) is returned, in the buffers
	// pointed to by mode and nodemask. ... If flags specifies MPOL_F_NODE, but
	// not MPOL_F_ADDR, and the thread's current policy is MPOL_INTERLEAVE,
	// then get_mempolicy() will return in the location pointed to by a
	// non-NULL mode argument, the node ID of the next node that will be used
	// for interleaving of internal kernel pages allocated on behalf of the
	// thread."
	policy, nodemaskVal := t.NumaPolicy()
	if nodeFlag {
		if policy&^linux.MPOL_MODE_FLAGS != linux.MPOL_INTERLEAVE {
			return 0, nil, syserror.EINVAL
		}
		policy = 0 // maxNodes == 1
	}
	if mode != 0 {
		if _, err := t.CopyOut(mode, policy); err != nil {
			return 0, nil, err
		}
	}
	if nodemask != 0 {
		if err := copyOutNodemask(t, nodemask, maxnode, nodemaskVal); err != nil {
			return 0, nil, err
		}
	}
	return 0, nil, nil
}

// SetMempolicy implements the syscall set_mempolicy(2).
func SetMempolicy(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	modeWithFlags := args[0].Int()
	nodemask := args[1].Pointer()
	maxnode := args[2].Uint()

	modeWithFlags, nodemaskVal, err := copyInMempolicyNodemask(t, modeWithFlags, nodemask, maxnode)
	if err != nil {
		return 0, nil, err
	}

	t.SetNumaPolicy(modeWithFlags, nodemaskVal)
	return 0, nil, nil
}

// Mbind implements the syscall mbind(2).
func Mbind(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	length := args[1].Uint64()
	mode := args[2].Int()
	nodemask := args[3].Pointer()
	maxnode := args[4].Uint()
	flags := args[5].Uint()

	if flags&^linux.MPOL_MF_VALID != 0 {
		return 0, nil, syserror.EINVAL
	}
	// "If MPOL_MF_MOVE_ALL is passed in flags ... [the] calling thread must be
	// privileged (CAP_SYS_NICE) to use this flag." - mbind(2)
	if flags&linux.MPOL_MF_MOVE_ALL != 0 && !t.HasCapability(linux.CAP_SYS_NICE) {
		return 0, nil, syserror.EPERM
	}

	mode, nodemaskVal, err := copyInMempolicyNodemask(t, mode, nodemask, maxnode)
	if err != nil {
		return 0, nil, err
	}

	// Since we claim to have only a single node, all flags can be ignored
	// (since all pages must already be on that single node).
	err = t.MemoryManager().SetNumaPolicy(addr, length, mode, nodemaskVal)
	return 0, nil, err
}

func copyInMempolicyNodemask(t *kernel.Task, modeWithFlags int32, nodemask usermem.Addr, maxnode uint32) (int32, uint64, error) {
	flags := modeWithFlags & linux.MPOL_MODE_FLAGS
	mode := modeWithFlags &^ linux.MPOL_MODE_FLAGS
	if flags == linux.MPOL_MODE_FLAGS {
		// Can't specify both mode flags simultaneously.
		return 0, 0, syserror.EINVAL
	}
	if mode < 0 || mode >= linux.MPOL_MAX {
		// Must specify a valid mode.
		return 0, 0, syserror.EINVAL
	}

	var nodemaskVal uint64
	if nodemask != 0 {
		var err error
		nodemaskVal, err = copyInNodemask(t, nodemask, maxnode)
		if err != nil {
			return 0, 0, err
		}
	}

	switch mode {
	case linux.MPOL_DEFAULT:
		// "nodemask must be specified as NULL." - set_mempolicy(2). This is inaccurate;
		// Linux allows a nodemask to be specified, as long as it is empty.
		if nodemaskVal != 0 {
			return 0, 0, syserror.EINVAL
		}
	case linux.MPOL_BIND, linux.MPOL_INTERLEAVE:
		// These require a non-empty nodemask.
		if nodemaskVal == 0 {
			return 0, 0, syserror.EINVAL
		}
	case linux.MPOL_PREFERRED:
		// This permits an empty nodemask, as long as no flags are set.
		if nodemaskVal == 0 && flags != 0 {
			return 0, 0, syserror.EINVAL
		}
	case linux.MPOL_LOCAL:
		// This requires an empty nodemask and no flags set ...
		if nodemaskVal != 0 || flags != 0 {
			return 0, 0, syserror.EINVAL
		}
		// ... and is implemented as MPOL_PREFERRED.
		mode = linux.MPOL_PREFERRED
	default:
		// Unknown mode, which we should have rejected above.
		panic(fmt.Sprintf("unknown mode: %v", mode))
	}

	return mode | flags, nodemaskVal, nil
}
