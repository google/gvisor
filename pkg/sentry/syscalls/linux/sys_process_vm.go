// Copyright 2020 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/usermem"
)

type processVMOpType int

const (
	processVMOpRead = iota
	processVMOpWrite
)

// ProcessVMReadv implements process_vm_readv(2).
func ProcessVMReadv(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return processVMOp(t, args, processVMOpRead)
}

// ProcessVMWritev implements process_vm_writev(2).
func ProcessVMWritev(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return processVMOp(t, args, processVMOpWrite)
}

func processVMOp(t *kernel.Task, args arch.SyscallArguments, op processVMOpType) (uintptr, *kernel.SyscallControl, error) {
	pid := kernel.ThreadID(args[0].Int())
	lvec := hostarch.Addr(args[1].Pointer())
	liovcnt := int(args[2].Int64())
	rvec := hostarch.Addr(args[3].Pointer())
	riovcnt := int(args[4].Int64())
	flags := args[5].Int()

	// Parse the flags.
	switch {
	case flags != 0 ||
		liovcnt < 0 ||
		riovcnt < 0 ||
		liovcnt > linux.UIO_MAXIOV ||
		riovcnt > linux.UIO_MAXIOV:
		return 0, nil, linuxerr.EINVAL
	case liovcnt == 0 || riovcnt == 0:
		return 0, nil, nil
	case lvec == 0 || rvec == 0:
		return 0, nil, linuxerr.EFAULT
	}

	// Local process is always the current task (t). Remote process is the
	// pid specified in the syscall arguments. It is allowed to be the same
	// as the caller process.
	remoteTask := t.PIDNamespace().TaskWithID(pid)
	if remoteTask == nil {
		return 0, nil, linuxerr.ESRCH
	}

	// man 2 process_vm_read: "Permission to read from or write to another
	// process is governed by a ptrace access mode
	// PTRACE_MODE_ATTACH_REALCREDS check; see ptrace(2)."
	if !t.CanTrace(remoteTask, true /* attach */) {
		return 0, nil, linuxerr.EPERM
	}

	// Calculate MemoryManager, IOOpts, and iovecs for each of the local
	// and remote operations.
	localIovecs, err := t.CopyInIovecsAsSlice(lvec, liovcnt)
	if err != nil {
		return 0, nil, err
	}
	localOps := processVMOps{
		mm:     t.MemoryManager(),
		ioOpts: usermem.IOOpts{AddressSpaceActive: true},
		iovecs: localIovecs,
	}
	remoteIovecs, err := t.CopyInIovecsAsSlice(rvec, riovcnt)
	if err != nil {
		return 0, nil, err
	}
	remoteOps := processVMOps{
		iovecs: remoteIovecs,
	}
	if remoteTask == t {
		// No need to take remoteTask.mu to fetch the memory manager,
		// and we can assume address space is active.
		remoteOps.mm = t.MemoryManager()
		remoteOps.ioOpts = usermem.IOOpts{AddressSpaceActive: true}
	} else {
		// Grab the remoteTask memory manager, and pin it by adding
		// ourselves as a user.
		remoteTask.WithMuLocked(func(*kernel.Task) {
			remoteOps.mm = remoteTask.MemoryManager()
		})
		// Check remoteTask memory manager exists and
		if remoteOps.mm == nil {
			return 0, nil, linuxerr.ESRCH
		}
		if !remoteOps.mm.IncUsers() {
			return 0, nil, linuxerr.EFAULT
		}
		defer remoteOps.mm.DecUsers(t)
	}

	// Finally time to copy some bytes. The order depends on whether we are
	// "reading" or "writing".
	var n int
	switch op {
	case processVMOpRead:
		// Copy from remote process to local.
		n, err = processVMCopyIovecs(t, remoteOps, localOps)
	case processVMOpWrite:
		// Copy from local process to remote.
		n, err = processVMCopyIovecs(t, localOps, remoteOps)
	}
	if n == 0 && err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// maxScratchBufferSize is the maximum size of a scratch buffer. It should be
// sufficiently large to minimizing the number of trips through MM.
const maxScratchBufferSize = 1 << 20

type processVMOps struct {
	mm     *mm.MemoryManager
	ioOpts usermem.IOOpts
	iovecs []hostarch.AddrRange
}

func processVMCopyIovecs(t *kernel.Task, readOps, writeOps processVMOps) (int, error) {
	// Get scratch buffer from the calling task.
	// Size should be max be size of largest read iovec.
	var bufSize int
	for _, readIovec := range readOps.iovecs {
		if int(readIovec.Length()) > bufSize {
			bufSize = int(readIovec.Length())
		}
	}
	if bufSize > maxScratchBufferSize {
		bufSize = maxScratchBufferSize
	}
	buf := t.CopyScratchBuffer(bufSize)

	// Number of bytes written.
	var n int
	for len(readOps.iovecs) != 0 && len(writeOps.iovecs) != 0 {
		readIovec := readOps.iovecs[0]
		length := readIovec.Length()
		if length == 0 {
			readOps.iovecs = readOps.iovecs[1:]
			continue
		}
		if length > maxScratchBufferSize {
			length = maxScratchBufferSize
		}
		buf = buf[0:int(length)]
		bytes, err := readOps.mm.CopyIn(t, readIovec.Start, buf, readOps.ioOpts)
		if bytes == 0 {
			return n, err
		}
		readOps.iovecs[0].Start += hostarch.Addr(bytes)

		start := 0
		for bytes > start && len(writeOps.iovecs) > 0 {
			writeLength := int(writeOps.iovecs[0].Length())
			if writeLength == 0 {
				writeOps.iovecs = writeOps.iovecs[1:]
				continue
			}
			if writeLength > (bytes - start) {
				writeLength = bytes - start
			}
			out, err := writeOps.mm.CopyOut(t, writeOps.iovecs[0].Start, buf[start:writeLength+start], writeOps.ioOpts)
			n += out
			start += out
			if out != writeLength {
				return n, err
			}
			writeOps.iovecs[0].Start += hostarch.Addr(out)
		}
	}
	return n, nil
}
