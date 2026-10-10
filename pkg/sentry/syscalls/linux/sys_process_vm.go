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

// If pid selects another task, callers must not hold that task's mutex.
// checklocks cannot name the task returned by PIDNamespace.TaskWithID.
func processVMOp(t *kernel.Task, args arch.SyscallArguments, op processVMOpType) (uintptr, *kernel.SyscallControl, error) {
	pid := kernel.ThreadID(args[0].Int())
	lvec := hostarch.Addr(args[1].Pointer())
	liovcnt := int(args[2].Int64())
	rvec := hostarch.Addr(args[3].Pointer())
	riovcnt := int(args[4].Int64())
	flags := args[5].Int()

	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// The staging below matches Linux's mm/process_vm_access.c:
	// process_vm_rw() validates and imports the local iovecs and returns 0
	// for an empty local transfer before examining the remote iovecs at all;
	// process_vm_rw_core() then returns 0 for an empty remote transfer before
	// looking up the target task.
	if liovcnt < 0 || liovcnt > linux.UIO_MAXIOV {
		return 0, nil, linuxerr.EINVAL
	}
	var localIovecs []hostarch.AddrRange
	if liovcnt > 0 {
		var err error
		localIovecs, err = t.CopyInIovecsAsSlice(lvec, liovcnt)
		if err != nil {
			return 0, nil, err
		}
	}
	if totalIovecLength(localIovecs) == 0 {
		return 0, nil, nil
	}
	if riovcnt < 0 || riovcnt > linux.UIO_MAXIOV {
		return 0, nil, linuxerr.EINVAL
	}
	var remoteIovecs []hostarch.AddrRange
	if riovcnt > 0 {
		var err error
		remoteIovecs, err = t.CopyInIovecsAsSlice(rvec, riovcnt)
		if err != nil {
			return 0, nil, err
		}
	}
	if totalIovecLength(remoteIovecs) == 0 {
		return 0, nil, nil
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
	//
	// The check must apply to the same MemoryManager we access, so that a
	// concurrent execve of the remote task cannot substitute a new
	// (e.g. non-dumpable) mm between the check and the access.
	remoteMM, err := t.CanTraceAndGetMM(remoteTask, true /* attach */)
	if err != nil {
		if linuxerr.Equals(linuxerr.EACCES, err) {
			// As in Linux's mm/process_vm_access.c:process_vm_rw_core(),
			// mm_access()'s EACCES becomes EPERM.
			err = linuxerr.EPERM
		}
		return 0, nil, err
	}
	defer remoteMM.DecUsers(t)

	localOps := processVMOps{
		mm:     t.MemoryManager(),
		iovecs: localIovecs,
	}
	remoteOps := processVMOps{
		mm:     remoteMM,
		iovecs: remoteIovecs,
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
	// As in Linux's mm/process_vm_access.c:process_vm_rw_core(), a partial
	// transfer returns the number of bytes copied, and an error is returned
	// only if nothing was copied.
	if err != nil && n == 0 {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

// totalIovecLength returns the total length of the given iovecs.
func totalIovecLength(iovecs []hostarch.AddrRange) uint64 {
	var total uint64
	for _, iov := range iovecs {
		total += uint64(iov.Length())
	}
	return total
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
