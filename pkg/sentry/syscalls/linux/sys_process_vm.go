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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
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

	// Determine local and remote processes.
	// Local process is always the caller.
	localTask := t.ThreadGroup().Leader()
	if localTask == nil {
		return 0, nil, linuxerr.ESRCH
	}
	// Remote process is the pid specified in the syscall arguments. It is
	// allowed to be the same as the caller process.
	remoteThreadGroup := localTask.PIDNamespace().ThreadGroupWithID(pid)
	if remoteThreadGroup == nil {
		return 0, nil, linuxerr.ESRCH
	}
	remoteTask := remoteThreadGroup.Leader()
	if remoteTask.ExitState() >= kernel.TaskExitInitiated {
		return 0, nil, linuxerr.ESRCH
	}

	// man 2 process_vm_read: "Permission to read from or write to another
	// process is governed by a ptrace access mode
	// PTRACE_MODE_ATTACH_REALCREDS check; see ptrace(2)."
	if !localTask.CanTrace(remoteTask, true /* attach */) {
		return 0, nil, linuxerr.EPERM
	}

	// Figure out which processes and arguments (local or remote) are for
	// writing and which are for reading, based on the operation.
	var opArgs processVMOpArgs
	switch op {
	case processVMOpRead:
		// Read from remote process and write into local.
		opArgs = processVMOpArgs{
			readCtx:         remoteTask.CopyContext(t, usermem.IOOpts{}),
			readAddr:        rvec,
			readIovecCount:  riovcnt,
			writeCtx:        localTask.CopyContext(t, usermem.IOOpts{AddressSpaceActive: true}),
			writeAddr:       lvec,
			writeIovecCount: liovcnt,
		}
	case processVMOpWrite:
		// Read from local process and write into remote.
		opArgs = processVMOpArgs{
			readCtx:         localTask.CopyContext(t, usermem.IOOpts{AddressSpaceActive: true}),
			readAddr:        lvec,
			readIovecCount:  liovcnt,
			writeCtx:        remoteTask.CopyContext(t, usermem.IOOpts{}),
			writeAddr:       rvec,
			writeIovecCount: riovcnt,
		}
	default:
		panic(fmt.Sprintf("unknown process vm op type: %v", op))
	}

	var (
		n   int
		err error
	)
	if localTask == remoteTask {
		// No need to lock remote process's task mutex since it is the
		// same as this process.
		n, err = doProcessVMOpMaybeLocked(t, opArgs)
	} else {
		// Need to take remote process's task mutex.
		remoteTask.WithMuLocked(func(*kernel.Task) {
			n, err = doProcessVMOpMaybeLocked(t, opArgs)
		})
	}
	if err != nil {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

type processVMOpArgs struct {
	readCtx         marshal.CopyContext
	readAddr        hostarch.Addr
	readIovecCount  int
	writeCtx        marshal.CopyContext
	writeAddr       hostarch.Addr
	writeIovecCount int
}

func doProcessVMOpMaybeLocked(t *kernel.Task, args processVMOpArgs) (int, error) {
	// Copy IOVecs in to kernel.
	readIovecs, err := t.CopyInIovecsAsSlice(args.readAddr, args.readIovecCount)
	if err != nil {
		return 0, err
	}
	writeIovecs, err := t.CopyInIovecsAsSlice(args.writeAddr, args.writeIovecCount)
	if err != nil {
		return 0, err
	}

	// Get scratch buffer from the calling task.
	// Size should be max be size of largest read iovec.
	var bufSize int
	for _, readIovec := range readIovecs {
		if int(readIovec.Length()) > bufSize {
			bufSize = int(readIovec.Length())
		}
	}
	buf := t.CopyScratchBuffer(bufSize)

	// Number of bytes written.
	var n int
	for _, readIovec := range readIovecs {
		if len(writeIovecs) == 0 {
			break
		}

		buf = buf[0:int(readIovec.Length())]
		bytes, err := args.readCtx.CopyInBytes(readIovec.Start, buf)
		if linuxerr.Equals(linuxerr.EFAULT, err) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if bytes != int(readIovec.Length()) {
			return n, nil
		}

		start := 0
		for bytes > start && 0 < len(writeIovecs) {
			writeLength := int(writeIovecs[0].Length())
			if writeLength > (bytes - start) {
				writeLength = bytes - start
			}
			out, err := args.writeCtx.CopyOutBytes(writeIovecs[0].Start, buf[start:writeLength+start])
			n += out
			start += out
			if linuxerr.Equals(linuxerr.EFAULT, err) {
				return n, nil
			}
			if err != nil {
				return n, err
			}
			if out != writeLength {
				return n, nil
			}
			writeIovecs[0].Start += hostarch.Addr(out)
			if !writeIovecs[0].WellFormed() {
				return n, err
			}
			if writeIovecs[0].Length() == 0 {
				writeIovecs = writeIovecs[1:]
			}
		}
	}
	return n, nil
}
