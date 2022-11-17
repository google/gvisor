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
	"gvisor.dev/gvisor/pkg/usermem"
)

// ProcessVMReadv implements process_vm_readv(2).
func ProcessVMReadv(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return processVMRW(t, args, false /*isWrite*/)
}

// ProcessVMWritev implements process_vm_writev(2).
func ProcessVMWritev(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return processVMRW(t, args, true /*isWrite*/)
}

func processVMRW(t *kernel.Task, args arch.SyscallArguments, isWrite bool) (uintptr, *kernel.SyscallControl, error) {
	pid := kernel.ThreadID(args[0].Int())
	lvec := hostarch.Addr(args[1].Pointer())
	liovcnt := int(args[2].Int64())
	rvec := hostarch.Addr(args[3].Pointer())
	riovcnt := int(args[4].Int64())
	flags := args[5].Int()

	switch {
	case flags != 0 ||
		liovcnt < 0 ||
		riovcnt < 0 ||
		liovcnt > linux.UIO_MAXIOV ||
		riovcnt > linux.UIO_MAXIOV:
		return 0, nil, linuxerr.EINVAL
	case lvec == 0 || rvec == 0:
		return 0, nil, linuxerr.EFAULT
	case liovcnt == 0 || riovcnt == 0:
		return 0, nil, nil
	}

	localProcess := t.ThreadGroup().Leader()
	if localProcess == nil {
		return 0, nil, linuxerr.ESRCH
	}
	remoteThreadGroup := localProcess.PIDNamespace().ThreadGroupWithID(pid)
	if remoteThreadGroup == nil {
		return 0, nil, linuxerr.ESRCH
	}
	remoteProcess := remoteThreadGroup.Leader()

	// For the write case, we read from the local process and write to the remote process.
	if isWrite {
		return doProcessVMReadWrite(localProcess, remoteProcess, lvec, rvec, liovcnt, riovcnt)
	}
	// For the read case, we read from the remote process and write to the local process.
	return doProcessVMReadWrite(remoteProcess, localProcess, rvec, lvec, riovcnt, liovcnt)
}

func doProcessVMReadWrite(rProcess, wProcess *kernel.Task, rAddr, wAddr hostarch.Addr, rIovecCount, wIovecCount int) (uintptr, *kernel.SyscallControl, error) {
	rCtx := rProcess.CopyContext(rProcess, usermem.IOOpts{})
	wCtx := wProcess.CopyContext(wProcess, usermem.IOOpts{})

	var wCount int
	doProcessVMReadWriteLocked := func() error {
		rIovecs, err := rCtx.CopyInIovecs(rAddr, rIovecCount)
		if err != nil {
			return err
		}
		wIovecs, err := wCtx.CopyInIovecs(wAddr, wIovecCount)
		if err != nil {
			return err
		}

		bufSize := 0
		for _, rIovec := range rIovecs {
			if int(rIovec.Length()) > bufSize {
				bufSize = int(rIovec.Length())
			}
		}

		buf := rCtx.CopyScratchBuffer(bufSize)
		for _, rIovec := range rIovecs {
			if len(wIovecs) <= 0 {
				break
			}

			buf = buf[0:int(rIovec.Length())]
			bytes, err := rCtx.CopyInBytes(rIovec.Start, buf)
			if linuxerr.Equals(linuxerr.EFAULT, err) {
				return nil
			}
			if err != nil {
				return err
			}
			if bytes != int(rIovec.Length()) {
				return nil
			}
			start := 0
			for bytes > start && 0 < len(wIovecs) {
				writeLength := int(wIovecs[0].Length())
				if writeLength > (bytes - start) {
					writeLength = bytes - start
				}
				out, err := wCtx.CopyOutBytes(wIovecs[0].Start, buf[start:writeLength+start])
				wCount += out
				start += out
				if linuxerr.Equals(linuxerr.EFAULT, err) {
					return nil
				}
				if err != nil {
					return err
				}
				if out != writeLength {
					return nil
				}
				wIovecs[0].Start += hostarch.Addr(out)
				if !wIovecs[0].WellFormed() {
					return err
				}
				if wIovecs[0].Length() == 0 {
					wIovecs = wIovecs[1:]
				}
			}
		}
		return nil
	}

	err := rCtx.WithTaskMutexLocked(func() error {
		if rProcess.ThreadGroup().Leader() != wProcess.ThreadGroup().Leader() {
			return wCtx.WithTaskMutexLocked(func() error {
				return doProcessVMReadWriteLocked()
			})
		}
		return doProcessVMReadWriteLocked()
	})

	return uintptr(wCount), nil, err
}
