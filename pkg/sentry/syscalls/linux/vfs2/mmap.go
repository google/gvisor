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

package vfs2

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Mmap implements Linux syscall mmap(2).
func Mmap(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	prot := args[2].Int()
	flags := args[3].Int()
	fd := args[4].Int()
	fixed := flags&linux.MAP_FIXED != 0
	private := flags&linux.MAP_PRIVATE != 0
	shared := flags&linux.MAP_SHARED != 0
	anon := flags&linux.MAP_ANONYMOUS != 0
	map32bit := flags&linux.MAP_32BIT != 0

	// Require exactly one of MAP_PRIVATE and MAP_SHARED.
	if private == shared {
		return 0, nil, linuxerr.EINVAL
	}

	opts := memmap.MMapOpts{
		Length:   args[1].Uint64(),
		Offset:   args[5].Uint64(),
		Addr:     args[0].Pointer(),
		Fixed:    fixed,
		Unmap:    fixed,
		Map32Bit: map32bit,
		Private:  private,
		Perms: hostarch.AccessType{
			Read:    linux.PROT_READ&prot != 0,
			Write:   linux.PROT_WRITE&prot != 0,
			Execute: linux.PROT_EXEC&prot != 0,
		},
		MaxPerms:  hostarch.AnyAccess,
		GrowsDown: linux.MAP_GROWSDOWN&flags != 0,
		Precommit: linux.MAP_POPULATE&flags != 0,
	}
	if linux.MAP_LOCKED&flags != 0 {
		opts.MLockMode = memmap.MLockEager
	}
	defer func() {
		if opts.MappingIdentity != nil {
			opts.MappingIdentity.DecRef(t)
		}
	}()

	if !anon {
		// Convert the passed FD to a file reference.
		file := t.GetFileVFS2(fd)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)

		// mmap unconditionally requires that the FD is readable.
		if !file.IsReadable() {
			return 0, nil, linuxerr.EACCES
		}
		// MAP_SHARED requires that the FD be writable for PROT_WRITE.
		if shared && !file.IsWritable() {
			opts.MaxPerms.Write = false
		}

		if err := file.ConfigureMMap(t, &opts); err != nil {
			return 0, nil, err
		}
	} else if shared {
		// Back shared anonymous mappings with an anonymous tmpfs file.
		opts.Offset = 0
		file, err := tmpfs.NewZeroFile(t, t.Credentials(), t.Kernel().ShmMount(), opts.Length)
		if err != nil {
			return 0, nil, err
		}
		defer file.DecRef(t)
		if err := file.ConfigureMMap(t, &opts); err != nil {
			return 0, nil, err
		}
	}

	rv, err := t.MemoryManager().MMap(t, opts)
	return uintptr(rv), nil, err
}

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
	case flags != 0:
		return 0, nil, linuxerr.EINVAL
	case liovcnt < 0 || liovcnt > linux.UIO_MAXIOV:
		return 0, nil, linuxerr.EINVAL
	case riovcnt < 0 || riovcnt > linux.UIO_MAXIOV:
		return 0, nil, linuxerr.EFAULT
	case lvec == 0 || rvec == 0:
		return 0, nil, linuxerr.EFAULT
	case riovcnt > linux.UIO_MAXIOV || liovcnt > linux.UIO_MAXIOV:
		return 0, nil, linuxerr.EINVAL
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

	rIovecs, err := rCtx.CopyInIovecs(rAddr, rIovecCount)
	if err != nil {
		return 0, nil, err
	}
	wIovecs, err := wCtx.CopyInIovecs(wAddr, wIovecCount)
	if err != nil {
		return 0, nil, err
	}

	bufSize := 0
	for _, rIovec := range rIovecs {
		if int(rIovec.Length()) > bufSize {
			bufSize = int(rIovec.Length())
		}
	}

	buf := rCtx.CopyScratchBuffer(bufSize)
	wCount := 0
	for _, rIovec := range rIovecs {
		if len(wIovecs) <= 0 {
			break
		}

		buf = buf[0:int(rIovec.Length())]
		bytes, err := rCtx.CopyInBytes(rIovec.Start, buf)
		if linuxerr.Equals(linuxerr.EFAULT, err) {
			return uintptr(wCount), nil, nil
		}
		if err != nil {
			return uintptr(wCount), nil, err
		}
		if bytes != int(rIovec.Length()) {
			return uintptr(wCount), nil, nil
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
				return uintptr(wCount), nil, nil
			}
			if err != nil {
				return uintptr(wCount), nil, err
			}
			if out != writeLength {
				return uintptr(wCount), nil, nil
			}
			wIovecs[0].Start += hostarch.Addr(out)
			if !wIovecs[0].WellFormed() {
				return uintptr(wCount), nil, err
			}
			if wIovecs[0].Length() == 0 {
				wIovecs = wIovecs[1:]
			}
		}
	}
	return uintptr(wCount), nil, nil
}
