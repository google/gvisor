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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Splice implements Linux syscall splice(2).
func Splice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	inOffsetPtr := args[1].Pointer()
	outFD := args[2].Int()
	outOffsetPtr := args[3].Pointer()
	count := int64(args[4].SizeT())
	flags := args[5].Int()

	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(kernel.MAX_RW_COUNT) {
		count = int64(kernel.MAX_RW_COUNT)
	}

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get file descriptions.
	inFile := t.GetFileVFS2(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef()
	outFile := t.GetFileVFS2(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef()

	// Check that both files support the required directionality.
	if !inFile.IsReadable() || !outFile.IsWritable() {
		return 0, nil, syserror.EBADF
	}

	// The operation is non-blocking if anything is non-blocking.
	//
	// N.B. This is a rather simplistic heuristic that avoids some
	// poor edge case behavior since the exact semantics here are
	// underspecified and vary between versions of Linux itself.
	nonBlock := ((inFile.StatusFlags()|outFile.StatusFlags())&linux.O_NONBLOCK != 0) || (flags&linux.SPLICE_F_NONBLOCK != 0)

	// At least one file description must represent a pipe.
	inPipeFD, inIsPipe := inFile.Impl().(*pipe.VFSPipeFD)
	outPipeFD, outIsPipe := outFile.Impl().(*pipe.VFSPipeFD)
	if !inIsPipe && !outIsPipe {
		return 0, nil, syserror.EINVAL
	}

	// Copy in offsets.
	inOffset := int64(-1)
	if inOffsetPtr != 0 {
		if inIsPipe {
			return 0, nil, syserror.ESPIPE
		}
		if inFile.Options().DenyPRead {
			return 0, nil, syserror.EINVAL
		}
		if _, err := t.CopyIn(inOffsetPtr, &inOffset); err != nil {
			return 0, nil, err
		}
		if inOffset < 0 {
			return 0, nil, syserror.EINVAL
		}
	}
	outOffset := int64(-1)
	if outOffsetPtr != 0 {
		if outIsPipe {
			return 0, nil, syserror.ESPIPE
		}
		if outFile.Options().DenyPWrite {
			return 0, nil, syserror.EINVAL
		}
		if _, err := t.CopyIn(outOffsetPtr, &outOffset); err != nil {
			return 0, nil, err
		}
		if outOffset < 0 {
			return 0, nil, syserror.EINVAL
		}
	}

	// Move data.
	var (
		n     int64
		err   error
		inCh  chan struct{}
		outCh chan struct{}
	)
	for {
		// If both input and output are pipes, delegate to the pipe
		// implementation. Otherwise, exactly one end is a pipe, which we
		// ensure is consistently ordered after the non-pipe FD's locks by
		// passing the pipe FD as usermem.IO to the non-pipe end.
		switch {
		case inIsPipe && outIsPipe:
			n, err = pipe.Splice(t, outPipeFD, inPipeFD, count)
		case inIsPipe:
			if outOffset != -1 {
				n, err = outFile.PWrite(t, inPipeFD.IOSequence(count), outOffset, vfs.WriteOptions{})
				outOffset += n
			} else {
				n, err = outFile.Write(t, inPipeFD.IOSequence(count), vfs.WriteOptions{})
			}
		case outIsPipe:
			if inOffset != -1 {
				n, err = inFile.PRead(t, outPipeFD.IOSequence(count), inOffset, vfs.ReadOptions{})
				inOffset += n
			} else {
				n, err = inFile.Read(t, outPipeFD.IOSequence(count), vfs.ReadOptions{})
			}
		}
		if n != 0 || err != syserror.ErrWouldBlock || nonBlock {
			break
		}

		// Note that the blocking behavior here is a bit different than the
		// normal pattern. Because we need to have both data to read and data
		// to write simultaneously, we actually explicitly block on both of
		// these cases in turn before returning to the splice operation.
		if inFile.Readiness(eventMaskRead)&eventMaskRead == 0 {
			if inCh == nil {
				inCh = make(chan struct{}, 1)
				inW, _ := waiter.NewChannelEntry(inCh)
				inFile.EventRegister(&inW, eventMaskRead)
				defer inFile.EventUnregister(&inW)
				continue // Need to refresh readiness.
			}
			if err = t.Block(inCh); err != nil {
				break
			}
		}
		if outFile.Readiness(eventMaskWrite)&eventMaskWrite == 0 {
			if outCh == nil {
				outCh = make(chan struct{}, 1)
				outW, _ := waiter.NewChannelEntry(outCh)
				outFile.EventRegister(&outW, eventMaskWrite)
				defer outFile.EventUnregister(&outW)
				continue // Need to refresh readiness.
			}
			if err = t.Block(outCh); err != nil {
				break
			}
		}
	}

	// Copy updated offsets out.
	if inOffsetPtr != 0 {
		if _, err := t.CopyOut(inOffsetPtr, &inOffset); err != nil {
			return 0, nil, err
		}
	}
	if outOffsetPtr != 0 {
		if _, err := t.CopyOut(outOffsetPtr, &outOffset); err != nil {
			return 0, nil, err
		}
	}

	if n == 0 {
		return 0, nil, err
	}

	// On Linux, inotify behavior is not very consistent with splice(2). We try
	// our best to emulate Linux for very basic calls to splice, where for some
	// reason, events are generated for output files, but not input files.
	outFile.Dentry().InotifyWithParent(linux.IN_MODIFY, 0, vfs.PathEvent)
	return uintptr(n), nil, nil
}

// Tee implements Linux syscall tee(2).
func Tee(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	outFD := args[1].Int()
	count := int64(args[2].SizeT())
	flags := args[3].Int()

	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(kernel.MAX_RW_COUNT) {
		count = int64(kernel.MAX_RW_COUNT)
	}

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get file descriptions.
	inFile := t.GetFileVFS2(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef()
	outFile := t.GetFileVFS2(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef()

	// Check that both files support the required directionality.
	if !inFile.IsReadable() || !outFile.IsWritable() {
		return 0, nil, syserror.EBADF
	}

	// The operation is non-blocking if anything is non-blocking.
	//
	// N.B. This is a rather simplistic heuristic that avoids some
	// poor edge case behavior since the exact semantics here are
	// underspecified and vary between versions of Linux itself.
	nonBlock := ((inFile.StatusFlags()|outFile.StatusFlags())&linux.O_NONBLOCK != 0) || (flags&linux.SPLICE_F_NONBLOCK != 0)

	// Both file descriptions must represent pipes.
	inPipeFD, inIsPipe := inFile.Impl().(*pipe.VFSPipeFD)
	outPipeFD, outIsPipe := outFile.Impl().(*pipe.VFSPipeFD)
	if !inIsPipe || !outIsPipe {
		return 0, nil, syserror.EINVAL
	}

	// Copy data.
	var (
		inCh  chan struct{}
		outCh chan struct{}
	)
	for {
		n, err := pipe.Tee(t, outPipeFD, inPipeFD, count)
		if n != 0 {
			return uintptr(n), nil, nil
		}
		if err != syserror.ErrWouldBlock || nonBlock {
			return 0, nil, err
		}

		// Note that the blocking behavior here is a bit different than the
		// normal pattern. Because we need to have both data to read and data
		// to write simultaneously, we actually explicitly block on both of
		// these cases in turn before returning to the tee operation.
		if inFile.Readiness(eventMaskRead)&eventMaskRead == 0 {
			if inCh == nil {
				inCh = make(chan struct{}, 1)
				inW, _ := waiter.NewChannelEntry(inCh)
				inFile.EventRegister(&inW, eventMaskRead)
				defer inFile.EventUnregister(&inW)
				continue // Need to refresh readiness.
			}
			if err := t.Block(inCh); err != nil {
				return 0, nil, err
			}
		}
		if outFile.Readiness(eventMaskWrite)&eventMaskWrite == 0 {
			if outCh == nil {
				outCh = make(chan struct{}, 1)
				outW, _ := waiter.NewChannelEntry(outCh)
				outFile.EventRegister(&outW, eventMaskWrite)
				defer outFile.EventUnregister(&outW)
				continue // Need to refresh readiness.
			}
			if err := t.Block(outCh); err != nil {
				return 0, nil, err
			}
		}
	}
}
