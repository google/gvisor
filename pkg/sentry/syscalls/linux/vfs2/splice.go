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
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
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
	defer inFile.DecRef(t)
	outFile := t.GetFileVFS2(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef(t)

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
		if _, err := primitive.CopyInt64In(t, inOffsetPtr, &inOffset); err != nil {
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
		if _, err := primitive.CopyInt64In(t, outOffsetPtr, &outOffset); err != nil {
			return 0, nil, err
		}
		if outOffset < 0 {
			return 0, nil, syserror.EINVAL
		}
	}

	// Move data.
	var (
		n   int64
		err error
	)
	dw := dualWaiter{
		inFile:  inFile,
		outFile: outFile,
	}
	defer dw.destroy()
	for {
		// If both input and output are pipes, delegate to the pipe
		// implementation. Otherwise, exactly one end is a pipe, which
		// we ensure is consistently ordered after the non-pipe FD's
		// locks by passing the pipe FD as usermem.IO to the non-pipe
		// end.
		switch {
		case inIsPipe && outIsPipe:
			n, err = pipe.Splice(t, outPipeFD, inPipeFD, count)
		case inIsPipe:
			n, err = inPipeFD.SpliceToNonPipe(t, outFile, outOffset, count)
			if outOffset != -1 {
				outOffset += n
			}
		case outIsPipe:
			n, err = outPipeFD.SpliceFromNonPipe(t, inFile, inOffset, count)
			if inOffset != -1 {
				inOffset += n
			}
		default:
			panic("at least one end of splice must be a pipe")
		}

		if n == 0 && err == io.EOF {
			// We reached the end of the file. Eat the error and exit the loop.
			err = nil
			break
		}
		if n != 0 || err != syserror.ErrWouldBlock || nonBlock {
			break
		}
		if err = dw.waitForBoth(t); err != nil {
			break
		}
	}

	// Copy updated offsets out.
	if inOffsetPtr != 0 {
		if _, err := primitive.CopyInt64Out(t, inOffsetPtr, inOffset); err != nil {
			return 0, nil, err
		}
	}
	if outOffsetPtr != 0 {
		if _, err := primitive.CopyInt64Out(t, outOffsetPtr, outOffset); err != nil {
			return 0, nil, err
		}
	}

	if n == 0 {
		return 0, nil, err
	}

	// On Linux, inotify behavior is not very consistent with splice(2). We try
	// our best to emulate Linux for very basic calls to splice, where for some
	// reason, events are generated for output files, but not input files.
	outFile.Dentry().InotifyWithParent(t, linux.IN_MODIFY, 0, vfs.PathEvent)
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
	defer inFile.DecRef(t)
	outFile := t.GetFileVFS2(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef(t)

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
		n   int64
		err error
	)
	dw := dualWaiter{
		inFile:  inFile,
		outFile: outFile,
	}
	defer dw.destroy()
	for {
		n, err = pipe.Tee(t, outPipeFD, inPipeFD, count)
		if n != 0 || err != syserror.ErrWouldBlock || nonBlock {
			break
		}
		if err = dw.waitForBoth(t); err != nil {
			break
		}
	}
	if n == 0 {
		return 0, nil, err
	}
	outFile.Dentry().InotifyWithParent(t, linux.IN_MODIFY, 0, vfs.PathEvent)
	return uintptr(n), nil, nil
}

// Sendfile implements linux system call sendfile(2).
func Sendfile(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	outFD := args[0].Int()
	inFD := args[1].Int()
	offsetAddr := args[2].Pointer()
	count := int64(args[3].SizeT())

	inFile := t.GetFileVFS2(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef(t)
	if !inFile.IsReadable() {
		return 0, nil, syserror.EBADF
	}

	outFile := t.GetFileVFS2(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef(t)
	if !outFile.IsWritable() {
		return 0, nil, syserror.EBADF
	}

	// Verify that the outFile Append flag is not set.
	if outFile.StatusFlags()&linux.O_APPEND != 0 {
		return 0, nil, syserror.EINVAL
	}

	// Verify that inFile is a regular file or block device. This is a
	// requirement; the same check appears in Linux
	// (fs/splice.c:splice_direct_to_actor).
	if stat, err := inFile.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE}); err != nil {
		return 0, nil, err
	} else if stat.Mask&linux.STATX_TYPE == 0 ||
		(stat.Mode&linux.S_IFMT != linux.S_IFREG && stat.Mode&linux.S_IFMT != linux.S_IFBLK) {
		return 0, nil, syserror.EINVAL
	}

	// Copy offset if it exists.
	offset := int64(-1)
	if offsetAddr != 0 {
		if inFile.Options().DenyPRead {
			return 0, nil, syserror.ESPIPE
		}
		var offsetP primitive.Int64
		if _, err := offsetP.CopyIn(t, offsetAddr); err != nil {
			return 0, nil, err
		}
		offset = int64(offsetP)

		if offset < 0 {
			return 0, nil, syserror.EINVAL
		}
		if offset+count < 0 {
			return 0, nil, syserror.EINVAL
		}
	}

	// Validate count. This must come after offset checks.
	if count < 0 {
		return 0, nil, syserror.EINVAL
	}
	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(kernel.MAX_RW_COUNT) {
		count = int64(kernel.MAX_RW_COUNT)
	}

	// Copy data.
	var (
		n   int64
		err error
	)
	dw := dualWaiter{
		inFile:  inFile,
		outFile: outFile,
	}
	defer dw.destroy()
	outPipeFD, outIsPipe := outFile.Impl().(*pipe.VFSPipeFD)
	// Reading from input file should never block, since it is regular or
	// block device. We only need to check if writing to the output file
	// can block.
	nonBlock := outFile.StatusFlags()&linux.O_NONBLOCK != 0
	if outIsPipe {
		for n < count {
			var spliceN int64
			spliceN, err = outPipeFD.SpliceFromNonPipe(t, inFile, offset, count)
			if spliceN == 0 && err == io.EOF {
				// We reached the end of the file. Eat the error and exit the loop.
				err = nil
				break
			}
			if offset != -1 {
				offset += spliceN
			}
			n += spliceN
			if err == syserror.ErrWouldBlock && !nonBlock {
				err = dw.waitForBoth(t)
			}
			if err != nil {
				break
			}
		}
	} else {
		// Read inFile to buffer, then write the contents to outFile.
		buf := make([]byte, count)
		for n < count {
			var readN int64
			if offset != -1 {
				readN, err = inFile.PRead(t, usermem.BytesIOSequence(buf), offset, vfs.ReadOptions{})
				offset += readN
			} else {
				readN, err = inFile.Read(t, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
			}
			if readN == 0 && err != nil {
				if err == io.EOF {
					// We reached the end of the file. Eat the error before exiting the loop.
					err = nil
				}
				break
			}
			n += readN

			// Write all of the bytes that we read. This may need
			// multiple write calls to complete.
			wbuf := buf[:readN]
			for len(wbuf) > 0 {
				var writeN int64
				writeN, err = outFile.Write(t, usermem.BytesIOSequence(wbuf), vfs.WriteOptions{})
				wbuf = wbuf[writeN:]
				if err == syserror.ErrWouldBlock && !nonBlock {
					err = dw.waitForOut(t)
				}
				if err != nil {
					// We didn't complete the write. Only report the bytes that were actually
					// written, and rewind offsets as needed.
					notWritten := int64(len(wbuf))
					n -= notWritten
					if offset == -1 {
						// We modified the offset of the input file itself during the read
						// operation. Rewind it.
						if _, seekErr := inFile.Seek(t, -notWritten, linux.SEEK_CUR); seekErr != nil {
							// Log the error but don't return it, since the write has already
							// completed successfully.
							log.Warningf("failed to roll back input file offset: %v", seekErr)
						}
					} else {
						// The sendfile call was provided an offset parameter that should be
						// adjusted to reflect the number of bytes sent. Rewind it.
						offset -= notWritten
					}
					break
				}
			}
			if err == syserror.ErrWouldBlock && !nonBlock {
				err = dw.waitForBoth(t)
			}
			if err != nil {
				break
			}
		}
	}

	if offsetAddr != 0 {
		// Copy out the new offset.
		offsetP := primitive.Uint64(offset)
		if _, err := offsetP.CopyOut(t, offsetAddr); err != nil {
			return 0, nil, err
		}
	}

	if n == 0 {
		return 0, nil, err
	}

	inFile.Dentry().InotifyWithParent(t, linux.IN_ACCESS, 0, vfs.PathEvent)
	outFile.Dentry().InotifyWithParent(t, linux.IN_MODIFY, 0, vfs.PathEvent)
	return uintptr(n), nil, nil
}

// dualWaiter is used to wait on one or both vfs.FileDescriptions. It is not
// thread-safe, and does not take a reference on the vfs.FileDescriptions.
//
// Users must call destroy() when finished.
type dualWaiter struct {
	inFile  *vfs.FileDescription
	outFile *vfs.FileDescription

	inW   waiter.Entry
	inCh  chan struct{}
	outW  waiter.Entry
	outCh chan struct{}
}

// waitForBoth waits for both dw.inFile and dw.outFile to be ready.
func (dw *dualWaiter) waitForBoth(t *kernel.Task) error {
	if dw.inFile.Readiness(eventMaskRead)&eventMaskRead == 0 {
		if dw.inCh == nil {
			dw.inW, dw.inCh = waiter.NewChannelEntry(nil)
			dw.inFile.EventRegister(&dw.inW, eventMaskRead)
			// We might be ready now. Try again before blocking.
			return nil
		}
		if err := t.Block(dw.inCh); err != nil {
			return err
		}
	}
	return dw.waitForOut(t)
}

// waitForOut waits for dw.outfile to be read.
func (dw *dualWaiter) waitForOut(t *kernel.Task) error {
	if dw.outFile.Readiness(eventMaskWrite)&eventMaskWrite == 0 {
		if dw.outCh == nil {
			dw.outW, dw.outCh = waiter.NewChannelEntry(nil)
			dw.outFile.EventRegister(&dw.outW, eventMaskWrite)
			// We might be ready now. Try again before blocking.
			return nil
		}
		if err := t.Block(dw.outCh); err != nil {
			return err
		}
	}
	return nil
}

// destroy cleans up resources help by dw. No more calls to wait* can occur
// after destroy is called.
func (dw *dualWaiter) destroy() {
	if dw.inCh != nil {
		dw.inFile.EventUnregister(&dw.inW)
		dw.inCh = nil
	}
	if dw.outCh != nil {
		dw.outFile.EventUnregister(&dw.outW)
		dw.outCh = nil
	}
	dw.inFile = nil
	dw.outFile = nil
}
