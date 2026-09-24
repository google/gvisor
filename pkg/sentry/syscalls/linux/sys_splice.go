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
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Splice implements Linux syscall splice(2).
func Splice(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	inOffsetPtr := args[1].Pointer()
	outFD := args[2].Int()
	outOffsetPtr := args[3].Pointer()
	count := int64(args[4].SizeT())
	flags := args[5].Int()

	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(linux.MAX_RW_COUNT) {
		count = int64(linux.MAX_RW_COUNT)
	}
	if count < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get file descriptions.
	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)
	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	// Check that both files support the required directionality.
	if !inFile.IsReadable() || !outFile.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	if outFile.Options().DenySpliceIn {
		return 0, nil, linuxerr.EINVAL
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
		return 0, nil, linuxerr.EINVAL
	}

	// Copy in offsets.
	inOffset := int64(-1)
	if inOffsetPtr != 0 {
		if inIsPipe {
			return 0, nil, linuxerr.ESPIPE
		}
		if inFile.Options().DenyPRead {
			return 0, nil, linuxerr.EINVAL
		}
		if _, err := primitive.CopyInt64In(t, inOffsetPtr, &inOffset); err != nil {
			return 0, nil, err
		}
		if inOffset < 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}
	outOffset := int64(-1)
	if outOffsetPtr != 0 {
		if outIsPipe {
			return 0, nil, linuxerr.ESPIPE
		}
		if outFile.Options().DenyPWrite {
			return 0, nil, linuxerr.EINVAL
		}
		if _, err := primitive.CopyInt64In(t, outOffsetPtr, &outOffset); err != nil {
			return 0, nil, err
		}
		if outOffset < 0 {
			return 0, nil, linuxerr.EINVAL
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

		if n != 0 || !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || nonBlock {
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

	// We can only pass a single file to handleIOError, so pick inFile arbitrarily.
	// This is used only for debugging purposes.
	return uintptr(n), nil, HandleIOError(t, n != 0, err, linuxerr.ERESTARTSYS, "splice", outFile)
}

// Tee implements Linux syscall tee(2).
func Tee(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	outFD := args[1].Int()
	count := int64(args[2].SizeT())
	flags := args[3].Int()

	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(linux.MAX_RW_COUNT) {
		count = int64(linux.MAX_RW_COUNT)
	}
	if count < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get file descriptions.
	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)
	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	// Check that both files support the required directionality.
	if !inFile.IsReadable() || !outFile.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	if outFile.Options().DenySpliceIn {
		return 0, nil, linuxerr.EINVAL
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
		return 0, nil, linuxerr.EINVAL
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
		if n != 0 || !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || nonBlock {
			break
		}
		if err = dw.waitForBoth(t); err != nil {
			break
		}
	}

	if n != 0 {
		// If a partial write is completed, the error is dropped. Log it here.
		if err != nil && err != io.EOF && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			log.Debugf("tee completed a partial write with error: %v", err)
			err = nil
		}
	}

	// We can only pass a single file to handleIOError, so pick inFile arbitrarily.
	// This is used only for debugging purposes.
	return uintptr(n), nil, HandleIOError(t, n != 0, err, linuxerr.ERESTARTSYS, "tee", inFile)
}

var sendfileBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pipe.MaximumPipeSize)
		return &b
	},
}

// Sendfile implements linux system call sendfile(2).
func Sendfile(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	outFD := args[0].Int()
	inFD := args[1].Int()
	offsetAddr := args[2].Pointer()
	count := int64(args[3].SizeT())

	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)
	if !inFile.IsReadable() {
		return 0, nil, linuxerr.EBADF
	}

	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)
	if !outFile.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	if outFile.Options().DenySpliceIn {
		return 0, nil, linuxerr.EINVAL
	}

	// Verify that the outFile Append flag is not set.
	if outFile.StatusFlags()&linux.O_APPEND != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Verify that inFile is a regular file or block device. This is a
	// requirement; the same check appears in Linux
	// (fs/splice.c:splice_direct_to_actor).
	if stat, err := inFile.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE}); err != nil {
		return 0, nil, err
	} else if stat.Mask&linux.STATX_TYPE == 0 ||
		(stat.Mode&linux.S_IFMT != linux.S_IFREG && stat.Mode&linux.S_IFMT != linux.S_IFBLK) {
		return 0, nil, linuxerr.EINVAL
	}

	// Copy offset if it exists.
	offset := int64(-1)
	if offsetAddr != 0 {
		if inFile.Options().DenyPRead {
			return 0, nil, linuxerr.ESPIPE
		}
		var offsetP primitive.Int64
		if _, err := offsetP.CopyIn(t, offsetAddr); err != nil {
			return 0, nil, err
		}
		offset = int64(offsetP)

		if offset < 0 {
			return 0, nil, linuxerr.EINVAL
		}
		if offset+count < 0 {
			return 0, nil, linuxerr.EINVAL
		}
	}

	// Validate count. This must come after offset checks.
	if count < 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if count == 0 {
		return 0, nil, nil
	}
	if count > int64(linux.MAX_RW_COUNT) {
		count = int64(linux.MAX_RW_COUNT)
	}

	// Copy data.
	var (
		total int64
		err   error
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
		for {
			var n int64
			n, err = outPipeFD.SpliceFromNonPipe(t, inFile, offset, count-total)
			if offset != -1 {
				offset += n
			}
			total += n
			if total == count {
				break
			}
			if err == nil && t.Interrupted() {
				err = linuxerr.ErrInterrupted
				break
			}
			if linuxerr.Equals(linuxerr.ErrWouldBlock, err) && !nonBlock {
				err = dw.waitForBoth(t)
			}
			if err != nil {
				break
			}
		}
	} else {
		// Read inFile to buffer, then write the contents to outFile.
		//
		// The buffer size has to be limited to avoid large memory
		// allocations and long delays. In Linux, the buffer size is
		// limited by a size of an internl pipe. Here, we repeat this
		// behavior.
		bufPtr := sendfileBufPool.Get().(*[]byte)
		defer sendfileBufPool.Put(bufPtr)
		for {
			bufLen := min(count-total, pipe.MaximumPipeSize)
			buf := (*bufPtr)[:bufLen]
			var readN int64
			if offset != -1 {
				readN, err = inFile.PRead(t, usermem.BytesIOSequence(buf), offset, vfs.ReadOptions{})
				offset += readN
			} else {
				readN, err = inFile.Read(t, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
			}

			// Write all of the bytes that we read. This may need
			// multiple write calls to complete.
			wbuf := buf[:readN]
			for len(wbuf) > 0 {
				var writeN int64
				writeN, err = outFile.Write(t, usermem.BytesIOSequence(wbuf), vfs.WriteOptions{})
				wbuf = wbuf[writeN:]
				if linuxerr.Equals(linuxerr.ErrWouldBlock, err) && !nonBlock {
					err = dw.waitForOut(t)
				}
				if err != nil {
					// We didn't complete the write. Only report the bytes that were actually
					// written, and rewind offsets as needed.
					notWritten := int64(len(wbuf))
					readN -= notWritten
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

			total += readN
			if total == count {
				break
			}
			if err == nil && t.Interrupted() {
				err = linuxerr.ErrInterrupted
				break
			}
			if linuxerr.Equals(linuxerr.ErrWouldBlock, err) && !nonBlock {
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

	if total != 0 {
		if err != nil && err != io.EOF && !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			// If a partial write is completed, the error is dropped. Log it here.
			log.Debugf("sendfile completed a partial write with error: %v", err)
			err = nil
		}
	}

	// We can only pass a single file to handleIOError, so pick inFile arbitrarily.
	// This is used only for debugging purposes.
	return uintptr(total), nil, HandleIOError(t, total != 0, err, linuxerr.ERESTARTSYS, "sendfile", inFile)
}

// copyFileRangeBufSize is the size of the transient buffer used to move bytes
// between the input and output files in copy_file_range(2).
const copyFileRangeBufSize = 64 << 10 // 64 KB

// copyFileRangeStat returns the stat of fd for copy_file_range, rejecting
// directories with EISDIR and non-regular files with EINVAL.
func copyFileRangeStat(t *kernel.Task, fd *vfs.FileDescription) (linux.Statx, error) {
	stat, err := fd.Stat(t, vfs.StatOptions{Mask: linux.STATX_TYPE | linux.STATX_INO | linux.STATX_SIZE})
	if err != nil {
		return stat, err
	}
	if stat.Mask&linux.STATX_TYPE == 0 {
		return stat, linuxerr.EINVAL
	}
	switch stat.Mode & linux.S_IFMT {
	case linux.S_IFREG:
		return stat, nil
	case linux.S_IFDIR:
		return stat, linuxerr.EISDIR
	default:
		return stat, linuxerr.EINVAL
	}
}

// CopyFileRange implements Linux syscall copy_file_range(2).
//
// Uses a bounded sentry buffer to perform a generic copy across any backing
// filesystem. Check ordering mirrors Linux fs/read_write.c.
func CopyFileRange(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	inOffsetAddr := args[1].Pointer()
	outFD := args[2].Int()
	outOffsetAddr := args[3].Pointer()
	// count is treated as unsigned.
	count := uint64(args[4].SizeT())
	flags := args[5].Uint()

	// Look up FDs first so bad FDs take precedence over invalid flags.
	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)

	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	// The flags argument must be zero.
	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Both descriptors must refer to regular files (directories return EISDIR).
	inStat, err := copyFileRangeStat(t, inFile)
	if err != nil {
		return 0, nil, err
	}
	outStat, err := copyFileRangeStat(t, outFile)
	if err != nil {
		return 0, nil, err
	}

	if !inFile.IsReadable() || !outFile.IsWritable() {
		return 0, nil, linuxerr.EBADF
	}
	// Append-only output returns EBADF.
	if outFile.StatusFlags()&linux.O_APPEND != 0 {
		return 0, nil, linuxerr.EBADF
	}

	// Copy in offsets if provided; negative offsets overflow later.
	inOffset := int64(-1)
	haveInOffset := inOffsetAddr != 0
	if haveInOffset {
		if inFile.Options().DenyPRead {
			return 0, nil, linuxerr.ESPIPE
		}
		var offsetP primitive.Int64
		if _, err := offsetP.CopyIn(t, inOffsetAddr); err != nil {
			return 0, nil, err
		}
		inOffset = int64(offsetP)
	}
	outOffset := int64(-1)
	haveOutOffset := outOffsetAddr != 0
	if haveOutOffset {
		if outFile.Options().DenyPWrite {
			return 0, nil, linuxerr.ESPIPE
		}
		var offsetP primitive.Int64
		if _, err := offsetP.CopyIn(t, outOffsetAddr); err != nil {
			return 0, nil, err
		}
		outOffset = int64(offsetP)
	}

	// Determine starting offsets.
	startIn, startOut := inOffset, outOffset
	if !haveInOffset {
		if startIn, err = inFile.Seek(t, 0, linux.SEEK_CUR); err != nil {
			return 0, nil, err
		}
	}
	if !haveOutOffset {
		if startOut, err = outFile.Seek(t, 0, linux.SEEK_CUR); err != nil {
			return 0, nil, err
		}
	}

	// Ensure ranges do not wrap.
	if uint64(startIn)+count < uint64(startIn) || uint64(startOut)+count < uint64(startOut) {
		return 0, nil, linuxerr.EOVERFLOW
	}
	// A zero count cannot wrap, so reject negative positions here.
	if startIn < 0 || startOut < 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Clamp count to remaining bytes before checking overlap.
	if inStat.Mask&linux.STATX_SIZE != 0 {
		if size := int64(inStat.Size); startIn >= size {
			count = 0
		} else if remaining := uint64(size - startIn); count > remaining {
			count = remaining
		}
	}
	if count > uint64(linux.MAX_RW_COUNT) {
		count = uint64(linux.MAX_RW_COUNT)
	}

	// Overlapping ranges within the same file are not permitted.
	if inStat.Mask&outStat.Mask&linux.STATX_INO != 0 &&
		inStat.Ino == outStat.Ino &&
		inStat.DevMajor == outStat.DevMajor &&
		inStat.DevMinor == outStat.DevMinor &&
		uint64(startOut)+count > uint64(startIn) && startOut < startIn+int64(count) {
		return 0, nil, linuxerr.EINVAL
	}

	if count == 0 {
		return 0, nil, nil
	}
	limit := int64(count)

	// Regular files do not block; no dualWaiter needed.
	var (
		total  int64
		cprErr error
	)
	bufBacking := make([]byte, min(limit, copyFileRangeBufSize))
	for total < limit {
		buf := bufBacking[:min(limit-total, int64(len(bufBacking)))]

		var readN int64
		if haveInOffset {
			readN, cprErr = inFile.PRead(t, usermem.BytesIOSequence(buf), inOffset, vfs.ReadOptions{})
		} else {
			readN, cprErr = inFile.Read(t, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		}
		if readN == 0 {
			// EOF or no progress.
			break
		}

		// Write all read bytes.
		var written int64
		for written < readN {
			var writeN int64
			if haveOutOffset {
				writeN, cprErr = outFile.PWrite(t, usermem.BytesIOSequence(buf[written:readN]), outOffset+written, vfs.WriteOptions{})
			} else {
				writeN, cprErr = outFile.Write(t, usermem.BytesIOSequence(buf[written:readN]), vfs.WriteOptions{})
			}
			written += writeN
			if cprErr != nil {
				break
			}
		}

		if notWritten := readN - written; notWritten > 0 && !haveInOffset {
			// Rewind unwritten bytes from the input file offset.
			if _, seekErr := inFile.Seek(t, -notWritten, linux.SEEK_CUR); seekErr != nil {
				log.Warningf("copy_file_range failed to roll back input file offset: %v", seekErr)
			}
		}
		if haveInOffset {
			inOffset += written
		}
		if haveOutOffset {
			outOffset += written
		}
		total += written

		if written < readN {
			break
		}
		if cprErr == nil && t.Interrupted() {
			cprErr = linuxerr.ErrInterrupted
			break
		}
		if cprErr != nil {
			break
		}
	}

	// Copy out the updated offsets.
	if haveInOffset {
		offsetP := primitive.Int64(inOffset)
		if _, err := offsetP.CopyOut(t, inOffsetAddr); err != nil {
			return 0, nil, err
		}
	}
	if haveOutOffset {
		offsetP := primitive.Int64(outOffset)
		if _, err := offsetP.CopyOut(t, outOffsetAddr); err != nil {
			return 0, nil, err
		}
	}

	if total != 0 && cprErr != nil && cprErr != io.EOF && !linuxerr.Equals(linuxerr.ErrWouldBlock, cprErr) {
		// A partial copy succeeded, so report it rather than the error.
		log.Debugf("copy_file_range completed a partial copy with error: %v", cprErr)
		cprErr = nil
	}

	// We can only pass a single file to HandleIOError, so pick inFile
	// arbitrarily. This is used only for debugging purposes.
	return uintptr(total), nil, HandleIOError(t, total != 0, cprErr, linuxerr.ERESTARTSYS, "copy_file_range", inFile)
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
			dw.inW, dw.inCh = waiter.NewChannelEntry(eventMaskRead)
			if err := dw.inFile.EventRegister(&dw.inW); err != nil {
				return err
			}
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
	// Don't bother checking readiness of the outFile, because it's not a
	// guarantee that it won't return EWOULDBLOCK. Both pipes and eventfds
	// can be "ready" but will reject writes of certain sizes with
	// EWOULDBLOCK. See b/172075629, b/170743336.
	if dw.outCh == nil {
		dw.outW, dw.outCh = waiter.NewChannelEntry(eventMaskWrite)
		if err := dw.outFile.EventRegister(&dw.outW); err != nil {
			return err
		}
		// We might be ready to write now. Try again before blocking.
		return nil
	}
	return t.Block(dw.outCh)
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
