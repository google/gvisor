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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/waiter"
)

// doSplice implements a blocking splice operation.
func doSplice(t *kernel.Task, outFile, inFile *fs.File, opts fs.SpliceOpts, nonBlocking bool) (int64, error) {
	if opts.Length < 0 || opts.SrcStart < 0 || opts.DstStart < 0 || (opts.SrcStart+opts.Length < 0) {
		return 0, linuxerr.EINVAL
	}
	if opts.Length == 0 {
		return 0, nil
	}
	if opts.Length > int64(kernel.MAX_RW_COUNT) {
		opts.Length = int64(kernel.MAX_RW_COUNT)
	}

	var (
		n     int64
		err   error
		inCh  chan struct{}
		outCh chan struct{}
	)

	for {
		n, err = fs.Splice(t, outFile, inFile, opts)
		if n != 0 || err != linuxerr.ErrWouldBlock {
			break
		} else if err == linuxerr.ErrWouldBlock && nonBlocking {
			break
		}

		// Note that the blocking behavior here is a bit different than the
		// normal pattern. Because we need to have both data to read and data
		// to write simultaneously, we actually explicitly block on both of
		// these cases in turn before returning to the splice operation.
		if inFile.Readiness(EventMaskRead) == 0 {
			if inCh == nil {
				var e waiter.Entry
				e, inCh = waiter.NewChannelEntry(EventMaskRead)
				inFile.EventRegister(&e)
				defer inFile.EventUnregister(&e)
				// Need to refresh readiness.
				continue
			}
			if err = t.Block(inCh); err != nil {
				break
			}
		}
		// Don't bother checking readiness of the outFile, because it's not a
		// guarantee that it won't return EWOULDBLOCK. Both pipes and eventfds
		// can be "ready" but will reject writes of certain sizes with
		// EWOULDBLOCK.
		if outCh == nil {
			var e waiter.Entry
			e, outCh = waiter.NewChannelEntry(EventMaskWrite)
			outFile.EventRegister(&e)
			defer outFile.EventUnregister(&e)
			// We might be ready to write now. Try again before
			// blocking.
			continue
		}
		if err = t.Block(outCh); err != nil {
			break
		}
	}

	if n > 0 {
		// On Linux, inotify behavior is not very consistent with splice(2). We try
		// our best to emulate Linux for very basic calls to splice, where for some
		// reason, events are generated for output files, but not input files.
		outFile.Dirent.InotifyEvent(linux.IN_MODIFY, 0)
	}
	return n, err
}

// Sendfile implements linux system call sendfile(2).
func Sendfile(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	outFD := args[0].Int()
	inFD := args[1].Int()
	offsetAddr := args[2].Pointer()
	count := int64(args[3].SizeT())

	// Get files.
	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)

	if !inFile.Flags().Read {
		return 0, nil, linuxerr.EBADF
	}

	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	if !outFile.Flags().Write {
		return 0, nil, linuxerr.EBADF
	}

	// Verify that the outfile Append flag is not set.
	if outFile.Flags().Append {
		return 0, nil, linuxerr.EINVAL
	}

	// Verify that we have a regular infile. This is a requirement; the
	// same check appears in Linux (fs/splice.c:splice_direct_to_actor).
	if !fs.IsRegular(inFile.Dirent.Inode.StableAttr) {
		return 0, nil, linuxerr.EINVAL
	}

	var (
		n   int64
		err error
	)
	if offsetAddr != 0 {
		// Verify that when offset address is not null, infile must be
		// seekable. The fs.Splice routine itself validates basic read.
		if !inFile.Flags().Pread {
			return 0, nil, linuxerr.ESPIPE
		}

		// Copy in the offset.
		var offset int64
		if _, err := primitive.CopyInt64In(t, offsetAddr, &offset); err != nil {
			return 0, nil, err
		}

		// Do the splice.
		n, err = doSplice(t, outFile, inFile, fs.SpliceOpts{
			Length:    count,
			SrcOffset: true,
			SrcStart:  int64(offset),
		}, outFile.Flags().NonBlocking)

		// Copy out the new offset.
		if _, err := primitive.CopyInt64Out(t, offsetAddr, offset+n); err != nil {
			return 0, nil, err
		}
	} else {
		// Send data using splice.
		n, err = doSplice(t, outFile, inFile, fs.SpliceOpts{
			Length: count,
		}, outFile.Flags().NonBlocking)
	}

	// Sendfile can't lose any data because inFD is always a regual file.
	if n != 0 {
		err = nil
	}

	// We can only pass a single file to handleIOError, so pick inFile
	// arbitrarily. This is used only for debugging purposes.
	return uintptr(n), nil, handleIOError(t, false, err, linuxerr.ERESTARTSYS, "sendfile", inFile)
}

// Splice implements splice(2).
func Splice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	inOffset := args[1].Pointer()
	outFD := args[2].Int()
	outOffset := args[3].Pointer()
	count := int64(args[4].SizeT())
	flags := args[5].Int()

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get files.
	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)

	// The operation is non-blocking if anything is non-blocking.
	//
	// N.B. This is a rather simplistic heuristic that avoids some
	// poor edge case behavior since the exact semantics here are
	// underspecified and vary between versions of Linux itself.
	nonBlock := inFile.Flags().NonBlocking || outFile.Flags().NonBlocking || (flags&linux.SPLICE_F_NONBLOCK != 0)

	// Construct our options.
	//
	// Note that exactly one of the underlying buffers must be a pipe. We
	// don't actually have this constraint internally, but we enforce it
	// for the semantics of the call.
	opts := fs.SpliceOpts{
		Length: count,
	}
	inFileAttr := inFile.Dirent.Inode.StableAttr
	outFileAttr := outFile.Dirent.Inode.StableAttr
	switch {
	case fs.IsPipe(inFileAttr) && !fs.IsPipe(outFileAttr):
		if inOffset != 0 {
			return 0, nil, linuxerr.ESPIPE
		}
		if outOffset != 0 {
			if !outFile.Flags().Pwrite {
				return 0, nil, linuxerr.EINVAL
			}

			var offset int64
			if _, err := primitive.CopyInt64In(t, outOffset, &offset); err != nil {
				return 0, nil, err
			}

			// Use the destination offset.
			opts.DstOffset = true
			opts.DstStart = offset
		}
	case !fs.IsPipe(inFileAttr) && fs.IsPipe(outFileAttr):
		if outOffset != 0 {
			return 0, nil, linuxerr.ESPIPE
		}
		if inOffset != 0 {
			if !inFile.Flags().Pread {
				return 0, nil, linuxerr.EINVAL
			}

			var offset int64
			if _, err := primitive.CopyInt64In(t, inOffset, &offset); err != nil {
				return 0, nil, err
			}

			// Use the source offset.
			opts.SrcOffset = true
			opts.SrcStart = offset
		}
	case fs.IsPipe(inFileAttr) && fs.IsPipe(outFileAttr):
		if inOffset != 0 || outOffset != 0 {
			return 0, nil, linuxerr.ESPIPE
		}

		// We may not refer to the same pipe; otherwise it's a continuous loop.
		if inFileAttr.InodeID == outFileAttr.InodeID {
			return 0, nil, linuxerr.EINVAL
		}
	default:
		return 0, nil, linuxerr.EINVAL
	}

	// Splice data.
	n, err := doSplice(t, outFile, inFile, opts, nonBlock)

	// Special files can have additional requirements for granularity.  For
	// example, read from eventfd returns EINVAL if a size is less 8 bytes.
	// Inotify is another example. read will return EINVAL is a buffer is
	// too small to return the next event, but a size of an event isn't
	// fixed, it is sizeof(struct inotify_event) + {NAME_LEN} + 1.
	if n != 0 && err != nil && (fs.IsAnonymous(inFileAttr) || fs.IsAnonymous(outFileAttr)) {
		err = nil
	}

	// See above; inFile is chosen arbitrarily here.
	return uintptr(n), nil, handleIOError(t, n != 0, err, linuxerr.ERESTARTSYS, "splice", inFile)
}

// Tee imlements tee(2).
func Tee(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := args[0].Int()
	outFD := args[1].Int()
	count := int64(args[2].SizeT())
	flags := args[3].Int()

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, linuxerr.EINVAL
	}

	// Get files.
	outFile := t.GetFile(outFD)
	if outFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer outFile.DecRef(t)

	inFile := t.GetFile(inFD)
	if inFile == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer inFile.DecRef(t)

	// All files must be pipes.
	if !fs.IsPipe(inFile.Dirent.Inode.StableAttr) || !fs.IsPipe(outFile.Dirent.Inode.StableAttr) {
		return 0, nil, linuxerr.EINVAL
	}

	// We may not refer to the same pipe; see above.
	if inFile.Dirent.Inode.StableAttr.InodeID == outFile.Dirent.Inode.StableAttr.InodeID {
		return 0, nil, linuxerr.EINVAL
	}

	// The operation is non-blocking if anything is non-blocking.
	nonBlock := inFile.Flags().NonBlocking || outFile.Flags().NonBlocking || (flags&linux.SPLICE_F_NONBLOCK != 0)

	// Splice data.
	n, err := doSplice(t, outFile, inFile, fs.SpliceOpts{
		Length: count,
		Dup:    true,
	}, nonBlock)

	// Tee doesn't change a state of inFD, so it can't lose any data.
	if n != 0 {
		err = nil
	}

	// See above; inFile is chosen arbitrarily here.
	return uintptr(n), nil, handleIOError(t, false, err, linuxerr.ERESTARTSYS, "tee", inFile)
}
