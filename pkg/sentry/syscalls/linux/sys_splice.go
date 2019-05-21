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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// doSplice implements a blocking splice operation.
func doSplice(t *kernel.Task, outFile, inFile *fs.File, opts fs.SpliceOpts, nonBlocking bool) (int64, error) {
	var (
		total int64
		n     int64
		err   error
		ch    chan struct{}
		inW   bool
		outW  bool
	)
	for opts.Length > 0 {
		n, err = fs.Splice(t, outFile, inFile, opts)
		opts.Length -= n
		total += n
		if err != syserror.ErrWouldBlock {
			break
		} else if err == syserror.ErrWouldBlock && nonBlocking {
			break
		}

		// Are we a registered waiter?
		if ch == nil {
			ch = make(chan struct{}, 1)
		}
		if !inW && inFile.Readiness(EventMaskRead) == 0 && !inFile.Flags().NonBlocking {
			w, _ := waiter.NewChannelEntry(ch)
			inFile.EventRegister(&w, EventMaskRead)
			defer inFile.EventUnregister(&w)
			inW = true // Registered.
		} else if !outW && outFile.Readiness(EventMaskWrite) == 0 && !outFile.Flags().NonBlocking {
			w, _ := waiter.NewChannelEntry(ch)
			outFile.EventRegister(&w, EventMaskWrite)
			defer outFile.EventUnregister(&w)
			outW = true // Registered.
		}

		// Was anything registered? If no, everything is non-blocking.
		if !inW && !outW {
			break
		}

		// Block until there's data.
		if err = t.Block(ch); err != nil {
			break
		}
	}

	return total, err
}

// Sendfile implements linux system call sendfile(2).
func Sendfile(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	outFD := kdefs.FD(args[0].Int())
	inFD := kdefs.FD(args[1].Int())
	offsetAddr := args[2].Pointer()
	count := int64(args[3].SizeT())

	// Don't send a negative number of bytes.
	if count < 0 {
		return 0, nil, syserror.EINVAL
	}

	// Get files.
	outFile := t.FDMap().GetFile(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef()

	inFile := t.FDMap().GetFile(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef()

	// Verify that the outfile Append flag is not set. Note that fs.Splice
	// itself validates that the output file is writable.
	if outFile.Flags().Append {
		return 0, nil, syserror.EBADF
	}

	// Verify that we have a regular infile. This is a requirement; the
	// same check appears in Linux (fs/splice.c:splice_direct_to_actor).
	if !fs.IsRegular(inFile.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.EINVAL
	}

	var (
		n   int64
		err error
	)
	if offsetAddr != 0 {
		// Verify that when offset address is not null, infile must be
		// seekable. The fs.Splice routine itself validates basic read.
		if !inFile.Flags().Pread {
			return 0, nil, syserror.ESPIPE
		}

		// Copy in the offset.
		var offset int64
		if _, err := t.CopyIn(offsetAddr, &offset); err != nil {
			return 0, nil, err
		}

		// The offset must be valid.
		if offset < 0 {
			return 0, nil, syserror.EINVAL
		}

		// Do the splice.
		n, err = doSplice(t, outFile, inFile, fs.SpliceOpts{
			Length:    count,
			SrcOffset: true,
			SrcStart:  offset,
		}, false)

		// Copy out the new offset.
		if _, err := t.CopyOut(offsetAddr, n+offset); err != nil {
			return 0, nil, err
		}
	} else {
		// Send data using splice.
		n, err = doSplice(t, outFile, inFile, fs.SpliceOpts{
			Length: count,
		}, false)
	}

	// We can only pass a single file to handleIOError, so pick inFile
	// arbitrarily. This is used only for debugging purposes.
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "sendfile", inFile)
}

// Splice implements splice(2).
func Splice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := kdefs.FD(args[0].Int())
	inOffset := args[1].Pointer()
	outFD := kdefs.FD(args[2].Int())
	outOffset := args[3].Pointer()
	count := int64(args[4].SizeT())
	flags := args[5].Int()

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	// Only non-blocking is meaningful. Note that unlike in Linux, this
	// flag is applied consistently. We will have either fully blocking or
	// non-blocking behavior below, regardless of the underlying files
	// being spliced to. It's unclear if this is a bug or not yet.
	nonBlocking := (flags & linux.SPLICE_F_NONBLOCK) != 0

	// Get files.
	outFile := t.FDMap().GetFile(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef()

	inFile := t.FDMap().GetFile(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef()

	// Construct our options.
	//
	// Note that exactly one of the underlying buffers must be a pipe. We
	// don't actually have this constraint internally, but we enforce it
	// for the semantics of the call.
	opts := fs.SpliceOpts{
		Length: count,
	}
	switch {
	case fs.IsPipe(inFile.Dirent.Inode.StableAttr) && !fs.IsPipe(outFile.Dirent.Inode.StableAttr):
		if inOffset != 0 {
			return 0, nil, syserror.ESPIPE
		}
		if outOffset != 0 {
			var offset int64
			if _, err := t.CopyIn(outOffset, &offset); err != nil {
				return 0, nil, err
			}
			// Use the destination offset.
			opts.DstOffset = true
			opts.DstStart = offset
		}
	case !fs.IsPipe(inFile.Dirent.Inode.StableAttr) && fs.IsPipe(outFile.Dirent.Inode.StableAttr):
		if outOffset != 0 {
			return 0, nil, syserror.ESPIPE
		}
		if inOffset != 0 {
			var offset int64
			if _, err := t.CopyIn(inOffset, &offset); err != nil {
				return 0, nil, err
			}
			// Use the source offset.
			opts.SrcOffset = true
			opts.SrcStart = offset
		}
	case fs.IsPipe(inFile.Dirent.Inode.StableAttr) && fs.IsPipe(outFile.Dirent.Inode.StableAttr):
		if inOffset != 0 || outOffset != 0 {
			return 0, nil, syserror.ESPIPE
		}
	default:
		return 0, nil, syserror.EINVAL
	}

	// We may not refer to the same pipe; otherwise it's a continuous loop.
	if inFile.Dirent.Inode.StableAttr.InodeID == outFile.Dirent.Inode.StableAttr.InodeID {
		return 0, nil, syserror.EINVAL
	}

	// Splice data.
	n, err := doSplice(t, outFile, inFile, opts, nonBlocking)

	// See above; inFile is chosen arbitrarily here.
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "splice", inFile)
}

// Tee imlements tee(2).
func Tee(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	inFD := kdefs.FD(args[0].Int())
	outFD := kdefs.FD(args[1].Int())
	count := int64(args[2].SizeT())
	flags := args[3].Int()

	// Check for invalid flags.
	if flags&^(linux.SPLICE_F_MOVE|linux.SPLICE_F_NONBLOCK|linux.SPLICE_F_MORE|linux.SPLICE_F_GIFT) != 0 {
		return 0, nil, syserror.EINVAL
	}

	// Only non-blocking is meaningful.
	nonBlocking := (flags & linux.SPLICE_F_NONBLOCK) != 0

	// Get files.
	outFile := t.FDMap().GetFile(outFD)
	if outFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer outFile.DecRef()

	inFile := t.FDMap().GetFile(inFD)
	if inFile == nil {
		return 0, nil, syserror.EBADF
	}
	defer inFile.DecRef()

	// All files must be pipes.
	if !fs.IsPipe(inFile.Dirent.Inode.StableAttr) || !fs.IsPipe(outFile.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.EINVAL
	}

	// We may not refer to the same pipe; see above.
	if inFile.Dirent.Inode.StableAttr.InodeID == outFile.Dirent.Inode.StableAttr.InodeID {
		return 0, nil, syserror.EINVAL
	}

	// Splice data.
	n, err := doSplice(t, outFile, inFile, fs.SpliceOpts{
		Length: count,
		Dup:    true,
	}, nonBlocking)

	// See above; inFile is chosen arbitrarily here.
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "tee", inFile)
}
