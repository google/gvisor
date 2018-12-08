// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

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

	// Verify that the outfile is writable.
	outFlags := outFile.Flags()
	if !outFlags.Write {
		return 0, nil, syserror.EBADF
	}

	// Verify that the outfile Append flag is not set. This is a constraint
	// imposed specifically by sendfile, the Splice implementation doesn't
	// actually care.
	if outFlags.Append {
		return 0, nil, syserror.EINVAL
	}

	// Verify that we have a regular infile; this is a constraint on the
	// sendfile system call, although fs.Splice doesn't actually care about
	// this.
	if !fs.IsRegular(inFile.Dirent.Inode.StableAttr) {
		return 0, nil, syserror.EINVAL
	}

	// Verify that the infile is readable.
	if !inFile.Flags().Read {
		return 0, nil, syserror.EBADF
	}

	// Setup for sending data.
	opts := fs.SpliceOpts{
		Length:    count,
		SrcOffset: offsetAddr != 0,
		DstOffset: false, // Always false for sendfile.
	}

	// Copy in the offset, if required.
	if opts.SrcOffset {
		// Verify that when offset address is not null, infile must be
		// seekable. This is required to call fs.Splice.
		if !inFile.Flags().Pread {
			return 0, nil, syserror.ESPIPE
		}

		// Copy in the offset.
		var offset int64
		if _, err := t.CopyIn(offsetAddr, &offset); err != nil {
			return 0, nil, err
		}

		// Set the offset to use.
		opts.SrcStart = offset
	}

	// Perform the splice.
	n, err := fs.Splice(t, outFile, inFile, opts)
	if err != nil {
		return 0, nil, err
	}
	if n > 0 && opts.SrcOffset {
		// Copy out the updated offset.
		offset := int64(opts.SrcStart) + n
		if _, err := t.CopyOut(offsetAddr, &offset); err != nil {
			return 0, nil, err
		}
	}

	// Return the result.
	return uintptr(n), nil, handleIOError(t, n != 0, err, kernel.ERESTARTSYS, "sendfile", inFile)
}

// Splice implements linux system call splice(2).
func Splice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.ENOSYS
}

// Tee implements linux system call tee(2).
func Tee(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.ENOSYS
}

// Vmsplice implements linux system call vmsplice(2).
func Vmsplice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, syserror.ENOSYS
}
