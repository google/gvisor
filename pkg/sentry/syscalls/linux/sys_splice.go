// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Splice implements linux syscall splice(2).
func Splice(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fdIn := kdefs.FD(args[0].Int())
	offIn := args[1].Pointer()
	fdOut := kdefs.FD(args[2].Int())
	offOut := args[3].Pointer()
	size := int64(args[4].SizeT())
	flags := uint(args[5].Uint())

	fileIn := t.FDMap().GetFile(fdIn)
	if fileIn == nil {
		return 0, nil, syserror.EBADF
	}
	defer fileIn.DecRef()
	fileOut := t.FDMap().GetFile(fdOut)
	if fileOut == nil {
		return 0, nil, syserror.EBADF
	}
	defer fileOut.DecRef()

	// Check for whether we have pipes.
	ipipe := fs.IsPipe(fileIn.Dirent.Inode.StableAttr)
	opipe := fs.IsPipe(fileOut.Dirent.Inode.StableAttr)
	if (ipipe && offIn != 0) || (opipe && offOut != 0) {
		return 0, nil, syserror.ESPIPE
	}

	// Check if both file descriptors are pipes.
	if ipipe && opipe {
		var readPipe *pipe.Pipe
		switch p := fileIn.FileOperations.(type) {
		case *pipe.Reader:
			readPipe = p.ReaderWriter.Pipe
		case *pipe.ReaderWriter:
			readPipe = p.Pipe
		default:
			return 0, nil, syserror.EBADF
		}
		var writePipe *pipe.Pipe
		switch p := fileOut.FileOperations.(type) {
		case *pipe.Writer:
			writePipe = p.ReaderWriter.Pipe
		case *pipe.ReaderWriter:
			writePipe = p.Pipe
		default:
			return 0, nil, syserror.EBADF
		}

		// Splicing with two ends of the same pipe is not allowed.
		if readPipe == writePipe {
			return 0, nil, syserror.EINVAL
		}
		spliced, err := splicePipeToPipe(t, fileIn, fileOut, size, flags)
		if err != nil {
			return 0, nil, err
		}
		return uintptr(spliced), nil, nil
	}

	// Check if the file descriptor that contains the data to move is a pipe.
	if ipipe {
		flagsOut := fileOut.Flags()
		offset := uint64(fileOut.Offset())

		// If there is an offset for the file, ensure the file has the Pwrite flag.
		if offOut != 0 {
			if !flagsOut.Pwrite {
				return 0, nil, syserror.EINVAL
			}
			if _, err := t.CopyIn(offOut, &offset); err != nil {
				return 0, nil, err
			}
		}

		if !flagsOut.Write {
			return 0, nil, syserror.EBADF
		}

		if flagsOut.Append {
			return 0, nil, syserror.EINVAL
		}

		switch fileIn.FileOperations.(type) {
		case *pipe.Reader, *pipe.ReaderWriter:
			// If the pipe in is a Reader or ReaderWriter, we can continue.
		default:
			return 0, nil, syserror.EBADF
		}
		spliced, err := spliceWrite(t, fileIn, fileOut, size, offset, flags)
		if err != nil {
			return 0, nil, err
		}

		// Make sure value that offset points to is updated.
		if offOut == 0 {
			fileOut.Seek(t, fs.SeekSet, spliced+int64(offset))
		} else if _, err := t.CopyOut(offOut, spliced+int64(offset)); err != nil {
			return 0, nil, err
		}
		return uintptr(spliced), nil, nil
	}

	// Check if the file descriptor that the data will be moved to is a pipe.
	if opipe {
		flagsIn := fileIn.Flags()
		offset := uint64(fileIn.Offset())

		// If there is an offset for the file, ensure the file has the Pread flag.
		if offIn != 0 {
			if !flagsIn.Pread {
				return 0, nil, syserror.EINVAL
			}
			if _, err := t.CopyIn(offIn, &offset); err != nil {
				return 0, nil, err
			}
		}

		if !flagsIn.Read {
			return 0, nil, syserror.EBADF
		}

		switch fileOut.FileOperations.(type) {
		case *pipe.Writer, *pipe.ReaderWriter:
			// If the pipe out is a Writer or ReaderWriter, we can continue.
		default:
			return 0, nil, syserror.EBADF
		}
		spliced, err := spliceRead(t, fileIn, fileOut, size, offset, flags)
		if err != nil {
			return 0, nil, err
		}

		// Make sure value that offset points to is updated.
		if offIn == 0 {
			fileOut.Seek(t, fs.SeekSet, spliced+int64(offset))
		} else if _, err := t.CopyOut(offIn, spliced+int64(offset)); err != nil {
			return 0, nil, err
		}
		return uintptr(spliced), nil, nil
	}

	// Splice requires one of the file descriptors to be a pipe.
	return 0, nil, syserror.EINVAL
}

// splicePipeToPipe moves data from one pipe to another pipe.
// TODO: Implement with zero copy movement/without copying between
// user and kernel address spaces.
func splicePipeToPipe(t *kernel.Task, inPipe *fs.File, outPipe *fs.File, size int64, flags uint) (int64, error) {
	w := &fs.FileWriter{t, outPipe}
	if flags == linux.SPLICE_F_NONBLOCK {
		r := &io.LimitedReader{R: &fs.FileReader{t, inPipe}, N: size}
		return io.Copy(w, r)
	}
	var n int64
	for read := int64(0); read < size; {
		var err error
		r := &io.LimitedReader{R: &fs.FileReader{t, inPipe}, N: size}
		n, err = io.Copy(w, r)
		if err != nil && err != syserror.ErrWouldBlock {
			return 0, err
		}
		read += n
	}
	return n, nil
}

// spliceRead moves data from a file to a pipe.
// TODO: Implement with zero copy movement/without copying between
// user and kernel address spaces.
func spliceRead(t *kernel.Task, inFile *fs.File, outPipe *fs.File, size int64, offset uint64, flags uint) (int64, error) {
	w := &fs.FileWriter{t, outPipe}
	if flags == linux.SPLICE_F_NONBLOCK {
		r := io.NewSectionReader(&fs.FileReader{t, inFile}, int64(offset), size)
		return io.Copy(w, r)
	}
	var n int64
	for read := int64(0); read < size; {
		r := io.NewSectionReader(&fs.FileReader{t, inFile}, int64(offset), size)
		var err error
		n, err = io.Copy(w, r)
		if err != nil && err != syserror.ErrWouldBlock {
			return 0, err
		}
		read += n
	}
	return n, nil
}

// offsetWriter implements io.Writer on a section of an underlying
// WriterAt starting from the offset and ending at the limit.
type offsetWriter struct {
	w     io.WriterAt
	off   int64
	limit int64
}

// Write implements io.Writer.Write and writes the content of the offsetWriter
// starting at the offset and ending at the limit into the given buffer.
func (o *offsetWriter) Write(p []byte) (n int, err error) {
	if o.off >= o.limit {
		return 0, io.EOF
	}
	if max := o.limit - o.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = o.w.WriteAt(p, o.off)
	o.off += int64(n)
	return n, err
}

// spliceWrite moves data from a pipe to a file.
// TODO: Implement with zero copy movement/without copying between
// user and kernel address spaces.
func spliceWrite(t *kernel.Task, inPipe *fs.File, outFile *fs.File, size int64, offset uint64, flags uint) (int64, error) {
	w := &offsetWriter{&fs.FileWriter{t, outFile}, int64(offset), int64(offset) + size}
	if flags == linux.SPLICE_F_NONBLOCK {
		r := &io.LimitedReader{R: &fs.FileReader{t, inPipe}, N: size}
		return io.Copy(w, r)
	}
	var n int64
	for read := int64(0); read < size; {
		var err error
		r := &io.LimitedReader{R: &fs.FileReader{t, inPipe}, N: size}
		n, err = io.Copy(w, r)
		if err != nil && err != syserror.ErrWouldBlock {
			return 0, err
		}
		read += n
	}
	return n, nil
}
