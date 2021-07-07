// Copyright 2018 The gVisor Authors.
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

package fdpipe

import (
	"bytes"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/usermem"
)

func singlePipeFD() (int, error) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		return -1, err
	}
	unix.Close(fds[1])
	return fds[0], nil
}

func singleDirFD() (int, error) {
	return unix.Open(os.TempDir(), unix.O_RDONLY, 0666)
}

func mockPipeDirent(t *testing.T) *fs.Dirent {
	ctx := contexttest.Context(t)
	node := fs.NewMockInodeOperations(ctx)
	node.UAttr = fs.UnstableAttr{
		Perms: fs.FilePermissions{
			User: fs.PermMask{Read: true, Write: true},
		},
	}
	inode := fs.NewInode(ctx, node, fs.NewMockMountSource(nil), fs.StableAttr{
		Type:      fs.Pipe,
		BlockSize: hostarch.PageSize,
	})
	return fs.NewDirent(ctx, inode, "")
}

func TestNewPipe(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// getfd generates the fd to pass to newPipeOperations.
		getfd func() (int, error)

		// flags are the fs.FileFlags passed to newPipeOperations.
		flags fs.FileFlags

		// readAheadBuffer is the buffer passed to newPipeOperations.
		readAheadBuffer []byte

		// err is the expected error.
		err error
	}{
		{
			desc:  "Cannot make new pipe from bad fd",
			getfd: func() (int, error) { return -1, nil },
			err:   unix.EINVAL,
		},
		{
			desc:  "Cannot make new pipe from non-pipe fd",
			getfd: singleDirFD,
			err:   unix.EINVAL,
		},
		{
			desc:            "Can make new pipe from pipe fd",
			getfd:           singlePipeFD,
			flags:           fs.FileFlags{Read: true},
			readAheadBuffer: []byte("hello"),
		},
	} {
		gfd, err := test.getfd()
		if err != nil {
			t.Errorf("%s: getfd got (%d, %v), want (fd, nil)", test.desc, gfd, err)
			continue
		}
		f := fd.New(gfd)

		ctx := contexttest.Context(t)
		p, err := newPipeOperations(ctx, nil, test.flags, f, test.readAheadBuffer)
		if p != nil {
			// This is necessary to remove the fd from the global fd notifier.
			defer p.Release(ctx)
		} else {
			// If there is no p to DecRef on, because newPipeOperations failed, then the
			// file still needs to be closed.
			defer f.Close()
		}

		if err != test.err {
			t.Errorf("%s: got error %v, want %v", test.desc, err, test.err)
			continue
		}
		// Check the state of the pipe given that it was successfully opened.
		if err == nil {
			if p == nil {
				t.Errorf("%s: got nil pipe and nil error, want (pipe, nil)", test.desc)
				continue
			}
			if flags := p.flags; test.flags != flags {
				t.Errorf("%s: got file flags %v, want %v", test.desc, flags, test.flags)
				continue
			}
			if len(test.readAheadBuffer) != len(p.readAheadBuffer) {
				t.Errorf("%s: got read ahead buffer length %d, want %d", test.desc, len(p.readAheadBuffer), len(test.readAheadBuffer))
				continue
			}
			fileFlags, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(p.file.FD()), unix.F_GETFL, 0)
			if errno != 0 {
				t.Errorf("%s: failed to get file flags for fd %d, got %v, want 0", test.desc, p.file.FD(), errno)
				continue
			}
			if fileFlags&unix.O_NONBLOCK == 0 {
				t.Errorf("%s: pipe is blocking, expected non-blocking", test.desc)
				continue
			}
			if !fdnotifier.HasFD(int32(f.FD())) {
				t.Errorf("%s: pipe fd %d is not registered for events", test.desc, f.FD())
			}
		}
	}
}

func TestPipeDestruction(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("failed to create pipes: got %v, want nil", err)
	}
	f := fd.New(fds[0])

	// We don't care about the other end, just use the read end.
	unix.Close(fds[1])

	// Test the read end, but it doesn't really matter which.
	ctx := contexttest.Context(t)
	p, err := newPipeOperations(ctx, nil, fs.FileFlags{Read: true}, f, nil)
	if err != nil {
		f.Close()
		t.Fatalf("newPipeOperations got error %v, want nil", err)
	}
	// Drop our only reference, which should trigger the destructor.
	p.Release(ctx)

	if fdnotifier.HasFD(int32(fds[0])) {
		t.Fatalf("after DecRef fdnotifier has fd %d, want no longer registered", fds[0])
	}
	if p.file != nil {
		t.Errorf("after DecRef got file, want nil")
	}
}

type Seek struct{}

type ReadDir struct{}

type Writev struct {
	Src usermem.IOSequence
}

type Readv struct {
	Dst usermem.IOSequence
}

type Fsync struct{}

func TestPipeRequest(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// request to execute.
		context interface{}

		// flags determines whether to use the read or write end
		// of the pipe, for this test it can only be Read or Write.
		flags fs.FileFlags

		// keepOpenPartner if false closes the other end of the pipe,
		// otherwise this is delayed until the end of the test.
		keepOpenPartner bool

		// expected error
		err error
	}{
		{
			desc:    "ReadDir on pipe returns ENOTDIR",
			context: &ReadDir{},
			err:     linuxerr.ENOTDIR,
		},
		{
			desc:    "Fsync on pipe returns EINVAL",
			context: &Fsync{},
			err:     linuxerr.EINVAL,
		},
		{
			desc:    "Seek on pipe returns ESPIPE",
			context: &Seek{},
			err:     linuxerr.ESPIPE,
		},
		{
			desc:    "Readv on pipe from empty buffer returns nil",
			context: &Readv{Dst: usermem.BytesIOSequence(nil)},
			flags:   fs.FileFlags{Read: true},
		},
		{
			desc:    "Readv on pipe from non-empty buffer and closed partner returns EOF",
			context: &Readv{Dst: usermem.BytesIOSequence(make([]byte, 10))},
			flags:   fs.FileFlags{Read: true},
			err:     io.EOF,
		},
		{
			desc:            "Readv on pipe from non-empty buffer and open partner returns EWOULDBLOCK",
			context:         &Readv{Dst: usermem.BytesIOSequence(make([]byte, 10))},
			flags:           fs.FileFlags{Read: true},
			keepOpenPartner: true,
			err:             linuxerr.ErrWouldBlock,
		},
		{
			desc:    "Writev on pipe from empty buffer returns nil",
			context: &Writev{Src: usermem.BytesIOSequence(nil)},
			flags:   fs.FileFlags{Write: true},
		},
		{
			desc:    "Writev on pipe from non-empty buffer and closed partner returns EPIPE",
			context: &Writev{Src: usermem.BytesIOSequence([]byte("hello"))},
			flags:   fs.FileFlags{Write: true},
			err:     linuxerr.EPIPE,
		},
		{
			desc:            "Writev on pipe from non-empty buffer and open partner succeeds",
			context:         &Writev{Src: usermem.BytesIOSequence([]byte("hello"))},
			flags:           fs.FileFlags{Write: true},
			keepOpenPartner: true,
		},
	} {
		if test.flags.Read && test.flags.Write {
			panic("both read and write not supported for this test")
		}

		fds := make([]int, 2)
		if err := unix.Pipe(fds); err != nil {
			t.Errorf("%s: failed to create pipes: got %v, want nil", test.desc, err)
			continue
		}

		// Configure the fd and partner fd based on the file flags.
		testFd, partnerFd := fds[0], fds[1]
		if test.flags.Write {
			testFd, partnerFd = fds[1], fds[0]
		}

		// Configure closing the fds.
		if test.keepOpenPartner {
			defer unix.Close(partnerFd)
		} else {
			unix.Close(partnerFd)
		}

		// Create the pipe.
		ctx := contexttest.Context(t)
		p, err := newPipeOperations(ctx, nil, test.flags, fd.New(testFd), nil)
		if err != nil {
			t.Fatalf("%s: newPipeOperations got error %v, want nil", test.desc, err)
		}
		defer p.Release(ctx)

		inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{Type: fs.Pipe})
		file := fs.NewFile(ctx, fs.NewDirent(ctx, inode, "pipe"), fs.FileFlags{Read: true}, p)

		// Issue request via the appropriate function.
		switch c := test.context.(type) {
		case *Seek:
			_, err = p.Seek(ctx, file, 0, 0)
		case *ReadDir:
			_, err = p.Readdir(ctx, file, nil)
		case *Readv:
			_, err = p.Read(ctx, file, c.Dst, 0)
		case *Writev:
			_, err = p.Write(ctx, file, c.Src, 0)
		case *Fsync:
			err = p.Fsync(ctx, file, 0, fs.FileMaxOffset, fs.SyncAll)
		default:
			t.Errorf("%s: unknown request type %T", test.desc, test.context)
		}

		if linuxErr, ok := test.err.(*errors.Error); ok {
			if !linuxerr.Equals(linuxErr, unwrapError(err)) {
				t.Errorf("%s: got error %v, want %v", test.desc, err, test.err)
			}
		} else if test.err != unwrapError(err) {
			t.Errorf("%s: got error %v, want %v", test.desc, err, test.err)
		}
	}
}

func TestPipeReadAheadBuffer(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("failed to create pipes: got %v, want nil", err)
	}
	rfile := fd.New(fds[0])

	// Eventually close the write end, which is not wrapped in a pipe object.
	defer unix.Close(fds[1])

	// Write some bytes to this end.
	data := []byte("world")
	if n, err := unix.Write(fds[1], data); n != len(data) || err != nil {
		rfile.Close()
		t.Fatalf("write to pipe got (%d, %v), want (%d, nil)", n, err, len(data))
	}
	// Close the write end immediately, we don't care about it.

	buffered := []byte("hello ")
	ctx := contexttest.Context(t)
	p, err := newPipeOperations(ctx, nil, fs.FileFlags{Read: true}, rfile, buffered)
	if err != nil {
		rfile.Close()
		t.Fatalf("newPipeOperations got error %v, want nil", err)
	}
	defer p.Release(ctx)

	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{
		Type: fs.Pipe,
	})
	file := fs.NewFile(ctx, fs.NewDirent(ctx, inode, "pipe"), fs.FileFlags{Read: true}, p)

	// In total we expect to read data + buffered.
	total := append(buffered, data...)

	buf := make([]byte, len(total))
	iov := usermem.BytesIOSequence(buf)
	n, err := p.Read(contexttest.Context(t), file, iov, 0)
	if err != nil {
		t.Fatalf("read request got error %v, want nil", err)
	}
	if n != int64(len(total)) {
		t.Fatalf("read request got %d bytes, want %d", n, len(total))
	}
	if !bytes.Equal(buf, total) {
		t.Errorf("read request got bytes [%v], want [%v]", buf, total)
	}
}

// This is very important for pipes in general because they can return
// EWOULDBLOCK and for those that block they must continue until they have read
// all of the data (and report it as such).
func TestPipeReadsAccumulate(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("failed to create pipes: got %v, want nil", err)
	}
	rfile := fd.New(fds[0])

	// Eventually close the write end, it doesn't depend on a pipe object.
	defer unix.Close(fds[1])

	// Get a new read only pipe reference.
	ctx := contexttest.Context(t)
	p, err := newPipeOperations(ctx, nil, fs.FileFlags{Read: true}, rfile, nil)
	if err != nil {
		rfile.Close()
		t.Fatalf("newPipeOperations got error %v, want nil", err)
	}
	// Don't forget to remove the fd from the fd notifier.  Otherwise other tests will
	// likely be borked, because it's global :(
	defer p.Release(ctx)

	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{
		Type: fs.Pipe,
	})
	file := fs.NewFile(ctx, fs.NewDirent(ctx, inode, "pipe"), fs.FileFlags{Read: true}, p)

	// Write some some bytes to the pipe.
	data := []byte("some message")
	if n, err := unix.Write(fds[1], data); n != len(data) || err != nil {
		t.Fatalf("write to pipe got (%d, %v), want (%d, nil)", n, err, len(data))
	}

	// Construct a segment vec that is a bit more than we have written so we
	// trigger an EWOULDBLOCK.
	wantBytes := len(data) + 1
	readBuffer := make([]byte, wantBytes)
	iov := usermem.BytesIOSequence(readBuffer)
	n, err := p.Read(ctx, file, iov, 0)
	total := n
	iov = iov.DropFirst64(n)
	if err != linuxerr.ErrWouldBlock {
		t.Fatalf("Readv got error %v, want %v", err, linuxerr.ErrWouldBlock)
	}

	// Write a few more bytes to allow us to read more/accumulate.
	extra := []byte("extra")
	if n, err := unix.Write(fds[1], extra); n != len(extra) || err != nil {
		t.Fatalf("write to pipe got (%d, %v), want (%d, nil)", n, err, len(extra))
	}

	// This time, using the same request, we should not block.
	n, err = p.Read(ctx, file, iov, 0)
	total += n
	if err != nil {
		t.Fatalf("Readv got error %v, want nil", err)
	}

	// Assert that the result we got back is cumulative.
	if total != int64(wantBytes) {
		t.Fatalf("Readv sequence got %d bytes, want %d", total, wantBytes)
	}

	if want := append(data, extra[0]); !bytes.Equal(readBuffer, want) {
		t.Errorf("Readv sequence got %v, want %v", readBuffer, want)
	}
}

// Same as TestReadsAccumulate.
func TestPipeWritesAccumulate(t *testing.T) {
	fds := make([]int, 2)
	if err := unix.Pipe(fds); err != nil {
		t.Fatalf("failed to create pipes: got %v, want nil", err)
	}
	wfile := fd.New(fds[1])

	// Eventually close the read end, it doesn't depend on a pipe object.
	defer unix.Close(fds[0])

	// Get a new write only pipe reference.
	ctx := contexttest.Context(t)
	p, err := newPipeOperations(ctx, nil, fs.FileFlags{Write: true}, wfile, nil)
	if err != nil {
		wfile.Close()
		t.Fatalf("newPipeOperations got error %v, want nil", err)
	}
	// Don't forget to remove the fd from the fd notifier. Otherwise other tests
	// will likely be borked, because it's global :(
	defer p.Release(ctx)

	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{
		Type: fs.Pipe,
	})
	file := fs.NewFile(ctx, fs.NewDirent(ctx, inode, "pipe"), fs.FileFlags{Read: true}, p)

	pipeSize, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(wfile.FD()), unix.F_GETPIPE_SZ, 0)
	if errno != 0 {
		t.Fatalf("fcntl(F_GETPIPE_SZ) failed: %v", errno)
	}
	t.Logf("Pipe buffer size: %d", pipeSize)

	// Construct a segment vec that is larger than the pipe size to trigger an
	// EWOULDBLOCK.
	wantBytes := int(pipeSize) * 2
	writeBuffer := make([]byte, wantBytes)
	for i := 0; i < wantBytes; i++ {
		writeBuffer[i] = 'a'
	}
	iov := usermem.BytesIOSequence(writeBuffer)
	n, err := p.Write(ctx, file, iov, 0)
	if err != linuxerr.ErrWouldBlock {
		t.Fatalf("Writev got error %v, want %v", err, linuxerr.ErrWouldBlock)
	}
	if n != int64(pipeSize) {
		t.Fatalf("Writev partial write, got: %v, want %v", n, pipeSize)
	}
	total := n
	iov = iov.DropFirst64(n)

	// Read the entire pipe buf size to make space for the second half.
	readBuffer := make([]byte, n)
	if n, err := unix.Read(fds[0], readBuffer); n != len(readBuffer) || err != nil {
		t.Fatalf("write to pipe got (%d, %v), want (%d, nil)", n, err, len(readBuffer))
	}
	if !bytes.Equal(readBuffer, writeBuffer[:len(readBuffer)]) {
		t.Fatalf("wrong data read from pipe, got: %v, want: %v", readBuffer, writeBuffer)
	}

	// This time we should not block.
	n, err = p.Write(ctx, file, iov, 0)
	if err != nil {
		t.Fatalf("Writev got error %v, want nil", err)
	}
	if n != int64(pipeSize) {
		t.Fatalf("Writev partial write, got: %v, want %v", n, pipeSize)
	}
	total += n

	// Assert that the result we got back is cumulative.
	if total != int64(wantBytes) {
		t.Fatalf("Writev sequence got %d bytes, want %d", total, wantBytes)
	}
}
