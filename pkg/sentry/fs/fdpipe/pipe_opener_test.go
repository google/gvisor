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
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

type hostOpener struct {
	name string
}

func (h *hostOpener) NonBlockingOpen(_ context.Context, p fs.PermMask) (*fd.FD, error) {
	var flags int
	switch {
	case p.Read && p.Write:
		flags = unix.O_RDWR
	case p.Write:
		flags = unix.O_WRONLY
	case p.Read:
		flags = unix.O_RDONLY
	default:
		return nil, unix.EINVAL
	}
	f, err := unix.Open(h.name, flags|unix.O_NONBLOCK, 0666)
	if err != nil {
		return nil, err
	}
	return fd.New(f), nil
}

func pipename() string {
	return fmt.Sprintf(path.Join(os.TempDir(), "test-named-pipe-%s"), uuid.New())
}

func mkpipe(name string) error {
	return unix.Mknod(name, unix.S_IFIFO|0666, 0)
}

func TestTryOpen(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// makePipe is true if the test case should create the pipe.
		makePipe bool

		// flags are the fs.FileFlags used to open the pipe.
		flags fs.FileFlags

		// expectFile is true if a fs.File is expected.
		expectFile bool

		// err is the expected error
		err error
	}{
		{
			desc:       "FileFlags lacking Read and Write are invalid",
			makePipe:   false,
			flags:      fs.FileFlags{}, /* bogus */
			expectFile: false,
			err:        unix.EINVAL,
		},
		{
			desc:       "NonBlocking Read only error returns immediately",
			makePipe:   false, /* causes the error */
			flags:      fs.FileFlags{Read: true, NonBlocking: true},
			expectFile: false,
			err:        unix.ENOENT,
		},
		{
			desc:       "NonBlocking Read only success returns immediately",
			makePipe:   true,
			flags:      fs.FileFlags{Read: true, NonBlocking: true},
			expectFile: true,
			err:        nil,
		},
		{
			desc:       "NonBlocking Write only error returns immediately",
			makePipe:   false, /* causes the error */
			flags:      fs.FileFlags{Write: true, NonBlocking: true},
			expectFile: false,
			err:        unix.ENOENT,
		},
		{
			desc:       "NonBlocking Write only no reader error returns immediately",
			makePipe:   true,
			flags:      fs.FileFlags{Write: true, NonBlocking: true},
			expectFile: false,
			err:        unix.ENXIO,
		},
		{
			desc:       "ReadWrite error returns immediately",
			makePipe:   false, /* causes the error */
			flags:      fs.FileFlags{Read: true, Write: true},
			expectFile: false,
			err:        unix.ENOENT,
		},
		{
			desc:       "ReadWrite returns immediately",
			makePipe:   true,
			flags:      fs.FileFlags{Read: true, Write: true},
			expectFile: true,
			err:        nil,
		},
		{
			desc:       "Blocking Write only returns open error",
			makePipe:   false, /* causes the error */
			flags:      fs.FileFlags{Write: true},
			expectFile: false,
			err:        unix.ENOENT, /* from bogus perms */
		},
		{
			desc:       "Blocking Read only returns open error",
			makePipe:   false, /* causes the error */
			flags:      fs.FileFlags{Read: true},
			expectFile: false,
			err:        unix.ENOENT,
		},
		{
			desc:       "Blocking Write only returns with syserror.ErrWouldBlock",
			makePipe:   true,
			flags:      fs.FileFlags{Write: true},
			expectFile: false,
			err:        syserror.ErrWouldBlock,
		},
		{
			desc:       "Blocking Read only returns with syserror.ErrWouldBlock",
			makePipe:   true,
			flags:      fs.FileFlags{Read: true},
			expectFile: false,
			err:        syserror.ErrWouldBlock,
		},
	} {
		name := pipename()
		if test.makePipe {
			// Create the pipe.  We do this per-test case to keep tests independent.
			if err := mkpipe(name); err != nil {
				t.Errorf("%s: failed to make host pipe: %v", test.desc, err)
				continue
			}
			defer unix.Unlink(name)
		}

		// Use a host opener to keep things simple.
		opener := &hostOpener{name: name}

		pipeOpenState := &pipeOpenState{}
		ctx := contexttest.Context(t)
		pipeOps, err := pipeOpenState.TryOpen(ctx, opener, test.flags)
		if unwrapError(err) != test.err {
			t.Errorf("%s: got error %v, want %v", test.desc, err, test.err)
			if pipeOps != nil {
				// Cleanup the state of the pipe, and remove the fd from the
				// fdnotifier.  Sadly this needed to maintain the correctness
				// of other tests because the fdnotifier is global.
				pipeOps.Release(ctx)
			}
			continue
		}
		if (pipeOps != nil) != test.expectFile {
			t.Errorf("%s: got non-nil file %v, want %v", test.desc, pipeOps != nil, test.expectFile)
		}
		if pipeOps != nil {
			// Same as above.
			pipeOps.Release(ctx)
		}
	}
}

func TestPipeOpenUnblocksEventually(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// partnerIsReader is true if the goroutine opening the same pipe as the test case
		// should open the pipe read only.  Otherwise write only.  This also means that the
		// test case will open the pipe in the opposite way.
		partnerIsReader bool

		// partnerIsBlocking is true if the goroutine opening the same pipe as the test case
		// should do so without the O_NONBLOCK flag, otherwise opens the pipe with O_NONBLOCK
		// until ENXIO is not returned.
		partnerIsBlocking bool
	}{
		{
			desc:              "Blocking Read with blocking writer partner opens eventually",
			partnerIsReader:   false,
			partnerIsBlocking: true,
		},
		{
			desc:              "Blocking Write with blocking reader partner opens eventually",
			partnerIsReader:   true,
			partnerIsBlocking: true,
		},
		{
			desc:              "Blocking Read with non-blocking writer partner opens eventually",
			partnerIsReader:   false,
			partnerIsBlocking: false,
		},
		{
			desc:              "Blocking Write with non-blocking reader partner opens eventually",
			partnerIsReader:   true,
			partnerIsBlocking: false,
		},
	} {
		// Create the pipe.  We do this per-test case to keep tests independent.
		name := pipename()
		if err := mkpipe(name); err != nil {
			t.Errorf("%s: failed to make host pipe: %v", test.desc, err)
			continue
		}
		defer unix.Unlink(name)

		// Spawn the partner.
		type fderr struct {
			fd  int
			err error
		}
		errch := make(chan fderr, 1)
		go func() {
			var flags int
			if test.partnerIsReader {
				flags = unix.O_RDONLY
			} else {
				flags = unix.O_WRONLY
			}
			if test.partnerIsBlocking {
				fd, err := unix.Open(name, flags, 0666)
				errch <- fderr{fd: fd, err: err}
			} else {
				var fd int
				err := error(unix.ENXIO)
				for err == unix.ENXIO {
					fd, err = unix.Open(name, flags|unix.O_NONBLOCK, 0666)
					time.Sleep(1 * time.Second)
				}
				errch <- fderr{fd: fd, err: err}
			}
		}()

		// Setup file flags for either a read only or write only open.
		flags := fs.FileFlags{
			Read:  !test.partnerIsReader,
			Write: test.partnerIsReader,
		}

		// Open the pipe in a blocking way, which should succeed eventually.
		opener := &hostOpener{name: name}
		ctx := contexttest.Context(t)
		pipeOps, err := Open(ctx, opener, flags)
		if pipeOps != nil {
			// Same as TestTryOpen.
			pipeOps.Release(ctx)
		}

		// Check that the partner opened the file successfully.
		e := <-errch
		if e.err != nil {
			t.Errorf("%s: partner got error %v, wanted nil", test.desc, e.err)
			continue
		}
		// If so, then close the partner fd to avoid leaking an fd.
		unix.Close(e.fd)

		// Check that our blocking open was successful.
		if err != nil {
			t.Errorf("%s: blocking open got error %v, wanted nil", test.desc, err)
			continue
		}
		if pipeOps == nil {
			t.Errorf("%s: blocking open got nil file, wanted non-nil", test.desc)
			continue
		}
	}
}

func TestCopiedReadAheadBuffer(t *testing.T) {
	// Create the pipe.
	name := pipename()
	if err := mkpipe(name); err != nil {
		t.Fatalf("failed to make host pipe: %v", err)
	}
	defer unix.Unlink(name)

	// We're taking advantage of the fact that pipes opened read only always return
	// success, but internally they are not deemed "opened" until we're sure that
	// another writer comes along.  This means we can open the same pipe write only
	// with no problems + write to it, given that opener.Open already tried to open
	// the pipe RDONLY and succeeded, which we know happened if TryOpen returns
	// syserror.ErrwouldBlock.
	//
	// This simulates the open(RDONLY) <-> open(WRONLY)+write race we care about, but
	// does not cause our test to be racy (which would be terrible).
	opener := &hostOpener{name: name}
	pipeOpenState := &pipeOpenState{}
	ctx := contexttest.Context(t)
	pipeOps, err := pipeOpenState.TryOpen(ctx, opener, fs.FileFlags{Read: true})
	if pipeOps != nil {
		pipeOps.Release(ctx)
		t.Fatalf("open(%s, %o) got file, want nil", name, unix.O_RDONLY)
	}
	if err != syserror.ErrWouldBlock {
		t.Fatalf("open(%s, %o) got error %v, want %v", name, unix.O_RDONLY, err, syserror.ErrWouldBlock)
	}

	// Then open the same pipe write only and write some bytes to it.  The next
	// time we try to open the pipe read only again via the pipeOpenState, we should
	// succeed and buffer some of the bytes written.
	fd, err := unix.Open(name, unix.O_WRONLY, 0666)
	if err != nil {
		t.Fatalf("open(%s, %o) got error %v, want nil", name, unix.O_WRONLY, err)
	}
	defer unix.Close(fd)

	data := []byte("hello")
	if n, err := unix.Write(fd, data); n != len(data) || err != nil {
		t.Fatalf("write(%v) got (%d, %v), want (%d, nil)", data, n, err, len(data))
	}

	// Try the read again, knowing that it should succeed this time.
	pipeOps, err = pipeOpenState.TryOpen(ctx, opener, fs.FileFlags{Read: true})
	if pipeOps == nil {
		t.Fatalf("open(%s, %o) got nil file, want not nil", name, unix.O_RDONLY)
	}
	defer pipeOps.Release(ctx)

	if err != nil {
		t.Fatalf("open(%s, %o) got error %v, want nil", name, unix.O_RDONLY, err)
	}

	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{
		Type: fs.Pipe,
	})
	file := fs.NewFile(ctx, fs.NewDirent(ctx, inode, "pipe"), fs.FileFlags{Read: true}, pipeOps)

	// Check that the file we opened points to a pipe with a non-empty read ahead buffer.
	bufsize := len(pipeOps.readAheadBuffer)
	if bufsize != 1 {
		t.Fatalf("read ahead buffer got %d bytes, want %d", bufsize, 1)
	}

	// Now for the final test, try to read everything in, expecting to get back all of
	// the bytes that were written at once.  Note that in the wild there is no atomic
	// read size so expecting to get all bytes from a single writer when there are
	// multiple readers is a bad expectation.
	buf := make([]byte, len(data))
	ioseq := usermem.BytesIOSequence(buf)
	n, err := pipeOps.Read(ctx, file, ioseq, 0)
	if err != nil {
		t.Fatalf("read request got error %v, want nil", err)
	}
	if n != int64(len(data)) {
		t.Fatalf("read request got %d bytes, want %d", n, len(data))
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("read request got bytes [%v], want [%v]", buf, data)
	}
}

func TestPipeHangup(t *testing.T) {
	for _, test := range []struct {
		// desc is the test's description.
		desc string

		// flags control how we open our end of the pipe and must be read
		// only or write only.  They also dicate how a coordinating partner
		// fd is opened, which is their inverse (read only -> write only, etc).
		flags fs.FileFlags

		// hangupSelf if true causes the test case to close our end of the pipe
		// and causes hangup errors to be asserted on our coordinating partner's
		// fd.  If hangupSelf is false, then our partner's fd is closed and the
		// hangup errors are expected on our end of the pipe.
		hangupSelf bool
	}{
		{
			desc:  "Read only gets hangup error",
			flags: fs.FileFlags{Read: true},
		},
		{
			desc:  "Write only gets hangup error",
			flags: fs.FileFlags{Write: true},
		},
		{
			desc:       "Read only generates hangup error",
			flags:      fs.FileFlags{Read: true},
			hangupSelf: true,
		},
		{
			desc:       "Write only generates hangup error",
			flags:      fs.FileFlags{Write: true},
			hangupSelf: true,
		},
	} {
		if test.flags.Read == test.flags.Write {
			t.Errorf("%s: test requires a single reader or writer", test.desc)
			continue
		}

		// Create the pipe.  We do this per-test case to keep tests independent.
		name := pipename()
		if err := mkpipe(name); err != nil {
			t.Errorf("%s: failed to make host pipe: %v", test.desc, err)
			continue
		}
		defer unix.Unlink(name)

		// Fire off a partner routine which tries to open the same pipe blocking,
		// which will synchronize with us.  The channel allows us to get back the
		// fd once we expect this partner routine to succeed, so we can manifest
		// hangup events more directly.
		fdchan := make(chan int, 1)
		go func() {
			// Be explicit about the flags to protect the test from
			// misconfiguration.
			var flags int
			if test.flags.Read {
				flags = unix.O_WRONLY
			} else {
				flags = unix.O_RDONLY
			}
			fd, err := unix.Open(name, flags, 0666)
			if err != nil {
				t.Logf("Open(%q, %o, 0666) partner failed: %v", name, flags, err)
			}
			fdchan <- fd
		}()

		// Open our end in a blocking way to ensure that we coordinate.
		opener := &hostOpener{name: name}
		ctx := contexttest.Context(t)
		pipeOps, err := Open(ctx, opener, test.flags)
		if err != nil {
			t.Errorf("%s: Open got error %v, want nil", test.desc, err)
			continue
		}
		// Don't defer file.DecRef here because that causes the hangup we're
		// trying to test for.

		// Expect the partner routine to have coordinated with us and get back
		// its open fd.
		f := <-fdchan
		if f < 0 {
			t.Errorf("%s: partner routine got fd %d, want > 0", test.desc, f)
			pipeOps.Release(ctx)
			continue
		}

		if test.hangupSelf {
			// Hangup self and assert that our partner got the expected hangup
			// error.
			pipeOps.Release(ctx)

			if test.flags.Read {
				// Partner is writer.
				assertWriterHungup(t, test.desc, fd.NewReadWriter(f))
			} else {
				// Partner is reader.
				assertReaderHungup(t, test.desc, fd.NewReadWriter(f))
			}
		} else {
			// Hangup our partner and expect us to get the hangup error.
			unix.Close(f)
			defer pipeOps.Release(ctx)

			if test.flags.Read {
				assertReaderHungup(t, test.desc, pipeOps.(*pipeOperations).file)
			} else {
				assertWriterHungup(t, test.desc, pipeOps.(*pipeOperations).file)
			}
		}
	}
}

func assertReaderHungup(t *testing.T, desc string, reader io.Reader) bool {
	// Drain the pipe completely, it might have crap in it, but expect EOF eventually.
	var err error
	for err == nil {
		_, err = reader.Read(make([]byte, 10))
	}
	if err != io.EOF {
		t.Errorf("%s: read from self after hangup got error %v, want %v", desc, err, io.EOF)
		return false
	}
	return true
}

func assertWriterHungup(t *testing.T, desc string, writer io.Writer) bool {
	if _, err := writer.Write([]byte("hello")); !linuxerr.Equals(linuxerr.EPIPE, unwrapError(err)) {
		t.Errorf("%s: write to self after hangup got error %v, want %v", desc, err, linuxerr.EPIPE)
		return false
	}
	return true
}
