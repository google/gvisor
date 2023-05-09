// Copyright 2022 The gVisor Authors.
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

package portforward

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// mockFileDescriptionRWImpl implements all vfs.FileDescriptionImpl methods used in
// fileDescriptionReaderWriter for a mockFileDescription.
type mockFileDescriptionRWImpl interface {
	Read(context.Context, usermem.IOSequence, vfs.ReadOptions) (int64, error)
	Write(context.Context, usermem.IOSequence, vfs.WriteOptions) (int64, error)
	EventRegister(*waiter.Entry) error
	EventUnregister(*waiter.Entry)
	Release(context.Context)
}

// mockFileDescription implements vfs.FileDescriptionImpl for portforward tests.
type mockFileDescription struct {
	vfsfd  vfs.FileDescription
	impl   vfs.FileDescriptionImpl
	vfsObj *vfs.VirtualFilesystem
}

// Read implements FileDescriptionImpl.Read.
func (m *mockFileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return m.impl.Read(ctx, dst, opts)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (m *mockFileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return m.impl.Write(ctx, src, opts)
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister.
func (m *mockFileDescription) EventRegister(waitEntry *waiter.Entry) error {
	return m.impl.EventRegister(waitEntry)
}

// EventUnregister implements vfs.FileDescriptionImpl.EventUnregister.
func (m *mockFileDescription) EventUnregister(waitEntry *waiter.Entry) {
	m.impl.EventUnregister(waitEntry)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (m *mockFileDescription) Release(ctx context.Context) { m.impl.Release(ctx) }

func newMockFileDescription(ctx context.Context, fdImpl vfs.FileDescriptionImpl) (*vfs.FileDescription, error) {
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, fmt.Errorf("vfsObj.Init: %v", err)
	}
	vd := vfsObj.NewAnonVirtualDentry("mock_app")
	defer vd.DecRef(ctx)
	fd := mockFileDescription{
		impl:   fdImpl,
		vfsObj: vfsObj,
	}
	fd.vfsfd.Init(fd.impl, linux.O_RDWR, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{})
	fd.vfsObj = vfsObj
	return &fd.vfsfd, nil
}

// readerWriter implements mockFileDescriptionRWImpl. On write, it appends given data to a buffer.
// On reads it pops the requested amount of data off the buffer.
type readerWriter struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl
	buf      bytes.Buffer
	released bool
}

var _ vfs.FileDescriptionImpl = (*readerWriter)(nil)

// Read implements vfs.FileDescriptionImpl.Read details for the parent mockFileDescription.
func (rw *readerWriter) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if rw.released {
		return 0, io.EOF
	}
	buf := make([]byte, dst.NumBytes())
	_, err := rw.buf.Read(buf)
	if err != nil {
		return 0, nil
	}
	n, err := dst.CopyOut(ctx, buf)
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write details for the parent mockFileDescription.
func (rw *readerWriter) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	if rw.released {
		return 0, io.EOF
	}
	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	n, err = rw.buf.Write(buf[:n])
	return int64(n), err
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister details for the parent mockFileDescription.
func (rw *readerWriter) EventRegister(we *waiter.Entry) error { return fmt.Errorf("not implemented") }

// EventUnregister implements vfs.FileDescriptionImpl.Unregister details for the parent mockFileDescription.
func (rw *readerWriter) EventUnregister(we *waiter.Entry) { panic("not implemented") }

// Release implements vfs.FileDescriptionImpl.Release details for the parent mockFileDescription.
func (rw *readerWriter) Release(context.Context) {
	rw.released = true
}

// waiterRW implements mockFileDescriptionRWImpl. waiterRW works the same way as readerWriter above,
// but it interleaves blocks in between Read and Write calls.
type waiterRW struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl
	buf        bytes.Buffer
	waitMu     sync.Mutex
	entries    []*waiter.Entry
	shouldWait bool
	quit       chan bool
	closed     bool
}

var _ vfs.FileDescriptionImpl = (*waiterRW)(nil)

func newWaiterReaderWriter() *waiterRW {
	ret := &waiterRW{
		entries:    []*waiter.Entry{},
		shouldWait: true,
		quit:       make(chan bool),
	}
	go ret.doNotify()
	return ret
}

// Read implements vfs.FileDescriptionImpl.Read details for the parent mockFileDescription.
func (w *waiterRW) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	if w.closed {
		return 0, io.EOF
	}
	if w.shouldWait {
		return 0, linuxerr.ErrWouldBlock
	}
	buf := make([]byte, dst.NumBytes())
	_, err := w.buf.Read(buf)
	if err != nil {
		return 0, err
	}
	n, err := dst.CopyOut(ctx, buf)
	w.shouldWait = true
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write details for the parent mockFileDescription.
func (w *waiterRW) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	if w.closed {
		return 0, nil
	}
	if w.shouldWait {
		return 0, linuxerr.ErrWouldBlock
	}
	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	if int64(n) != src.NumBytes() {
		return 0, linuxerr.EFAULT
	}
	n, err = w.buf.Write(buf)
	w.shouldWait = true
	return int64(n), err
}

// EventRegister implements vfs.FileDescriptionImpl.EventRegister details for the parent mockFileDescription.
func (w *waiterRW) EventRegister(we *waiter.Entry) error {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	w.entries = append(w.entries, we)
	for _, e := range w.entries {
		if e == we {
			return nil
		}
	}
	w.entries = append(w.entries, we)
	return nil
}

// EventUnregister implements vfs.FileDescriptionImpl.Unregister details for the parent mockFileDescription.
func (w *waiterRW) EventUnregister(we *waiter.Entry) {
	for i, e := range w.entries {
		if e == we {
			w.entries = append(w.entries[:i], w.entries[i+1:]...)
		}
	}
}

// Release implements vfs.FileDescriptionImpl.Release details for the parent mockFileDescription.
func (w *waiterRW) Release(context.Context) {
	w.quit <- true
}

func (w *waiterRW) doNotify() {
	for {
		w.waitMu.Lock()
		select {
		case <-w.quit:
			w.closed = true
			w.waitMu.Unlock()
			return
		default:
			w.shouldWait = false
			for _, we := range w.entries {
				we.NotifyEvent(waiter.ReadableEvents | waiter.WritableEvents)
			}
			w.waitMu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestReaderWriter(t *testing.T) {
	ctx := contexttest.Context(t)
	for _, tc := range []struct {
		name       string
		mockFDImpl vfs.FileDescriptionImpl
	}{
		{
			name:       "readerWriter",
			mockFDImpl: &readerWriter{},
		},
		{
			name:       "waiter",
			mockFDImpl: newWaiterReaderWriter(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd, err := newMockFileDescription(ctx, tc.mockFDImpl)
			if err != nil {
				tc.mockFDImpl.Release(ctx)
				t.Fatal(err)
			}
			readerWriter := fileDescriptionConn{
				file: fd,
			}
			sendBytes := []([]byte){
				[]byte{'a', 'b', 'c'},
				[]byte{'1', '2', '3'},
				[]byte{'a', 'b', 'c', '1', '2', '3'},
				[]byte{'y', 'o', 'u', 'a', 'n', 'd', 'm', 'e'},
			}
			for _, buf := range sendBytes {
				n, err := readerWriter.Write(ctx, buf, nil)
				if err != nil {
					tc.mockFDImpl.Release(ctx)
					t.Fatalf("write failed: %v", err)
				}
				if n != len(buf) {
					tc.mockFDImpl.Release(ctx)
					t.Fatalf("failed to write buf: %s", string(buf))
				}
			}

			got := []byte{}
			buf := make([]byte, 4)
			for {
				n, err := readerWriter.Read(ctx, buf, nil)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("read failed: %v", err)
				}
				if n == 0 {
					break
				}
				got = append(got, buf...)
				buf = buf[0:]
			}
			tc.mockFDImpl.Release(ctx)

			want := []byte{}
			for _, buf := range sendBytes {
				want = append(want, buf...)
			}

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("mismatch types: got: %q want: %q", string(got), string(want))
			}

			_, err = readerWriter.Read(ctx, buf[0:], nil)
			if err != io.EOF {
				t.Fatalf("expected end of file: got: %v", err)
			}
		})
	}
}
