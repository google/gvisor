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
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// newMockFileDescriptionConn takes ownership of impl, including on failure.
func newMockFileDescriptionConn(t *testing.T, ctx context.Context, impl vfs.FileDescriptionImpl) *fileDescriptionConn {
	t.Helper()
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		impl.Release(ctx)
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vd := vfsObj.NewAnonVirtualDentry("mock_app")
	defer vd.DecRef(ctx)
	var fd vfs.FileDescription
	if err := fd.Init(impl, linux.O_RDWR, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{}); err != nil {
		impl.Release(ctx)
		t.Fatalf("FileDescription.Init: %v", err)
	}
	conn := &fileDescriptionConn{file: &fd}
	// The proxy and cleanup must share the same Once-protected close.
	t.Cleanup(func() { conn.Close(ctx) })
	return conn
}

// readerWriter is a synchronous in-memory FileDescriptionImpl for
// TestReaderWriter. Writes append to its buffer; reads consume buffered data.
type readerWriter struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl
	buf      bytes.Buffer
	released bool
}

var _ vfs.FileDescriptionImpl = (*readerWriter)(nil)

// Read implements vfs.FileDescriptionImpl.Read.
func (rw *readerWriter) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	if rw.released {
		return 0, io.EOF
	}
	buf := make([]byte, dst.NumBytes())
	n, err := rw.buf.Read(buf)
	if err != nil {
		return 0, nil
	}
	n, err = dst.CopyOut(ctx, buf[:n])
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write.
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

// EventRegister implements vfs.FileDescriptionImpl.EventRegister.
func (rw *readerWriter) EventRegister(we *waiter.Entry) error { return fmt.Errorf("not implemented") }

// EventUnregister implements vfs.FileDescriptionImpl.EventUnregister.
func (rw *readerWriter) EventUnregister(we *waiter.Entry) { panic("not implemented") }

// Release implements vfs.FileDescriptionImpl.Release.
func (rw *readerWriter) Release(context.Context) {
	rw.released = true
}

// waiterRW is like readerWriter, but blocks between Read and Write calls.
type waiterRW struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD
	vfs.DentryMetadataFileDescriptionImpl

	waitMu sync.Mutex

	// +checklocks:waitMu
	buf bytes.Buffer

	// +checklocks:waitMu
	entries []*waiter.Entry

	// +checklocks:waitMu
	shouldWait bool

	quit chan bool

	// +checklocks:waitMu
	closed bool
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

// Read implements vfs.FileDescriptionImpl.Read.
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
	n, err := w.buf.Read(buf)
	if err != nil {
		return 0, err
	}
	n, err = dst.CopyOut(ctx, buf[:n])
	w.shouldWait = true
	return int64(n), err
}

// Write implements vfs.FileDescriptionImpl.Write.
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

// EventRegister implements vfs.FileDescriptionImpl.EventRegister.
func (w *waiterRW) EventRegister(we *waiter.Entry) error {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	w.entries = append(w.entries, we)
	return nil
}

// EventUnregister implements vfs.FileDescriptionImpl.EventUnregister.
func (w *waiterRW) EventUnregister(we *waiter.Entry) {
	w.waitMu.Lock()
	defer w.waitMu.Unlock()
	if i := slices.Index(w.entries, we); i >= 0 {
		w.entries = slices.Delete(w.entries, i, i+1)
	}
}

// Release implements vfs.FileDescriptionImpl.Release.
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
			// Keep a real clock so notifications can overlap waiter registration
			// and removal. A synctest clock would wait for the I/O goroutine to
			// block again.
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func TestReaderWriter(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		newImpl func() vfs.FileDescriptionImpl
	}{
		{
			name:    "readerWriter",
			newImpl: func() vfs.FileDescriptionImpl { return &readerWriter{} },
		},
		{
			name:    "waiter",
			newImpl: func() vfs.FileDescriptionImpl { return newWaiterReaderWriter() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			readerWriter := newMockFileDescriptionConn(t, ctx, tc.newImpl())
			// The total is not a multiple of the read buffer size, so the last
			// read must not copy or report unused buffer bytes.
			sendBytes := [][]byte{
				[]byte("abc"),
				[]byte("123"),
				[]byte("abc123"),
				[]byte("youandme!"),
			}
			for _, buf := range sendBytes {
				n, err := readerWriter.Write(ctx, buf, nil)
				if err != nil {
					t.Fatalf("write failed: %v", err)
				}
				if n != len(buf) {
					t.Fatalf("failed to write buf: %s", string(buf))
				}
			}

			var got []byte
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
				got = append(got, buf[:n]...)
			}
			if want := slices.Concat(sendBytes...); !slices.Equal(got, want) {
				t.Fatalf("mismatch data: got: %q want: %q", got, want)
			}
		})
	}
}

type blockingConn struct {
	name        string
	releaseRead <-chan struct{}
	mu          sync.Mutex

	// +checklocks:mu
	readExited bool

	// +checklocks:mu
	closedBeforeReadExit bool
}

func (b *blockingConn) Name() string { return b.name }

func (b *blockingConn) Read(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	<-cancel
	<-b.releaseRead
	b.mu.Lock()
	b.readExited = true
	b.mu.Unlock()
	return 0, io.EOF
}

func (b *blockingConn) Write(ctx context.Context, buf []byte, cancel <-chan struct{}) (int, error) {
	<-cancel
	return 0, io.EOF
}

func (b *blockingConn) Close(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.readExited {
		b.closedBeforeReadExit = true
	}
}

func TestProxyCloseOrdersCancellationBeforeCleanup(t *testing.T) {
	ctx := context.Background()
	synctest.Test(t, func(t *testing.T) {
		releaseRead := make(chan struct{})
		to := &blockingConn{name: "to", releaseRead: releaseRead}
		from := &blockingConn{name: "from", releaseRead: releaseRead}
		proxy := NewProxy(ProxyPair{To: to, From: from}, "test-cid")
		unblock := sync.OnceFunc(func() { close(releaseRead) })
		t.Cleanup(func() {
			unblock()
			proxy.Close()
			synctest.Wait()
		})
		proxy.Start(ctx)

		// Both reads must block on cancellation before Close starts.
		synctest.Wait()
		go proxy.Close()

		// Keep the canceled reads blocked so cleanup cannot run early without
		// being observed. This uses durable blocking, not simulated time.
		synctest.Wait()
		unblock()
		synctest.Wait()

		to.mu.Lock()
		defer to.mu.Unlock()
		if to.closedBeforeReadExit {
			t.Errorf("Proxy.Close invoked to.Close() before to.Read() exited")
		}

		from.mu.Lock()
		defer from.mu.Unlock()
		if from.closedBeforeReadExit {
			t.Errorf("Proxy.Close invoked from.Close() before from.Read() exited")
		}
	})
}
