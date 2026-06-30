// Copyright 2026 The gVisor Authors.
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

package fuse

import (
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// newTestHostConnection creates a hostConnection backed by a socketpair.
// Returns the hostConnection, the server-side FD, and a cleanup function.
// The connection is pre-initialized and the reader goroutine is started.
func newTestHostConnection(t *testing.T) (*hostConnection, int, func()) {
	t.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           4096,
	}
	conn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		unix.Close(fds[0])
		unix.Close(fds[1])
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}

	conn.setInitialized()
	conn.mu.Lock()
	conn.connInitSuccess = true
	conn.maxWrite = 4096
	conn.mu.Unlock()

	hc := newHostConnection(conn, int32(fds[0]))
	hc.startReader()

	cleanup := func() {
		unix.Shutdown(fds[1], unix.SHUT_RDWR)
		unix.Shutdown(fds[0], unix.SHUT_RDWR)
		unix.Close(fds[0])
		unix.Close(fds[1])
	}
	return hc, fds[1], cleanup
}

// echoServer reads one FUSE request from serverFD and echoes the payload
// back as a response. It signals completion on the done channel.
func echoServer(t *testing.T, serverFD int, done chan struct{}) {
	t.Helper()
	defer close(done)

	buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	n, err := unix.Read(serverFD, buf)
	if err != nil {
		t.Errorf("server Read: %v", err)
		return
	}
	if n < int(linux.SizeOfFUSEHeaderIn) {
		t.Errorf("server: short read %d bytes", n)
		return
	}

	var reqHdr linux.FUSEHeaderIn
	reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])

	payload := buf[linux.SizeOfFUSEHeaderIn:n]
	respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
	respBuf := make([]byte, respLen)

	respHdr := linux.FUSEHeaderOut{
		Len:    respLen,
		Error:  0,
		Unique: reqHdr.Unique,
	}
	respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
	copy(respBuf[linux.SizeOfFUSEHeaderOut:], payload)

	if _, err := unix.Write(serverFD, respBuf); err != nil {
		t.Errorf("server Write: %v", err)
	}
}

// echoServerN reads count FUSE requests from serverFD and echoes each
// payload back as a response. It signals completion on the done channel.
func echoServerN(t *testing.T, serverFD int, count int, done chan struct{}) {
	t.Helper()
	defer close(done)

	for i := 0; i < count; i++ {
		buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
		n, err := unix.Read(serverFD, buf)
		if err != nil {
			t.Errorf("server Read %d: %v", i, err)
			return
		}
		if n < int(linux.SizeOfFUSEHeaderIn) {
			t.Errorf("server: short read %d bytes on request %d", n, i)
			return
		}

		var reqHdr linux.FUSEHeaderIn
		reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])

		payload := buf[linux.SizeOfFUSEHeaderIn:n]
		respLen := linux.SizeOfFUSEHeaderOut + uint32(len(payload))
		respBuf := make([]byte, respLen)

		respHdr := linux.FUSEHeaderOut{
			Len:    respLen,
			Error:  0,
			Unique: reqHdr.Unique,
		}
		respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
		copy(respBuf[linux.SizeOfFUSEHeaderOut:], payload)

		if _, err := unix.Write(serverFD, respBuf); err != nil {
			t.Errorf("server Write %d: %v", i, err)
			return
		}
	}
}

func TestHostConnectionCall(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	done := make(chan struct{})
	go echoServer(t, serverFD, done)

	creds := auth.CredentialsFromContext(s.Ctx)
	testObj := primitive.Uint32(42)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &testObj)

	resp, err := hc.Call(s.Ctx, req)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}

	<-done

	if resp.hdr.Error != 0 {
		t.Fatalf("response error: %d", resp.hdr.Error)
	}
	if resp.hdr.Unique != req.hdr.Unique {
		t.Fatalf("unique mismatch: got %d, want %d", resp.hdr.Unique, req.hdr.Unique)
	}

	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != testObj {
		t.Fatalf("payload: got %d, want %d", got, testObj)
	}
}

func TestHostConnectionInit(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[1])
	defer unix.Close(fds[0])
	defer unix.Shutdown(fds[0], unix.SHUT_RDWR)
	defer unix.Shutdown(fds[1], unix.SHUT_RDWR)

	fsopts := filesystemOptions{
		maxActiveRequests: maxActiveRequestsDefault,
		maxRead:           4096,
	}
	conn, err := newFUSEConnectionOpts(&fsopts)
	if err != nil {
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}
	hc := newHostConnection(conn, int32(fds[0]))

	const testMaxWrite uint32 = 65536

	done := make(chan struct{})
	go func() {
		defer close(done)

		buf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
		n, err := unix.Read(fds[1], buf)
		if err != nil {
			t.Errorf("server Read: %v", err)
			return
		}

		var reqHdr linux.FUSEHeaderIn
		reqHdr.UnmarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
		if reqHdr.Opcode != linux.FUSE_INIT {
			t.Errorf("expected FUSE_INIT opcode, got %d", reqHdr.Opcode)
			return
		}
		_ = n

		initOut := linux.FUSEInitOut{
			Major:    linux.FUSE_KERNEL_VERSION,
			Minor:    linux.FUSE_KERNEL_MINOR_VERSION,
			MaxWrite: testMaxWrite,
		}
		respLen := uint32(linux.SizeOfFUSEHeaderOut) + uint32(initOut.SizeBytes())
		respBuf := make([]byte, respLen)

		respHdr := linux.FUSEHeaderOut{
			Len:    respLen,
			Error:  0,
			Unique: reqHdr.Unique,
		}
		respHdr.MarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])
		initOut.MarshalUnsafe(respBuf[linux.SizeOfFUSEHeaderOut:])

		if _, err := unix.Write(fds[1], respBuf); err != nil {
			t.Errorf("server Write: %v", err)
		}
	}()

	creds := auth.CredentialsFromContext(s.Ctx)
	if err := hc.InitSend(creds, 1, true); err != nil {
		t.Fatalf("InitSend: %v", err)
	}

	<-done

	if !conn.isInitialized() {
		t.Fatal("connection not initialized after InitSend")
	}

	conn.mu.Lock()
	if !conn.connInitSuccess {
		t.Error("connInitSuccess not set")
	}
	if conn.maxWrite < fuseMinMaxWrite {
		t.Errorf("maxWrite = %d, want >= %d", conn.maxWrite, fuseMinMaxWrite)
	}
	conn.mu.Unlock()
}

func TestHostConnectionCallAsync(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	done := make(chan struct{})
	go echoServerN(t, serverFD, 2, done)

	creds := auth.CredentialsFromContext(s.Ctx)
	asyncPayload := primitive.Uint32(99)
	asyncReq := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &asyncPayload)

	if err := hc.CallAsync(s.Ctx, asyncReq); err != nil {
		t.Fatalf("CallAsync: %v", err)
	}

	// Make a subsequent sync Call to verify no stale data in the FD.
	syncPayload := primitive.Uint32(123)
	syncReq := hc.conn.NewRequest(creds, 2, 2, echoTestOpcode, &syncPayload)

	resp, err := hc.Call(s.Ctx, syncReq)
	if err != nil {
		t.Fatalf("Call after CallAsync: %v", err)
	}
	<-done

	if resp.hdr.Unique != syncReq.hdr.Unique {
		t.Fatalf("unique mismatch after async: got %d, want %d", resp.hdr.Unique, syncReq.hdr.Unique)
	}

	var got primitive.Uint32
	if err := resp.UnmarshalPayload(&got); err != nil {
		t.Fatalf("UnmarshalPayload: %v", err)
	}
	if got != syncPayload {
		t.Fatalf("payload after async: got %d, want %d", got, syncPayload)
	}
}

func TestHostConnectionConcurrent(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, serverFD, cleanup := newTestHostConnection(t)
	defer cleanup()

	const numRequests = 10

	serverDone := make(chan struct{})
	go echoServerN(t, serverFD, numRequests, serverDone)

	creds := auth.CredentialsFromContext(s.Ctx)

	var wg sync.WaitGroup
	errs := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(val uint32) {
			defer wg.Done()
			payload := primitive.Uint32(val)
			req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &payload)

			// Each goroutine needs its own context because NoTask.Block
			// has unsynchronized state.
			ctx := kernel.KernelFromContext(s.Ctx).SupervisorContext()
			resp, err := hc.Call(ctx, req)
			if err != nil {
				errs <- err
				return
			}
			if resp.hdr.Unique != req.hdr.Unique {
				errs <- linuxerr.EINVAL
				return
			}
			var got primitive.Uint32
			if err := resp.UnmarshalPayload(&got); err != nil {
				errs <- err
				return
			}
			if got != payload {
				errs <- linuxerr.EINVAL
				return
			}
		}(uint32(i))
	}

	wg.Wait()
	close(errs)
	<-serverDone

	for err := range errs {
		t.Fatalf("concurrent call failed: %v", err)
	}
}

func TestHostConnectionNotConnected(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	hc, _, cleanup := newTestHostConnection(t)
	defer cleanup()

	// Disconnect the connection.
	hc.conn.mu.Lock()
	hc.conn.connected = false
	hc.conn.mu.Unlock()

	creds := auth.CredentialsFromContext(s.Ctx)
	testObj := primitive.Uint32(0)
	req := hc.conn.NewRequest(creds, 1, 1, echoTestOpcode, &testObj)

	_, err := hc.Call(s.Ctx, req)
	if !linuxerr.Equals(linuxerr.ENOTCONN, err) {
		t.Fatalf("expected ENOTCONN, got %v", err)
	}
}
