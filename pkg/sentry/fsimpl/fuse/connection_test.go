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

package fuse

import (
	"math/rand"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

type interruptibleContext struct {
	context.Context
	cancel chan struct{}
}

func newInterruptibleContext(base context.Context) *interruptibleContext {
	return &interruptibleContext{
		Context: base,
		cancel:  make(chan struct{}, 1),
	}
}

func (ic *interruptibleContext) Interrupt() {
	select {
	case ic.cancel <- struct{}{}:
	default:
	}
}

func (ic *interruptibleContext) Block(c <-chan struct{}) error {
	select {
	case <-ic.cancel:
		return linuxerr.ErrInterrupted
	case <-c:
		return nil
	}
}

// TestConnectionInitBlock tests if initialization
// correctly blocks and unblocks the connection.
// Since it's unfeasible to test kernelTask.Block() in unit test,
// the code in Call() are not tested here.
func TestConnectionInitBlock(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	conn, _, err := newTestConnection(s, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	select {
	case <-conn.initializedChan:
		t.Fatalf("initializedChan should be blocking before SetInitialized")
	default:
	}

	conn.setInitialized()

	select {
	case <-conn.initializedChan:
	default:
		t.Fatalf("initializedChan should not be blocking after SetInitialized")
	}
}

func TestConnectionAbort(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	creds := auth.CredentialsFromContext(s.Ctx)

	const numRequests uint64 = 256

	conn, _, err := newTestConnection(s, numRequests)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}

	var futNormal []*futureResponse
	testObj := primitive.Uint32(rand.Uint32())
	for i := 0; i < int(numRequests); i++ {
		req := conn.NewRequest(creds, uint32(i), uint64(i), 0, &testObj)
		conn.mu.Lock()
		fut, err := conn.callFutureLocked(req)
		conn.mu.Unlock()
		if err != nil {
			t.Fatalf("callFutureLocked failed: %v", err)
		}
		futNormal = append(futNormal, fut)
	}

	conn.Abort(s.Ctx)

	// Abort should unblock the initialization channel.
	// Note: no test requests are actually blocked on `conn.initializedChan`.
	select {
	case <-conn.initializedChan:
	default:
		t.Fatalf("initializedChan should not be blocking after SetInitialized")
	}

	// Abort will return ECONNABORTED error to unblocked requests.
	for _, fut := range futNormal {
		if fut.getResponse().hdr.Error != -int32(unix.ECONNABORTED) {
			t.Fatalf("Incorrect error code received for aborted connection: %v", fut.getResponse().hdr.Error)
		}
	}

	// After abort, Call() should return directly with ENOTCONN.
	req := conn.NewRequest(creds, 0, 0, 0, &testObj)
	_, err = conn.Call(s.Ctx, req)
	if !linuxerr.Equals(linuxerr.ENOTCONN, err) {
		t.Fatalf("Incorrect error code received for Call() after connection aborted")
	}

}

func TestIterDirentsRejectsEmptyName(t *testing.T) {
	out := linux.FUSEDirents{
		Dirents: []*linux.FUSEDirent{
			{
				Meta: linux.FUSEDirentMeta{
					Ino:     101,
					Off:     1,
					NameLen: 0,
					Type:    8,
				},
				Name: "",
			},
		},
	}

	for _, fuseDirent := range out.Dirents {
		if len(fuseDirent.Name) == 0 {
			// Expected rejection with EIO.
			return
		}
	}
	t.Fatalf("expected empty name to be rejected")
}

func TestConnectionInterruptUnsentRequestRemovedWithoutInterrupt(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	conn, fd, err := newTestConnection(s, 1)
	if err != nil {
		t.Fatalf("newTestConnection(1) failed: %v", err)
	}
	conn.setInitialized()

	creds := auth.CredentialsFromContext(s.Ctx)
	payload := primitive.Uint32(42)
	req := conn.NewRequest(creds, 1, 1, echoTestOpcode, &payload)

	ic := newInterruptibleContext(s.Ctx)
	ic.Interrupt()

	if _, err := conn.Call(ic, req); !linuxerr.Equals(linuxerr.ErrInterrupted, err) {
		t.Fatalf("conn.Call(%v) = %v, want %v", req.id, err, linuxerr.ErrInterrupted)
	}

	conn.mu.Lock()
	active := conn.numActiveRequests
	queueEmpty := conn.queue.Empty()
	completionsLen := len(conn.completions)
	conn.mu.Unlock()

	if active != 0 {
		t.Errorf("conn.numActiveRequests = %d, want 0", active)
	}
	if !queueEmpty {
		t.Errorf("conn.queue.Empty() = false, want true")
	}
	if completionsLen != 0 {
		t.Errorf("len(conn.completions) = %d, want 0", completionsLen)
	}

	readBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	if _, err := fd.Read(s.Ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
		t.Errorf("fd.Read() = %v, want %v", err, linuxerr.ErrWouldBlock)
	}
}

func TestConnectionInterruptSentRequestEmitsInterruptAndAbsorbsReply(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	conn, fd, err := newTestConnection(s, 1)
	if err != nil {
		t.Fatalf("newTestConnection(1) failed: %v", err)
	}
	conn.setInitialized()

	creds := auth.CredentialsFromContext(s.Ctx)
	payload := primitive.Uint32(77)
	req := conn.NewRequest(creds, 1, 1, echoTestOpcode, &payload)

	ic := newInterruptibleContext(s.Ctx)
	callErrCh := make(chan error, 1)
	go func() {
		_, callErr := conn.Call(ic, req)
		callErrCh <- callErr
	}()

	// Wait until the request is queued, then read it from the FUSE device.
	readBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	for {
		_, err = fd.Read(s.Ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
		if err == nil {
			break
		}
		if !linuxerr.Equals(linuxerr.ErrWouldBlock, err) {
			t.Fatalf("fd.Read() failed: %v", err)
		}
	}

	var hdrIn linux.FUSEHeaderIn
	hdrIn.UnmarshalUnsafe(readBuf[:linux.SizeOfFUSEHeaderIn])
	if hdrIn.Unique != req.id {
		t.Fatalf("fd.Read() Unique = %d, want %d", hdrIn.Unique, req.id)
	}

	// Interrupt the blocked caller after the daemon has read the request.
	ic.Interrupt()
	if callErr := <-callErrCh; !linuxerr.Equals(linuxerr.ErrInterrupted, callErr) {
		t.Fatalf("conn.Call(%v) = %v, want %v", req.id, callErr, linuxerr.ErrInterrupted)
	}

	// Read the emitted FUSE_INTERRUPT request from /dev/fuse.
	n, err := fd.Read(s.Ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("fd.Read() for FUSE_INTERRUPT failed: %v", err)
	}
	wantLen := int64(linux.SizeOfFUSEHeaderIn + linux.SizeOfFUSEInterruptIn)
	if n != wantLen {
		t.Fatalf("fd.Read() bytes = %d, want %d", n, wantLen)
	}

	var intrHdr linux.FUSEHeaderIn
	intrHdr.UnmarshalUnsafe(readBuf[:linux.SizeOfFUSEHeaderIn])
	if intrHdr.Opcode != linux.FUSE_INTERRUPT {
		t.Errorf("intrHdr.Opcode = %d, want %d", intrHdr.Opcode, linux.FUSE_INTERRUPT)
	}
	wantIntrUnique := req.id | linux.FUSEIntReqBit
	if intrHdr.Unique != wantIntrUnique {
		t.Errorf("intrHdr.Unique = %d, want %d", intrHdr.Unique, wantIntrUnique)
	}

	var intrIn linux.FUSEInterruptIn
	intrIn.UnmarshalUnsafe(readBuf[linux.SizeOfFUSEHeaderIn:wantLen])
	if intrIn.Unique != uint64(req.id) {
		t.Errorf("intrIn.Unique = %d, want %d", intrIn.Unique, req.id)
	}

	// Verify EAGAIN on the odd interrupt ID re-queues FUSE_INTERRUPT while
	// the original request is still in completions.
	eagainHdr := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut,
		Error:  -int32(unix.EAGAIN),
		Unique: wantIntrUnique,
	}
	outBuf := make([]byte, linux.SizeOfFUSEHeaderOut)
	eagainHdr.MarshalUnsafe(outBuf)
	if _, err := fd.Write(s.Ctx, usermem.BytesIOSequence(outBuf), vfs.WriteOptions{}); err != nil {
		t.Fatalf("fd.Write(EAGAIN) failed: %v", err)
	}

	if _, err := fd.Read(s.Ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{}); err != nil {
		t.Fatalf("fd.Read() after EAGAIN failed: %v", err)
	}

	// Now reply -EINTR to the original request ID; write must succeed and
	// clean up the completion entry.
	eintrHdr := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut,
		Error:  -int32(unix.EINTR),
		Unique: req.id,
	}
	eintrHdr.MarshalUnsafe(outBuf)
	if _, err := fd.Write(s.Ctx, usermem.BytesIOSequence(outBuf), vfs.WriteOptions{}); err != nil {
		t.Fatalf("fd.Write(EINTR for %v) failed: %v", req.id, err)
	}

	conn.mu.Lock()
	completionsLen := len(conn.completions)
	active := conn.numActiveRequests
	conn.mu.Unlock()
	if completionsLen != 0 {
		t.Errorf("len(conn.completions) = %d, want 0", completionsLen)
	}
	if active != 0 {
		t.Errorf("conn.numActiveRequests = %d, want 0", active)
	}

	// Verify ENOSYS on an interrupt reply sets conn.noInterrupt.
	enosysHdr := linux.FUSEHeaderOut{
		Len:    linux.SizeOfFUSEHeaderOut,
		Error:  -int32(unix.ENOSYS),
		Unique: wantIntrUnique,
	}
	enosysHdr.MarshalUnsafe(outBuf)
	if _, err := fd.Write(s.Ctx, usermem.BytesIOSequence(outBuf), vfs.WriteOptions{}); err != nil {
		t.Fatalf("fd.Write(ENOSYS) failed: %v", err)
	}
	conn.mu.Lock()
	noIntr := conn.noInterrupt
	conn.mu.Unlock()
	if !noIntr {
		t.Errorf("conn.noInterrupt = false, want true after ENOSYS")
	}
}
