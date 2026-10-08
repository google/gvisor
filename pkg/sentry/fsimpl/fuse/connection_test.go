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
	"gvisor.dev/gvisor/pkg/usermem"
)

// interruptibleTaskContext wraps a context.Context to simulate a kernel.Task
// whose Block() returns linuxerr.ErrInterrupted when interrupted by
// Kernel.Pause() / TaskSet.BeginExternalStop().
type interruptibleTaskContext struct {
	context.Context
	enteredBlock chan struct{}
	interruptCh  chan struct{}
}

func (c *interruptibleTaskContext) Block(ch <-chan struct{}) error {
	select {
	case c.enteredBlock <- struct{}{}:
	default:
	}
	select {
	case <-ch:
		return nil
	case <-c.interruptCh:
		return linuxerr.ErrInterrupted
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

// TestConnectionCallInterruptedByPause reproduces b/569841594: when a task is
// blocked in conn.Call() waiting for a paused FUSE daemon (such as srcfsd
// during a gVisor snapshot) and Kernel.Pause() interrupts the task (causing
// Task.block to return linuxerr.ErrInterrupted), conn.Call() must return
// linuxerr.ERESTARTSYS so the VFS syscall is restarted upon resume/restore
// rather than failing with EINTR, and must clean up the aborted request from
// conn.queue and conn.completions.
func TestConnectionCallInterruptedByPause(t *testing.T) {
	s := setup(t)
	defer s.Destroy()

	creds := auth.CredentialsFromContext(s.Ctx)
	conn, _, err := newTestConnection(s, maxActiveRequestsDefault)
	if err != nil {
		t.Fatalf("newTestConnection: %v", err)
	}
	conn.setInitialized()

	taskCtx := &interruptibleTaskContext{
		Context:      s.Ctx,
		enteredBlock: make(chan struct{}, 1),
		interruptCh:  make(chan struct{}),
	}

	testObj := primitive.Uint32(42)
	req := conn.NewRequest(creds, 1, 1, linux.FUSE_GETATTR, &testObj)

	callErrCh := make(chan error, 1)
	go func() {
		_, err := conn.Call(taskCtx, req)
		callErrCh <- err
	}()

	// Wait until the request is queued and the task is blocked in
	// futureResponse.resolve() waiting for the paused FUSE daemon.
	<-taskCtx.enteredBlock

	// Simulate Kernel.Pause() -> TaskSet.BeginExternalStop() interrupting the
	// blocked task goroutine.
	close(taskCtx.interruptCh)

	callErr := <-callErrCh
	if !linuxerr.Equals(linuxerr.ERESTARTSYS, callErr) {
		t.Errorf("conn.Call() after Kernel.Pause interrupt = %v, want %v (ERESTARTSYS)", callErr, linuxerr.ERESTARTSYS)
	}

	conn.mu.Lock()
	activeReqs := conn.numActiveRequests
	queueEmpty := conn.queue.Empty()
	numCompletions := len(conn.completions)
	conn.mu.Unlock()

	if activeReqs != 0 {
		t.Errorf("conn.numActiveRequests after interrupted Call = %d, want 0", activeReqs)
	}
	if !queueEmpty {
		t.Errorf("conn.queue.Empty() after interrupted Call = false, want true")
	}
	if numCompletions != 0 {
		t.Errorf("len(conn.completions) after interrupted Call = %d, want 0", numCompletions)
	}

	// Now test interrupting a request AFTER the FUSE daemon has already
	// dequeued it via fd.Read(). The daemon is sent a FUSE_INTERRUPT request,
	// and the request is forgotten, releasing its active request slot. As in
	// Linux, the daemon's late reply to it fails with ENOENT.
	taskCtx2 := &interruptibleTaskContext{
		Context:      s.Ctx,
		enteredBlock: make(chan struct{}, 1),
		interruptCh:  make(chan struct{}),
	}
	req2 := conn.NewRequest(creds, 1, 1, linux.FUSE_GETATTR, &testObj)
	callErrCh2 := make(chan error, 1)
	go func() {
		_, err := conn.Call(taskCtx2, req2)
		callErrCh2 <- err
	}()

	<-taskCtx2.enteredBlock

	readBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	if _, err := conn.read(s.Ctx, usermem.BytesIOSequence(readBuf)); err != nil {
		t.Fatalf("conn.read() failed: %v", err)
	}

	close(taskCtx2.interruptCh)
	callErr2 := <-callErrCh2
	if !linuxerr.Equals(linuxerr.ERESTARTSYS, callErr2) {
		t.Errorf("conn.Call() after interrupt of dequeued req = %v, want %v (ERESTARTSYS)", callErr2, linuxerr.ERESTARTSYS)
	}

	conn.mu.Lock()
	activeReqs = conn.numActiveRequests
	numCompletions = len(conn.completions)
	intr := conn.interrupts.Front()
	conn.mu.Unlock()
	if activeReqs != 0 {
		t.Errorf("conn.numActiveRequests after interrupt of dequeued req = %d, want 0", activeReqs)
	}
	if numCompletions != 0 {
		t.Errorf("len(conn.completions) after interrupt of dequeued req = %d, want 0", numCompletions)
	}
	if intr == nil || intr.hdr.Unique != req2.id|linux.FUSE_INT_REQ_BIT {
		t.Errorf("no FUSE_INTERRUPT request queued for dequeued req %d", req2.id)
	}

	var hdrOut linux.FUSEHeaderOut
	hdrOut.Len = uint32(hdrOut.SizeBytes())
	hdrOut.Error = 0
	hdrOut.Unique = req2.id
	writeBuf := make([]byte, hdrOut.Len)
	hdrOut.MarshalUnsafe(writeBuf)
	if _, err := conn.write(s.Ctx, usermem.BytesIOSequence(writeBuf)); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("conn.write() for abandoned request = %v, want ENOENT", err)
	}
}
