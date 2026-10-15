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
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// newBareConnection returns a connection that isn't attached to a device.
func newBareConnection(t *testing.T) *connection {
	t.Helper()
	conn, err := newFUSEConnectionOpts(&filesystemOptions{maxActiveRequests: 10})
	if err != nil {
		t.Fatalf("newFUSEConnectionOpts: %v", err)
	}
	return conn
}

func newTestRequest(conn *connection, opcode linux.FUSEOpcode) *Request {
	payload := primitive.Uint32(0)
	return conn.NewRequest(auth.NewAnonymousCredentials(), 1, 1, opcode, &payload)
}

// newQueuedRequest queues a new request on conn, as Call would, and returns
// it along with its future response.
func newQueuedRequest(t *testing.T, conn *connection, opcode linux.FUSEOpcode) (*Request, *futureResponse) {
	t.Helper()
	r := newTestRequest(conn, opcode)
	conn.mu.Lock()
	defer conn.mu.Unlock()
	fut, err := conn.callFutureLocked(r)
	if err != nil {
		t.Fatalf("callFutureLocked: %v", err)
	}
	return r, fut
}

// newSentRequest is like newQueuedRequest, but also simulates the server
// reading the request.
func newSentRequest(t *testing.T, conn *connection, opcode linux.FUSEOpcode) (*Request, *futureResponse) {
	t.Helper()
	r, fut := newQueuedRequest(t, conn, opcode)
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.queue.Remove(r)
	fut.sent = true
	return r, fut
}

// interruptReplyLocked passes the server's reply to the FUSE_INTERRUPT
// request for the given request to handleInterruptReplyLocked.
//
// +checklocks:conn.mu
func interruptReplyLocked(conn *connection, unique linux.FUSEOpID, errno unix.Errno, size uint32) (*futureResponse, error) {
	hdr := linux.FUSEHeaderOut{
		Len:    size,
		Error:  -int32(errno),
		Unique: unique | linux.FUSE_INT_REQ_BIT,
	}
	return conn.handleInterruptReplyLocked(&hdr, int64(size))
}

func TestHandleInterruptReply(t *testing.T) {
	conn := newBareConnection(t)
	_, fut := newSentRequest(t, conn, echoTestOpcode)
	_, unsentFut := newQueuedRequest(t, conn, echoTestOpcode)
	size := linux.SizeOfFUSEHeaderOut

	conn.mu.Lock()
	defer conn.mu.Unlock()
	for _, tc := range []struct {
		name    string
		unique  linux.FUSEOpID
		size    uint32
		wantErr error
	}{
		{"unknown request", fut.unique + 100, size, linuxerr.ENOENT},
		{"unsent request", unsentFut.unique, size, linuxerr.ENOENT},
		{"bad size", fut.unique, size + 8, linuxerr.EINVAL},
		{"EAGAIN without interrupt", fut.unique, size, linuxerr.EINVAL},
	} {
		if got, err := interruptReplyLocked(conn, tc.unique, unix.EAGAIN, tc.size); got != nil || err != tc.wantErr {
			t.Errorf("%s: got (%v, %v), want (nil, %v)", tc.name, got, err, tc.wantErr)
		}
	}

	fut.interrupted = true
	if got, err := interruptReplyLocked(conn, fut.unique, unix.EAGAIN, size); got != fut || err != nil {
		t.Errorf("EAGAIN: got (%v, %v), want (%v, nil)", got, err, fut)
	}
	if got, err := interruptReplyLocked(conn, fut.unique, unix.ENOSYS, size); got != nil || err != nil {
		t.Errorf("ENOSYS: got (%v, %v), want (nil, nil)", got, err)
	}
	if conn.markInterruptedLocked(fut) {
		t.Errorf("markInterruptedLocked returned true after ENOSYS reply")
	}
}

func TestAbandonRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sent   bool
		killed bool
		force  bool
		// wantReleased is true if the request should be forgotten, releasing
		// its active request slot.
		wantReleased bool
	}{
		{name: "unsent, stop", wantReleased: true},
		{name: "unsent, killed", killed: true, wantReleased: true},
		{name: "unsent, forced", force: true},
		{name: "sent, stop", sent: true, wantReleased: true},
		{name: "sent, killed", sent: true, killed: true},
		{name: "sent, forced", sent: true, force: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newBareConnection(t)
			newRequest := newQueuedRequest
			if tc.sent {
				newRequest = newSentRequest
			}
			r, fut := newRequest(t, conn, linux.FUSE_MKDIR)
			r.force = tc.force

			if res, err := conn.abandonRequest(r, fut, tc.killed, linuxerr.ErrInterrupted); res != nil || err != linuxerr.ErrInterrupted {
				t.Errorf("abandonRequest: got (%v, %v), want (nil, ErrInterrupted)", res, err)
			}

			conn.mu.Lock()
			defer conn.mu.Unlock()
			if _, outstanding := conn.completions[fut.unique]; outstanding == tc.wantReleased {
				t.Errorf("request outstanding = %t, want %t", outstanding, !tc.wantReleased)
			}
			wantActive := uint64(1)
			if tc.wantReleased {
				wantActive = 0
			}
			if conn.numActiveRequests != wantActive {
				t.Errorf("numActiveRequests = %d, want %d", conn.numActiveRequests, wantActive)
			}
			wantQueued := !tc.sent && !tc.wantReleased
			if queued := conn.queue.Front() == r; queued != wantQueued {
				t.Errorf("request queued = %t, want %t", queued, wantQueued)
			}
		})
	}
}

// A FUSE_INTERRUPT request queued for a request that is then abandoned (e.g.
// because the task must enter a stop) is still sent to the server, and the
// server's reply to it is rejected with ENOENT.
func TestAbandonRequestInterruptStillSent(t *testing.T) {
	conn := newBareConnection(t)
	r, fut := newSentRequest(t, conn, linux.FUSE_MKDIR)
	conn.fuseConn.interrupt(fut)
	if _, err := conn.abandonRequest(r, fut, false /* killed */, linuxerr.ErrInterrupted); err != linuxerr.ErrInterrupted {
		t.Fatalf("abandonRequest: got error %v, want ErrInterrupted", err)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if intr := conn.interrupts.Front(); intr == nil || intr.hdr.Unique != fut.unique|linux.FUSE_INT_REQ_BIT {
		t.Fatalf("FUSE_INTERRUPT request not queued for abandoned request %d", fut.unique)
	}
	if _, err := interruptReplyLocked(conn, fut.unique, unix.EAGAIN, linux.SizeOfFUSEHeaderOut); err != linuxerr.ENOENT {
		t.Errorf("reply to FUSE_INTERRUPT: got error %v, want ENOENT", err)
	}
}
