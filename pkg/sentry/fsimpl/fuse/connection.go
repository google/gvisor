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
	"errors"
	"fmt"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

const MaxInFlightRequestsDefault = 1000

var (
	// Ordinary requests have even IDs, while interrupts IDs are odd.
	InitReqBit uint64 = 1
	ReqIDStep  uint64 = 2
)

// Request represents a FUSE operation request that hasn't been sent to the
// server yet.
//
// +stateify savable
type Request struct {
	requestEntry

	id   linux.FUSEOpID
	hdr  *linux.FUSEHeaderIn
	data []byte
}

// futureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type futureResponse struct {
	ch   chan struct{}
	hdr  *linux.FUSEHeaderOut
	data []byte
}

// Connection is the struct by which the sentry communicates with the FUSE server daemon.
type Connection struct {
	fd *DeviceFD
}

// NewFUSEConnection creates a FUSE connection to fd
func NewFUSEConnection(_ context.Context, fd *vfs.FileDescription, maxInFlightRequests uint64) (*Connection, error) {
	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	fuseFD := fd.Impl().(*DeviceFD)
	fuseFD.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	fuseFD.writeBuf = make([]byte, hdrLen)
	fuseFD.completions = make(map[linux.FUSEOpID]*futureResponse)
	fuseFD.requestKind = make(map[linux.FUSEOpID]linux.FUSEOpcode)
	fuseFD.emptyQueueCh = make(chan struct{}, maxInFlightRequests)
	fuseFD.fullQueueCh = make(chan struct{}, maxInFlightRequests)

	// This is emulating the behaviour of a counting semaphore. Is there a better
	// way to do this?
	for i := uint64(0); i < maxInFlightRequests; i++ {
		fuseFD.fullQueueCh <- struct{}{}
	}

	fuseFD.writeCursor = 0
	fuseFD.readCursor = 0

	return &Connection{
		fd: fuseFD,
	}, nil
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *Connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (*Request, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()
	conn.fd.nextOpID += linux.FUSEOpID(ReqIDStep)

	hdrLen := (*linux.FUSEHeaderIn)(nil).SizeBytes()
	hdr := linux.FUSEHeaderIn{
		Len:    uint32(hdrLen + payload.SizeBytes()),
		Opcode: opcode,
		Unique: conn.fd.nextOpID,
		NodeID: ino,
		UID:    uint32(creds.EffectiveKUID),
		GID:    uint32(creds.EffectiveKGID),
		PID:    pid,
	}

	buf := make([]byte, hdr.Len)
	hdr.MarshalUnsafe(buf[:hdrLen])
	payload.MarshalUnsafe(buf[hdrLen:])

	return &Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}, nil
}

// Call makes a request to the server and blocks the invoking task until a
// server responds with a response.
// NOTE: If no task is provided then the Call will simply enqueue the request
// and return a nil response. No blocking will happen in this case. Instead,
// this is used to signify that the processing of this request will happen by
// the kernel.Task that writes the response. See FUSE_INIT for such an
// invocation.
func (conn *Connection) Call(t *kernel.Task, r *Request) (*Response, error) {
	fut, err := conn.callFuture(t, r)
	if err != nil {
		return nil, err
	}

	return fut.resolve(t)
}

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *Connection) callFuture(t *kernel.Task, r *Request) (*futureResponse, error) {
	// Is the queue full?
	if conn.fd.numInFlightRequests == conn.fd.fs.opts.maxInflightRequests {
		// Can't add a new request into the queue until space is cleared up.
		if t == nil {
			// Since there is no task that is waiting. We must error out.
			return nil, errors.New("FUSE request queue full")
		}
	}

	// Consider possible starvation here if the queue is continuously full.
	// Will go channels respect FIFO order when unblocking threads?
	if err := t.Block(conn.fd.fullQueueCh); err != nil {
		log.Warningf("Connection.Call: couldn't wait on request queue: %v", err)
		return nil, syserror.EBUSY
	}

	conn.fd.mu.Lock()
	conn.fd.queue.PushBack(r)
	conn.fd.numInFlightRequests += 1
	fut := newFutureResponse()
	conn.fd.completions[r.id] = fut
	conn.fd.requestKind[r.id] = r.hdr.Opcode
	conn.fd.mu.Unlock()

	// Signal a reader notifying them about a queued request.
	select {
	case conn.fd.emptyQueueCh <- struct{}{}:
	default:
		log.Warningf("fuse.Connection: blocking when signalling the emptyQueueCh")
	}

	return fut, nil
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse() *futureResponse {
	return &futureResponse{
		ch: make(chan struct{}),
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (f *futureResponse) resolve(t *kernel.Task) (*Response, error) {
	// If there is no Task associated with this request  - then we don't try to resolve
	// the response.  Instead, the task writing the response (proxy to the server) will
	// process the response on our behalf.
	if t == nil {
		log.Infof("fuse.Response: Not waiting on a response from server.")
		return nil, nil
	}

	if err := t.Block(f.ch); err != nil {
		return nil, err
	}

	return f.getResponse(), nil
}

// getResponse creates a Response from the data the futureResponse has.
func (f *futureResponse) getResponse() *Response {
	return &Response{
		hdr:  *f.hdr,
		data: f.data,
	}
}

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	hdr  linux.FUSEHeaderOut
	data []byte
}

func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := syscall.Errno(-errno)
	return error(sysErrNo)
}

func (r *Response) UnmarshalPayload(m marshal.Marshallable) error {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		return fmt.Errorf("payload too small. Minimum data lenth required: %d,  but got data length %d", wantDataLen, haveDataLen)
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
	return nil
}
