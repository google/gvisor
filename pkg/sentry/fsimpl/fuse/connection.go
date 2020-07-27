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
	"gvisor.dev/gvisor/pkg/waiter"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// MaxActiveRequestsDefault is the default setting controlling the upper bound
// on the number of active requests at any given time.
const MaxActiveRequestsDefault = 10000

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

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	opcode linux.FUSEOpcode
	hdr    linux.FUSEHeaderOut
	data   []byte
}

// Connection is the struct by which the sentry communicates with the FUSE server daemon.
type Connection struct {
	fd *DeviceFD

	// MaxWrite is the daemon's maximum size of a write buffer.
	// This is negotiated during FUSE_INIT.
	MaxWrite uint32
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
	fuseFD.fullQueueCh = make(chan struct{}, maxInFlightRequests)
	fuseFD.writeCursor = 0

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

// Error returns the error of the FUSE call.
func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := syscall.Errno(-errno)
	return error(sysErrNo)
}

// UnmarshalPayload unmarshals the response data into m.
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

// callFuture makes a request to the server and returns a future response.
// Call resolve() when the response needs to be fulfilled.
func (conn *Connection) callFuture(t *kernel.Task, r *Request) (*futureResponse, error) {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()

	// Is the queue full?
	//
	// We must busy wait here until the request can be queued. We don't
	// block on the fd.fullQueueCh with a lock - so after being signalled,
	// before we acquire the lock, it is possible that a barging task enters
	// and queues a request. As a result, upon acquiring the lock we must
	// again check if the room is available.
	//
	// This can potentially starve a request forever but this can only happen
	// if there are always too many ongoing requests all the time. The
	// supported maxActiveRequests setting should be really high to avoid this.
	for conn.fd.numActiveRequests == conn.fd.fs.opts.maxActiveRequests {
		if t == nil {
			// Since there is no task that is waiting. We must error out.
			return nil, errors.New("FUSE request queue full")
		}

		log.Infof("Blocking request %v from being queued. Too many active requests: %v",
			r.id, conn.fd.numActiveRequests)
		conn.fd.mu.Unlock()
		err := t.Block(conn.fd.fullQueueCh)
		conn.fd.mu.Lock()
		if err != nil {
			return nil, err
		}
	}

	return conn.callFutureLocked(t, r)
}

// callFutureLocked makes a request to the server and returns a future response.
func (conn *Connection) callFutureLocked(t *kernel.Task, r *Request) (*futureResponse, error) {
	conn.fd.queue.PushBack(r)
	conn.fd.numActiveRequests += 1
	fut := newFutureResponse(r.hdr.Opcode)
	conn.fd.completions[r.id] = fut

	// Signal the readers that there is something to read.
	conn.fd.waitQueue.Notify(waiter.EventIn)

	return fut, nil
}

// futureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type futureResponse struct {
	opcode linux.FUSEOpcode
	ch     chan struct{}
	hdr    *linux.FUSEHeaderOut
	data   []byte
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse(opcode linux.FUSEOpcode) *futureResponse {
	return &futureResponse{
		opcode: opcode,
		ch:     make(chan struct{}),
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (f *futureResponse) resolve(t *kernel.Task) (*Response, error) {
	// If there is no Task associated with this request  - then we don't try to resolve
	// the response.  Instead, the task writing the response (proxy to the server) will
	// process the response on our behalf.
	if t == nil {
		log.Infof("fuse.Response.resolve: Not waiting on a response from server.")
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
		opcode: f.opcode,
		hdr:    *f.hdr,
		data:   f.data,
	}
}
