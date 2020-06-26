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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
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

// FutureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
//
// +stateify savable
type FutureResponse struct {
	ch   chan struct{}
	hdr  *linux.FUSEHeaderOut
	data []byte
}

// Connection is the interface by which the sentry communicates with the FUSE server daemon.
type Connection interface {
	// NewRequest creates a new request that can be sent to the FUSE server.
	NewRequest(creds auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (Request, error)

	// Call makes a request to the server and blocks until a server responds with a response.
    Call(t *kernel.Task, r *Request) (*Response, error)

	// CallFuture makes a request to the server and returns a future response. Call Resolve()
	// when the response needs to be fulfilled.
	CallFuture(t *kernel.Task, r *Request) (*FutureResponse, error)
}

func NewFUSEConnection(ctx context.Context,  fd *vfs.FileDescription) Connection {

	// Mark the device as ready so it can be used. /dev/fuse can only be used if the FD was used to
	// mount a FUSE filesystem.
	fuseFD := fd.Impl().(*DeviceFD)
	fuseFD.mounted = true

	// Create the writeBuf for the header to be stored in.
	hdrLen := uint32((*linux.FUSEHeaderOut)(nil).SizeBytes())
	fuseFD.writeBuf = make([]byte, hdrLen)

	return fuseFD
}

// NewRequest implements fuse.Connection.NewRequest.
func (fd *DeviceFD) NewRequest(creds auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) (Request, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	hdrLen := (*linux.FUSEHeaderIn)(nil).SizeBytes()
	hdr := linux.FUSEHeaderIn{
		Len:    uint32(hdrLen + payload.SizeBytes()),
		Opcode: opcode,
		Unique: fd.nextOpID,
		NodeID: ino,
		UID:    uint32(creds.EffectiveKUID),
		GID:    uint32(creds.EffectiveKGID),
		PID:    pid,
	}
	fd.nextOpID++

	buf := make([]byte, hdr.Len)
	hdr.MarshalUnsafe(buf[:hdrLen])
	payload.MarshalUnsafe(buf[hdrLen:])

	return Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}, nil
}

// Call implements fuse.Connection.Call.
func (fd *DeviceFD) Call(t *kernel.Task, r *Request) (*Response, error) {
	fut, err := fd.CallFuture(t, r)
	if err != nil {
		return nil, err
	}

	return fut.Resolve(t)
}

func (fd *DeviceFD) CallFuture(t *kernel.Task, r *Request) (*FutureResponse, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	fd.queue.PushBack(r)
	fut := newFutureResponse()
	fd.completions[r.id] = fut
	return fut, nil
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse() *FutureResponse {
	return &FutureResponse{
		ch: make(chan struct{}),
	}
}

// Resolve blocks until the server responds to its corresponding request, then
// returns a resolved response.
func (r *FutureResponse) Resolve(t *kernel.Task) (*Response, error) {
	// TODO: Consider blocking with a timeout.
	if err := t.Block(r.ch); err != nil {
		return nil, err
	}

	return &Response{
		hdr:  *r.hdr,
		data: r.data,
	}, nil
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
	// TODO: Map r.hdr.Error to some error in the syserror package.
	return nil
}

func (r *Response) UnmarshalPayload(m marshal.Marshallable) {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		// Somehow return an error.
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
}
