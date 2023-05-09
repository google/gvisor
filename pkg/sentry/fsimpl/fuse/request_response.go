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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// fuseInitRes is a variable-length wrapper of linux.FUSEInitOut. The FUSE
// server may implement an older version of FUSE protocol, which contains a
// linux.FUSEInitOut with less attributes.
//
// +marshal dynamic
type fuseInitRes struct {
	// initOut contains the response from the FUSE server.
	initOut linux.FUSEInitOut

	// initLen is the total length of bytes of the response.
	initLen uint32
}

func (r *fuseInitRes) MarshalBytes(src []byte) []byte {
	panic("Unimplemented, fuseInitRes should never be marshalled")
}

// UnmarshalBytes deserializes src to the initOut attribute in a fuseInitRes.
func (r *fuseInitRes) UnmarshalBytes(src []byte) []byte {
	out := &r.initOut

	// Introduced before FUSE kernel version 7.13.
	out.Major = uint32(hostarch.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.Minor = uint32(hostarch.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.MaxReadahead = uint32(hostarch.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.Flags = uint32(hostarch.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.MaxBackground = uint16(hostarch.ByteOrder.Uint16(src[:2]))
	src = src[2:]
	out.CongestionThreshold = uint16(hostarch.ByteOrder.Uint16(src[:2]))
	src = src[2:]
	out.MaxWrite = uint32(hostarch.ByteOrder.Uint32(src[:4]))
	src = src[4:]

	// Introduced in FUSE kernel version 7.23.
	if len(src) >= 4 {
		out.TimeGran = uint32(hostarch.ByteOrder.Uint32(src[:4]))
		src = src[4:]
	}
	// Introduced in FUSE kernel version 7.28.
	if len(src) >= 2 {
		out.MaxPages = uint16(hostarch.ByteOrder.Uint16(src[:2]))
		src = src[2:]
	}
	return src
}

// SizeBytes is the size of the payload of the FUSE_INIT response.
func (r *fuseInitRes) SizeBytes() int {
	return int(r.initLen)
}

// Ordinary requests have even IDs, while interrupts IDs are odd.
// Used to increment the unique ID for each FUSE request.
var reqIDStep uint64 = 2

// Request represents a FUSE operation request that hasn't been sent to the
// server yet.
//
// +stateify savable
type Request struct {
	requestEntry

	id   linux.FUSEOpID
	hdr  *linux.FUSEHeaderIn
	data []byte

	// If this request is async.
	async bool
	// If we don't care its response.
	// Manually set by the caller.
	noReply bool
}

// NewRequest creates a new request that can be sent to the FUSE server.
func (conn *connection) NewRequest(creds *auth.Credentials, pid uint32, ino uint64, opcode linux.FUSEOpcode, payload marshal.Marshallable) *Request {
	conn.fd.mu.Lock()
	defer conn.fd.mu.Unlock()
	conn.fd.nextOpID += linux.FUSEOpID(reqIDStep)

	hdr := linux.FUSEHeaderIn{
		Len:    linux.SizeOfFUSEHeaderIn + uint32(payload.SizeBytes()),
		Opcode: opcode,
		Unique: conn.fd.nextOpID,
		NodeID: ino,
		UID:    uint32(creds.EffectiveKUID),
		GID:    uint32(creds.EffectiveKGID),
		PID:    pid,
	}

	buf := make([]byte, hdr.Len)

	hdr.MarshalUnsafe(buf[:linux.SizeOfFUSEHeaderIn])
	payload.MarshalUnsafe(buf[linux.SizeOfFUSEHeaderIn:])

	return &Request{
		id:   hdr.Unique,
		hdr:  &hdr,
		data: buf,
	}
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

	// If this request is async.
	async bool
}

// newFutureResponse creates a future response to a FUSE request.
func newFutureResponse(req *Request) *futureResponse {
	return &futureResponse{
		opcode: req.hdr.Opcode,
		ch:     make(chan struct{}),
		async:  req.async,
	}
}

// resolve blocks the task until the server responds to its corresponding request,
// then returns a resolved response.
func (f *futureResponse) resolve(t *kernel.Task) (*Response, error) {
	// Return directly for async requests.
	if f.async {
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

// Response represents an actual response from the server, including the
// response payload.
//
// +stateify savable
type Response struct {
	opcode linux.FUSEOpcode
	hdr    linux.FUSEHeaderOut
	data   []byte
}

// Error returns the error of the FUSE call.
func (r *Response) Error() error {
	errno := r.hdr.Error
	if errno >= 0 {
		return nil
	}

	sysErrNo := unix.Errno(-errno)
	return error(sysErrNo)
}

// DataLen returns the size of the response without the header.
func (r *Response) DataLen() uint32 {
	return r.hdr.Len - uint32(r.hdr.SizeBytes())
}

// UnmarshalPayload unmarshals the response data into m.
func (r *Response) UnmarshalPayload(m marshal.Marshallable) error {
	hdrLen := r.hdr.SizeBytes()
	haveDataLen := r.hdr.Len - uint32(hdrLen)
	wantDataLen := uint32(m.SizeBytes())

	if haveDataLen < wantDataLen {
		log.Warningf("fusefs: Payload too small. Minimum data length required: %d, but got data length %d", wantDataLen, haveDataLen)
		return linuxerr.EINVAL

	}

	// The response data is empty unless there is some payload. And so, doesn't
	// need to be unmarshalled.
	if r.data == nil {
		return nil
	}

	m.UnmarshalUnsafe(r.data[hdrLen:])
	return nil
}
