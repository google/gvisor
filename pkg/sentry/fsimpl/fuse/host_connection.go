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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

// hostConnection implements fuseConn for the host FD passthrough path.
// Instead of using the /dev/fuse device within the sandbox, it writes FUSE
// requests to and reads FUSE responses from a host FD. This allows a FUSE
// server running outside the sandbox to serve the filesystem.
//
// I/O is synchronous: each call() writes the full request and reads the full
// response while holding ioMu. Only one request can be in flight at a time.
type hostConnection struct {
	// conn holds shared FUSE connection state (protocol version, limits, etc).
	conn *connection

	// hostFD is the host file descriptor for /dev/fuse.
	hostFD int32

	// ioMu serializes read/write operations on hostFD.
	ioMu sync.Mutex
}

// newHostConnection creates a hostConnection that communicates over hostFD.
func newHostConnection(conn *connection, hostFD int32) *hostConnection {
	return &hostConnection{
		conn:   conn,
		hostFD: hostFD,
	}
}

// call implements fuseConn.call by performing synchronous I/O on the host FD.
func (hc *hostConnection) call(ctx context.Context, r *Request) (*Response, error) {
	return hc.doIO(r)
}

// Call makes a request to the server via the host FD and blocks until a
// response is received. It mirrors connection.Call but dispatches through the
// host I/O path.
func (hc *hostConnection) Call(ctx context.Context, r *Request) (*Response, error) {
	if !hc.conn.isInitialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := ctx.Block(hc.conn.initializedChan); err != nil {
			return nil, linuxError(err)
		}
	}

	hc.conn.mu.Lock()
	connected := hc.conn.connected
	connInitError := hc.conn.connInitError
	hc.conn.mu.Unlock()

	if !connected {
		return nil, linuxerr.ENOTCONN
	}

	if connInitError {
		return nil, linuxerr.ECONNREFUSED
	}

	return hc.call(ctx, r)
}

// CallAsync makes an async (fire-and-forget) request via the host FD. The
// response is read and discarded.
func (hc *hostConnection) CallAsync(ctx context.Context, r *Request) error {
	r.async = true
	_, err := hc.Call(ctx, r)
	return err
}

// release implements fuseConn.release.
func (hc *hostConnection) release(ctx context.Context) {
	hc.conn.DecRef(ctx)
	unix.Close(int(hc.hostFD))
}

// doIO performs the actual write-then-read on the host FD under ioMu.
func (hc *hostConnection) doIO(r *Request) (*Response, error) {
	hc.ioMu.Lock()
	defer hc.ioMu.Unlock()

	// Write the full request.
	data := r.data
	for len(data) > 0 {
		n, err := unix.Write(int(hc.hostFD), data)
		if err != nil {
			return nil, err
		}
		data = data[n:]
	}

	if r.noReply {
		return nil, nil
	}

	// Read the response. The host kernel delivers one complete response per
	// read(2) call on /dev/fuse.
	respBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	n, err := unix.Read(int(hc.hostFD), respBuf)
	if err != nil {
		return nil, err
	}
	if n < int(linux.SizeOfFUSEHeaderOut) {
		log.Warningf("fuse host connection: short read %d bytes, need at least %d", n, linux.SizeOfFUSEHeaderOut)
		return nil, linuxerr.EIO
	}
	respBuf = respBuf[:n]

	var hdr linux.FUSEHeaderOut
	hdr.UnmarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])

	if hdr.Len > uint32(n) {
		log.Warningf("fuse host connection: response says %d bytes but only read %d", hdr.Len, n)
		return nil, linuxerr.EIO
	}

	return &Response{
		opcode: r.hdr.Opcode,
		hdr:    hdr,
		data:   respBuf[:hdr.Len],
	}, nil
}

// InitSend performs the FUSE_INIT handshake synchronously over the host FD.
func (hc *hostConnection) InitSend(creds *auth.Credentials, pid uint32, hasSysAdminCap bool) error {
	in := linux.FUSEInitIn{
		Major:        linux.FUSE_KERNEL_VERSION,
		Minor:        linux.FUSE_KERNEL_MINOR_VERSION,
		MaxReadahead: fuseDefaultMaxReadahead,
		Flags:        fuseDefaultInitFlags,
	}

	req := hc.conn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)

	res, err := hc.doIO(req)
	if err != nil {
		return err
	}

	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	return hc.conn.InitRecv(res, hasSysAdminCap)
}
