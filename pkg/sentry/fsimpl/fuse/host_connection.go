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

var respBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, linux.FUSE_MIN_READ_BUFFER)
		return &b
	},
}

// hostConnection implements fuseConn for the host FD passthrough path.
// Instead of using the /dev/fuse device within the sandbox, it writes FUSE
// requests to and reads FUSE responses from a host FD. This allows a FUSE
// server running outside the sandbox to serve the filesystem.
//
// Multiple requests can be in flight concurrently. Writes are serialized by
// writeMu, while a background reader goroutine dispatches responses to callers
// via the connection's completions map.
type hostConnection struct {
	// conn holds shared FUSE connection state (protocol version, limits, etc).
	conn *connection

	// hostFD is the host file descriptor for the FUSE connection.
	hostFD int32

	// writeMu serializes write operations on hostFD.
	writeMu sync.Mutex
}

// newHostConnection creates a hostConnection that communicates over hostFD.
func newHostConnection(conn *connection, hostFD int32) *hostConnection {
	return &hostConnection{
		conn:   conn,
		hostFD: hostFD,
	}
}

// startReader launches the background goroutine that reads responses from the
// host FD and dispatches them to waiting callers. Must be called after the
// FUSE_INIT handshake completes.
func (hc *hostConnection) startReader() {
	go hc.readLoop()
}

// readLoop reads FUSE responses from the host FD and dispatches them to the
// corresponding callers via the connection's completions map.
func (hc *hostConnection) readLoop() {
	for {
		bufp := respBufPool.Get().(*[]byte)
		respBuf := (*bufp)[:linux.FUSE_MIN_READ_BUFFER]

		n, err := unix.Read(int(hc.hostFD), respBuf)
		if err != nil || n == 0 {
			respBufPool.Put(bufp)
			hc.abortPending()
			return
		}
		if n < int(linux.SizeOfFUSEHeaderOut) {
			respBufPool.Put(bufp)
			log.Warningf("fuse host connection: short read %d bytes, need at least %d", n, linux.SizeOfFUSEHeaderOut)
			continue
		}

		var hdr linux.FUSEHeaderOut
		hdr.UnmarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])

		if hdr.Len > uint32(n) {
			respBufPool.Put(bufp)
			log.Warningf("fuse host connection: response says %d bytes but only read %d", hdr.Len, n)
			continue
		}

		hc.conn.mu.Lock()
		fut, ok := hc.conn.completions[hdr.Unique]
		if ok {
			delete(hc.conn.completions, hdr.Unique)
			fut.hdr = &hdr
			copy(fut.buf[:], respBuf[:hdr.Len])
			fut.data = fut.buf[:hdr.Len]
			select {
			case hc.conn.fullQueueCh <- struct{}{}:
			default:
			}
			hc.conn.numActiveRequests--
			close(fut.ch)
		}
		hc.conn.mu.Unlock()
		respBufPool.Put(bufp)
	}
}

// abortPending wakes all callers blocked on a response with closed channels.
// Called when the reader goroutine exits due to an error or FD closure.
func (hc *hostConnection) abortPending() {
	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	for id, fut := range hc.conn.completions {
		delete(hc.conn.completions, id)
		hc.conn.numActiveRequests--
		close(fut.ch)
	}
}

// call implements fuseConn.call. It registers a futureResponse, writes the
// request to the host FD, and blocks until the reader goroutine dispatches
// the matching response.
func (hc *hostConnection) call(ctx context.Context, r *Request) (*Response, error) {
	hc.conn.mu.Lock()
	if !hc.conn.connected {
		hc.conn.mu.Unlock()
		return nil, linuxerr.ECONNABORTED
	}
	hc.conn.numActiveRequests++
	fut := newFutureResponse(r)
	hc.conn.completions[r.id] = fut
	hc.conn.mu.Unlock()

	if err := hc.writeRequest(r); err != nil {
		hc.conn.mu.Lock()
		delete(hc.conn.completions, r.id)
		hc.conn.numActiveRequests--
		hc.conn.mu.Unlock()
		return nil, err
	}

	return fut.resolve(ctx)
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

// writeRequest writes a FUSE request to the host FD under writeMu.
func (hc *hostConnection) writeRequest(r *Request) error {
	hc.writeMu.Lock()
	defer hc.writeMu.Unlock()
	data := r.data
	for len(data) > 0 {
		n, err := unix.Write(int(hc.hostFD), data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// InitSend performs the FUSE_INIT handshake synchronously over the host FD.
// After a successful handshake, it starts the background reader goroutine
// for concurrent request processing.
func (hc *hostConnection) InitSend(creds *auth.Credentials, pid uint32, hasSysAdminCap bool) error {
	in := linux.FUSEInitIn{
		Major:        linux.FUSE_KERNEL_VERSION,
		Minor:        linux.FUSE_KERNEL_MINOR_VERSION,
		MaxReadahead: fuseDefaultMaxReadahead,
		Flags:        fuseDefaultInitFlags,
	}

	req := hc.conn.NewRequest(creds, pid, 0, linux.FUSE_INIT, &in)

	if err := hc.writeRequest(req); err != nil {
		return err
	}

	respBuf := make([]byte, linux.FUSE_MIN_READ_BUFFER)
	n, err := unix.Read(int(hc.hostFD), respBuf)
	if err != nil {
		return err
	}
	if n < int(linux.SizeOfFUSEHeaderOut) {
		return linuxerr.EIO
	}

	var hdr linux.FUSEHeaderOut
	hdr.UnmarshalUnsafe(respBuf[:linux.SizeOfFUSEHeaderOut])

	res := &Response{
		opcode: linux.FUSE_INIT,
		hdr:    hdr,
		data:   respBuf[:hdr.Len],
	}

	hc.conn.mu.Lock()
	defer hc.conn.mu.Unlock()
	if err := hc.conn.InitRecv(res, hasSysAdminCap); err != nil {
		return err
	}

	hc.startReader()
	return nil
}
