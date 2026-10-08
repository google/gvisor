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

	// closed is true once hostFD has been closed by release.
	//
	// +checklocks:writeMu
	closed bool
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
		if hdr.Unique&linux.FUSE_INT_REQ_BIT != 0 {
			// Reply to a FUSE_INTERRUPT request.
			fut, err := hc.conn.handleInterruptReplyLocked(&hdr, int64(hdr.Len))
			hc.conn.mu.Unlock()
			respBufPool.Put(bufp)
			if err != nil {
				// ENOENT is expected if the interrupted request has been
				// answered or abandoned in the meantime.
				if !linuxerr.Equals(linuxerr.ENOENT, err) {
					log.Warningf("fuse host connection: invalid FUSE_INTERRUPT reply for request %d: %v", hdr.Unique&^linux.FUSE_INT_REQ_BIT, err)
				}
			} else if fut != nil {
				// The server asked us to re-send the interrupt. Don't
				// block the reader goroutine on the write.
				go hc.sendInterrupt(fut.unique)
			}
			continue
		}
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
		fut.hdr = &linux.FUSEHeaderOut{
			Len:    linux.SizeOfFUSEHeaderOut,
			Error:  -int32(unix.ECONNABORTED),
			Unique: id,
		}
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
	// The request is written synchronously below, before we wait for the
	// response, so it can be considered sent for the purposes of interrupts.
	fut.sent = true
	hc.conn.completions[r.id] = fut
	hc.conn.mu.Unlock()

	if err := hc.writeRequest(r); err != nil {
		hc.conn.mu.Lock()
		delete(hc.conn.completions, r.id)
		hc.conn.numActiveRequests--
		hc.conn.mu.Unlock()
		return nil, linuxError(err)
	}

	if fut.async {
		return nil, nil
	}
	return hc.conn.waitForResponse(ctx, r, fut)
}

// interrupt implements fuseConn.interrupt.
func (hc *hostConnection) interrupt(fut *futureResponse) {
	hc.conn.mu.Lock()
	ok := hc.conn.markInterruptedLocked(fut)
	hc.conn.mu.Unlock()
	if ok {
		hc.sendInterrupt(fut.unique)
	}
}

// sendInterrupt sends a FUSE_INTERRUPT request for the request with the given
// unique ID.
func (hc *hostConnection) sendInterrupt(unique linux.FUSEOpID) {
	if err := hc.writeRequest(newInterruptRequest(unique)); err != nil {
		log.Warningf("fuse host connection: failed to send FUSE_INTERRUPT for request %d: %v", unique, err)
	}
}

// Call makes a request to the server via the host FD and blocks until a
// response is received. It mirrors connection.Call but dispatches through the
// host I/O path.
func (hc *hostConnection) Call(ctx context.Context, r *Request) (*Response, error) {
	if !hc.conn.isInitialized() && r.hdr.Opcode != linux.FUSE_INIT {
		if err := blockKillable(ctx, hc.conn.initializedChan); err != nil {
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

	res, err := hc.call(ctx, r)
	return res, linuxError(err)
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
	// Hold writeMu so that concurrent writers (e.g. FUSE_INTERRUPT requests)
	// don't write to a closed, and possibly reused, FD.
	hc.writeMu.Lock()
	defer hc.writeMu.Unlock()
	if !hc.closed {
		hc.closed = true
		unix.Close(int(hc.hostFD))
	}
}

// writeRequest writes a FUSE request to the host FD under writeMu.
func (hc *hostConnection) writeRequest(r *Request) error {
	hc.writeMu.Lock()
	defer hc.writeMu.Unlock()
	if hc.closed {
		return unix.EBADF
	}
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
		// Each request is a single SOCK_SEQPACKET datagram, which
		// writeRequest cannot fragment.
		Flags: fuseDefaultInitFlags &^ fuseDatagramUnsafeInitFlags,
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
	// Big writes stay off even if the server echoes the flag unsolicited;
	// the transport cannot carry them.
	hc.conn.bigWrites = false

	hc.startReader()
	return nil
}
