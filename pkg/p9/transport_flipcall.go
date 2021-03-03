// Copyright 2019 The gVisor Authors.
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

package p9

import (
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fdchannel"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
)

// channelsPerClient is the number of channels to create per client.
//
// While the client and server will generally agree on this number, in reality
// it's completely up to the server. We simply define a minimum of 2, and a
// maximum of 4, and select the number of available processes as a tie-breaker.
// Note that we don't want the number of channels to be too large, because each
// will account for channelSize memory used, which can be large.
var channelsPerClient = func() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 4 {
		return 4
	}
	return n
}()

// channelSize is the channel size to create.
//
// We simply ensure that this is larger than the largest possible message size,
// plus the flipcall packet header, plus the two bytes we write below.
const channelSize = int(2 + flipcall.PacketHeaderBytes + 2 + maximumLength)

// channel is a fast IPC channel.
//
// The same object is used by both the server and client implementations. In
// general, the client will use only the send and recv methods.
type channel struct {
	desc flipcall.PacketWindowDescriptor
	data flipcall.Endpoint
	fds  fdchannel.Endpoint
	buf  buffer

	// -- client only --
	connected bool
	active    bool

	// -- server only --
	client *fd.FD
	done   chan struct{}
}

// reset resets the channel buffer.
func (ch *channel) reset(sz uint32) {
	ch.buf.data = ch.data.Data()[:sz]
}

// service services the channel.
func (ch *channel) service(cs *connState) error {
	rsz, err := ch.data.RecvFirst()
	if err != nil {
		return err
	}
	for rsz > 0 {
		m, err := ch.recv(nil, rsz)
		if err != nil {
			return err
		}
		r := cs.handle(m)
		msgRegistry.put(m)
		rsz, err = ch.send(r)
		if err != nil {
			return err
		}
	}
	return nil // Done.
}

// Shutdown shuts down the channel.
//
// This must be called before Close.
func (ch *channel) Shutdown() {
	ch.data.Shutdown()
}

// Close closes the channel.
//
// This must only be called once, and cannot return an error. Note that
// synchronization for this method is provided at a high-level, depending on
// whether it is the client or server. This cannot be called while there are
// active callers in either service or sendRecv.
//
// Precondition: the channel should be shutdown.
func (ch *channel) Close() error {
	// Close all backing transports.
	ch.fds.Destroy()
	ch.data.Destroy()
	if ch.client != nil {
		ch.client.Close()
	}
	return nil
}

// send sends the given message.
//
// The return value is the size of the received response. Not that in the
// server case, this is the size of the next request.
func (ch *channel) send(m message) (uint32, error) {
	if log.IsLogging(log.Debug) {
		log.Debugf("send [channel @%p] %s", ch, m.String())
	}

	// Send any file payload.
	sentFD := false
	if filer, ok := m.(filer); ok {
		if f := filer.FilePayload(); f != nil {
			if err := ch.fds.SendFD(f.FD()); err != nil {
				return 0, err
			}
			f.Close()     // Per sendRecvLegacy.
			sentFD = true // To mark below.
		}
	}

	// Encode the message.
	//
	// Note that IPC itself encodes the length of messages, so we don't
	// need to encode a standard 9P header. We write only the message type.
	ch.reset(0)

	ch.buf.WriteMsgType(m.Type())
	if sentFD {
		ch.buf.Write8(1) // Incoming FD.
	} else {
		ch.buf.Write8(0) // No incoming FD.
	}
	m.encode(&ch.buf)
	ssz := uint32(len(ch.buf.data)) // Updated below.

	// Is there a payload?
	if payloader, ok := m.(payloader); ok {
		p := payloader.Payload()
		copy(ch.data.Data()[ssz:], p)
		ssz += uint32(len(p))
	}

	// Perform the one-shot communication.
	return ch.data.SendRecv(ssz)
}

// recv decodes a message that exists on the channel.
//
// If the passed r is non-nil, then the type must match or an error will be
// generated. If the passed r is nil, then a new message will be created and
// returned.
func (ch *channel) recv(r message, rsz uint32) (message, error) {
	// Decode the response from the inline buffer.
	ch.reset(rsz)
	t := ch.buf.ReadMsgType()
	hasFD := ch.buf.Read8() != 0
	if t == MsgRlerror {
		// Change the message type. We check for this special case
		// after decoding below, and transform into an error.
		r = &Rlerror{}
	} else if r == nil {
		nr, err := msgRegistry.get(0, t)
		if err != nil {
			return nil, err
		}
		r = nr // New message.
	} else if t != r.Type() {
		// Not an error and not the expected response; propagate.
		return nil, &ErrBadResponse{Got: t, Want: r.Type()}
	}

	// Is there a payload? Copy from the latter portion.
	if payloader, ok := r.(payloader); ok {
		fs := payloader.FixedSize()
		p := payloader.Payload()
		payloadData := ch.buf.data[fs:]
		if len(p) < len(payloadData) {
			p = make([]byte, len(payloadData))
			copy(p, payloadData)
			payloader.SetPayload(p)
		} else if n := copy(p, payloadData); n < len(p) {
			payloader.SetPayload(p[:n])
		}
		ch.buf.data = ch.buf.data[:fs]
	}

	r.decode(&ch.buf)
	if ch.buf.isOverrun() {
		// Nothing valid was available.
		log.Debugf("recv [got %d bytes, needed more]", rsz)
		return nil, ErrNoValidMessage
	}

	// Read any FD result.
	if hasFD {
		if rfd, err := ch.fds.RecvFDNonblock(); err == nil {
			f := fd.New(rfd)
			if filer, ok := r.(filer); ok {
				// Set the payload.
				filer.SetFilePayload(f)
			} else {
				// Don't want the FD.
				f.Close()
			}
		} else {
			// The header bit was set but nothing came in.
			log.Warningf("expected FD, got err: %v", err)
		}
	}

	// Log a message.
	if log.IsLogging(log.Debug) {
		log.Debugf("recv [channel @%p] %s", ch, r.String())
	}

	// Convert errors appropriately; see above.
	if rlerr, ok := r.(*Rlerror); ok {
		return r, unix.Errno(rlerr.Error)
	}

	return r, nil
}
