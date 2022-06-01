// Copyright 2018 The gVisor Authors.
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

package unix

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// EndpointWriter implements safemem.Writer that writes to a transport.Endpoint.
//
// EndpointWriter is not thread-safe.
type EndpointWriter struct {
	Ctx context.Context

	// Endpoint is the transport.Endpoint to write to.
	Endpoint transport.Endpoint

	// Control is the control messages to send.
	Control transport.ControlMessages

	// To is the endpoint to send to. May be nil.
	To transport.BoundEndpoint

	// Notify is the receiver.SendNotify notification callback that is set
	// by WriteFromBlocks and should be called without mm.activeMu held
	// (i.e. after CopyOut completes).
	Notify func()
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (w *EndpointWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	return safemem.FromVecWriterFunc{func(bufs [][]byte) (int64, error) {
		n, notify, err := w.Endpoint.SendMsg(w.Ctx, bufs, w.Control, w.To)
		w.Notify = notify
		if err != nil {
			return int64(n), err.ToError()
		}
		return int64(n), nil
	}}.WriteFromBlocks(srcs)
}

// EndpointReader implements safemem.Reader that reads from a
// transport.Endpoint.
//
// EndpointReader is not thread-safe.
type EndpointReader struct {
	Ctx context.Context

	// Endpoint is the transport.Endpoint to read from.
	Endpoint transport.Endpoint

	// Creds indicates if credential control messages are requested.
	Creds bool

	// NumRights is the number of SCM_RIGHTS FDs requested.
	NumRights int

	// Peek indicates that the data should not be consumed from the
	// endpoint.
	Peek bool

	// MsgSize is the size of the message that was read from. For stream
	// sockets, it is the amount read.
	MsgSize int64

	// From, if not nil, will be set with the address read from.
	From *tcpip.FullAddress

	// Control contains the received control messages.
	Control transport.ControlMessages

	// ControlTrunc indicates that SCM_RIGHTS FDs were discarded based on
	// the value of NumRights.
	ControlTrunc bool

	// Notify is the ConnectedEndpoint.RecvNotify callback that is set by
	// ReadToBlocks and should be called without mm.activeMu held (i.e.
	// after CopyIn completes).
	Notify func()
}

// Truncate calls RecvMsg on the endpoint without writing to a destination.
func (r *EndpointReader) Truncate() error {
	// Ignore bytes read since it will always be zero.
	_, ms, c, ct, notify, err := r.Endpoint.RecvMsg(r.Ctx, [][]byte{}, r.Creds, r.NumRights, r.Peek, r.From)
	r.Control = c
	r.ControlTrunc = ct
	r.MsgSize = ms
	if notify != nil {
		notify()
	}
	if err != nil {
		return err.ToError()
	}
	return nil
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (r *EndpointReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	return safemem.FromVecReaderFunc{func(bufs [][]byte) (int64, error) {
		n, ms, c, ct, notify, err := r.Endpoint.RecvMsg(r.Ctx, bufs, r.Creds, r.NumRights, r.Peek, r.From)
		r.Control = c
		r.ControlTrunc = ct
		r.MsgSize = ms
		r.Notify = notify
		if err != nil {
			return int64(n), err.ToError()
		}
		return int64(n), nil
	}}.ReadToBlocks(dsts)
}
