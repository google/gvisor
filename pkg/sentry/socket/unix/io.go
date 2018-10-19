// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

// EndpointWriter implements safemem.Writer that writes to a transport.Endpoint.
//
// EndpointWriter is not thread-safe.
type EndpointWriter struct {
	// Endpoint is the transport.Endpoint to write to.
	Endpoint transport.Endpoint

	// Control is the control messages to send.
	Control transport.ControlMessages

	// To is the endpoint to send to. May be nil.
	To transport.BoundEndpoint
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
func (w *EndpointWriter) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	return safemem.FromVecWriterFunc{func(bufs [][]byte) (int64, error) {
		n, err := w.Endpoint.SendMsg(bufs, w.Control, w.To)
		if err != nil {
			return int64(n), syserr.TranslateNetstackError(err).ToError()
		}
		return int64(n), nil
	}}.WriteFromBlocks(srcs)
}

// EndpointReader implements safemem.Reader that reads from a
// transport.Endpoint.
//
// EndpointReader is not thread-safe.
type EndpointReader struct {
	// Endpoint is the transport.Endpoint to read from.
	Endpoint transport.Endpoint

	// Creds indicates if credential control messages are requested.
	Creds bool

	// NumRights is the number of SCM_RIGHTS FDs requested.
	NumRights uintptr

	// Peek indicates that the data should not be consumed from the
	// endpoint.
	Peek bool

	// MsgSize is the size of the message that was read from. For stream
	// sockets, it is the amount read.
	MsgSize uintptr

	// From, if not nil, will be set with the address read from.
	From *tcpip.FullAddress

	// Control contains the received control messages.
	Control transport.ControlMessages
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (r *EndpointReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	return safemem.FromVecReaderFunc{func(bufs [][]byte) (int64, error) {
		n, ms, c, err := r.Endpoint.RecvMsg(bufs, r.Creds, r.NumRights, r.Peek, r.From)
		r.Control = c
		r.MsgSize = ms
		if err != nil {
			return int64(n), syserr.TranslateNetstackError(err).ToError()
		}
		return int64(n), nil
	}}.ReadToBlocks(dsts)
}
