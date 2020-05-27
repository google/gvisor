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

package flipcall

import (
	"fmt"
	"io"
)

// DatagramReader implements io.Reader by reading a datagram from an Endpoint's
// packet window. Its use is optional; users that can use Endpoint.Data() more
// efficiently are advised to do so.
type DatagramReader struct {
	ep  *Endpoint
	off uint32
	end uint32
}

// Init must be called on zero-value DatagramReaders before first use.
//
// Preconditions: dataLen is 0, or was returned by a previous call to
// ep.RecvFirst() or ep.SendRecv().
func (r *DatagramReader) Init(ep *Endpoint, dataLen uint32) {
	r.ep = ep
	r.Reset(dataLen)
}

// Reset causes r to begin reading a new datagram of the given length from the
// associated Endpoint.
//
// Preconditions: dataLen is 0, or was returned by a previous call to the
// associated Endpoint's RecvFirst() or SendRecv() methods.
func (r *DatagramReader) Reset(dataLen uint32) {
	if dataLen > r.ep.dataCap {
		panic(fmt.Sprintf("invalid dataLen (%d) > ep.dataCap (%d)", dataLen, r.ep.dataCap))
	}
	r.off = 0
	r.end = dataLen
}

// NewReader is a convenience function that returns an initialized
// DatagramReader allocated on the heap.
//
// Preconditions: dataLen was returned by a previous call to ep.RecvFirst() or
// ep.SendRecv().
func (ep *Endpoint) NewReader(dataLen uint32) *DatagramReader {
	r := &DatagramReader{}
	r.Init(ep, dataLen)
	return r
}

// Read implements io.Reader.Read.
func (r *DatagramReader) Read(dst []byte) (int, error) {
	n := copy(dst, r.ep.Data()[r.off:r.end])
	r.off += uint32(n)
	if r.off == r.end {
		return n, io.EOF
	}
	return n, nil
}

// DatagramWriter implements io.Writer by writing a datagram to an Endpoint's
// packet window. Its use is optional; users that can use Endpoint.Data() more
// efficiently are advised to do so.
type DatagramWriter struct {
	ep  *Endpoint
	off uint32
}

// Init must be called on zero-value DatagramWriters before first use.
func (w *DatagramWriter) Init(ep *Endpoint) {
	w.ep = ep
}

// Reset causes w to begin writing a new datagram to the associated Endpoint.
func (w *DatagramWriter) Reset() {
	w.off = 0
}

// NewWriter is a convenience function that returns an initialized
// DatagramWriter allocated on the heap.
func (ep *Endpoint) NewWriter() *DatagramWriter {
	w := &DatagramWriter{}
	w.Init(ep)
	return w
}

// Write implements io.Writer.Write.
func (w *DatagramWriter) Write(src []byte) (int, error) {
	n := copy(w.ep.Data()[w.off:w.ep.dataCap], src)
	w.off += uint32(n)
	if n != len(src) {
		return n, fmt.Errorf("datagram would exceed maximum size of %d bytes", w.ep.dataCap)
	}
	return n, nil
}

// Len returns the length of the written datagram.
func (w *DatagramWriter) Len() uint32 {
	return w.off
}
