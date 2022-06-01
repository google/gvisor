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

package transport

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// connectionlessEndpoint is a unix endpoint for unix sockets that support operating in
// a connectionless fashon.
//
// Specifically, this means datagram unix sockets not created with
// socketpair(2).
//
// +stateify savable
type connectionlessEndpoint struct {
	baseEndpoint
}

var (
	_ = BoundEndpoint((*connectionlessEndpoint)(nil))
	_ = Endpoint((*connectionlessEndpoint)(nil))
)

// NewConnectionless creates a new unbound dgram endpoint.
func NewConnectionless(ctx context.Context) Endpoint {
	ep := &connectionlessEndpoint{baseEndpoint{Queue: &waiter.Queue{}}}
	q := queue{ReaderQueue: ep.Queue, WriterQueue: &waiter.Queue{}, limit: defaultBufferSize}
	q.InitRefs()
	ep.receiver = &queueReceiver{readQueue: &q}
	ep.ops.InitHandler(ep, &stackHandler{}, getSendBufferLimits, getReceiveBufferLimits)
	ep.ops.SetSendBufferSize(defaultBufferSize, false /* notify */)
	ep.ops.SetReceiveBufferSize(defaultBufferSize, false /* notify */)
	return ep
}

// isBound returns true iff the endpoint is bound.
func (e *connectionlessEndpoint) isBound() bool {
	return e.path != ""
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it.
func (e *connectionlessEndpoint) Close(ctx context.Context) {
	e.Lock()
	connected := e.connected
	e.connected = nil

	if e.isBound() {
		e.path = ""
	}

	e.receiver.CloseRecv()
	r := e.receiver
	e.receiver = nil
	e.Unlock()

	if connected != nil {
		connected.Release(ctx)
	}
	r.CloseNotify()
	r.Release(ctx)
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *connectionlessEndpoint) BidirectionalConnect(ctx context.Context, ce ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) *syserr.Error {
	return syserr.ErrConnectionRefused
}

// UnidirectionalConnect implements BoundEndpoint.UnidirectionalConnect.
func (e *connectionlessEndpoint) UnidirectionalConnect(ctx context.Context) (ConnectedEndpoint, *syserr.Error) {
	e.Lock()
	r := e.receiver
	e.Unlock()
	if r == nil {
		return nil, syserr.ErrConnectionRefused
	}
	q := r.(*queueReceiver).readQueue
	if !q.TryIncRef() {
		return nil, syserr.ErrConnectionRefused
	}
	return &connectedEndpoint{
		endpoint:   e,
		writeQueue: q,
	}, nil
}

// SendMsg writes data and a control message to the specified endpoint.
// This method does not block if the data cannot be written.
func (e *connectionlessEndpoint) SendMsg(ctx context.Context, data [][]byte, c ControlMessages, to BoundEndpoint) (int64, func(), *syserr.Error) {
	if to == nil {
		return e.baseEndpoint.SendMsg(ctx, data, c, nil)
	}

	connected, err := to.UnidirectionalConnect(ctx)
	if err != nil {
		return 0, nil, syserr.ErrInvalidEndpointState
	}
	defer connected.Release(ctx)

	e.Lock()
	n, notify, err := connected.Send(ctx, data, c, tcpip.FullAddress{Addr: tcpip.Address(e.path)})
	e.Unlock()

	var notifyFn func()
	if notify {
		notifyFn = connected.SendNotify
	}

	return n, notifyFn, err
}

// Type implements Endpoint.Type.
func (e *connectionlessEndpoint) Type() linux.SockType {
	return linux.SOCK_DGRAM
}

// Connect attempts to connect directly to server.
func (e *connectionlessEndpoint) Connect(ctx context.Context, server BoundEndpoint) *syserr.Error {
	connected, err := server.UnidirectionalConnect(ctx)
	if err != nil {
		return err
	}

	e.Lock()
	if e.connected != nil {
		e.connected.Release(ctx)
	}
	e.connected = connected
	e.Unlock()

	return nil
}

// Listen starts listening on the connection.
func (*connectionlessEndpoint) Listen(context.Context, int) *syserr.Error {
	return syserr.ErrNotSupported
}

// Accept accepts a new connection.
func (*connectionlessEndpoint) Accept(context.Context, *tcpip.FullAddress) (Endpoint, *syserr.Error) {
	return nil, syserr.ErrNotSupported
}

// Bind binds the connection.
//
// For Unix endpoints, this _only sets the address associated with the socket_.
// Work associated with sockets in the filesystem or finding those sockets must
// be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionlessEndpoint) Bind(addr tcpip.FullAddress) *syserr.Error {
	e.Lock()
	defer e.Unlock()
	if e.isBound() {
		return syserr.ErrAlreadyBound
	}
	if addr.Addr == "" {
		// The empty string is not permitted.
		return syserr.ErrBadLocalAddress
	}

	// Save the bound address.
	e.path = string(addr.Addr)
	return nil
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *connectionlessEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	e.Lock()
	defer e.Unlock()

	ready := waiter.EventMask(0)
	if mask&waiter.ReadableEvents != 0 && e.receiver.Readable() {
		ready |= waiter.ReadableEvents
	}

	if e.Connected() {
		if mask&waiter.WritableEvents != 0 && e.connected.Writable() {
			ready |= waiter.WritableEvents
		}
	}

	return ready
}

// State implements socket.Socket.State.
func (e *connectionlessEndpoint) State() uint32 {
	e.Lock()
	defer e.Unlock()

	switch {
	case e.isBound():
		return linux.SS_UNCONNECTED
	case e.Connected():
		return linux.SS_CONNECTING
	default:
		return linux.SS_DISCONNECTING
	}
}

// OnSetSendBufferSize implements tcpip.SocketOptionsHandler.OnSetSendBufferSize.
func (e *connectionlessEndpoint) OnSetSendBufferSize(v int64) (newSz int64) {
	e.Lock()
	defer e.Unlock()
	if e.Connected() {
		return e.baseEndpoint.connected.SetSendBufferSize(v)
	}
	return v
}

// WakeupWriters implements tcpip.SocketOptionsHandler.WakeupWriters.
func (e *connectionlessEndpoint) WakeupWriters() {}
