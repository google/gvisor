// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unix

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/queue"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// connectionlessEndpoint is a unix endpoint for unix sockets that support operating in
// a conectionless fashon.
//
// Specifically, this means datagram unix sockets not created with
// socketpair(2).
type connectionlessEndpoint struct {
	baseEndpoint
}

// NewConnectionless creates a new unbound dgram endpoint.
func NewConnectionless() Endpoint {
	ep := &connectionlessEndpoint{baseEndpoint{Queue: &waiter.Queue{}}}
	ep.receiver = &queueReceiver{readQueue: queue.New(&waiter.Queue{}, ep.Queue, initialLimit)}
	return ep
}

// isBound returns true iff the endpoint is bound.
func (e *connectionlessEndpoint) isBound() bool {
	return e.path != ""
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionlessEndpoint) Close() {
	e.Lock()
	var r Receiver
	if e.Connected() {
		e.receiver.CloseRecv()
		r = e.receiver
		e.receiver = nil

		e.connected.Release()
		e.connected = nil
	}
	if e.isBound() {
		e.path = ""
	}
	e.Unlock()
	if r != nil {
		r.CloseNotify()
		r.Release()
	}
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *connectionlessEndpoint) BidirectionalConnect(ce ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) *tcpip.Error {
	return tcpip.ErrConnectionRefused
}

// UnidirectionalConnect implements BoundEndpoint.UnidirectionalConnect.
func (e *connectionlessEndpoint) UnidirectionalConnect() (ConnectedEndpoint, *tcpip.Error) {
	return &connectedEndpoint{
		endpoint:   e,
		writeQueue: e.receiver.(*queueReceiver).readQueue,
	}, nil
}

// SendMsg writes data and a control message to the specified endpoint.
// This method does not block if the data cannot be written.
func (e *connectionlessEndpoint) SendMsg(data [][]byte, c ControlMessages, to BoundEndpoint) (uintptr, *tcpip.Error) {
	if to == nil {
		return e.baseEndpoint.SendMsg(data, c, nil)
	}

	connected, err := to.UnidirectionalConnect()
	if err != nil {
		return 0, tcpip.ErrInvalidEndpointState
	}
	defer connected.Release()

	e.Lock()
	n, notify, err := connected.Send(data, c, tcpip.FullAddress{Addr: tcpip.Address(e.path)})
	e.Unlock()
	if err != nil {
		return 0, err
	}
	if notify {
		connected.SendNotify()
	}

	return n, nil
}

// Type implements Endpoint.Type.
func (e *connectionlessEndpoint) Type() SockType {
	return SockDgram
}

// Connect attempts to connect directly to server.
func (e *connectionlessEndpoint) Connect(server BoundEndpoint) *tcpip.Error {
	connected, err := server.UnidirectionalConnect()
	if err != nil {
		return err
	}

	e.Lock()
	e.connected = connected
	e.Unlock()

	return nil
}

// Listen starts listening on the connection.
func (e *connectionlessEndpoint) Listen(int) *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Accept accepts a new connection.
func (e *connectionlessEndpoint) Accept() (Endpoint, *tcpip.Error) {
	return nil, tcpip.ErrNotSupported
}

// Bind binds the connection.
//
// For Unix endpoints, this _only sets the address associated with the socket_.
// Work associated with sockets in the filesystem or finding those sockets must
// be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionlessEndpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	e.Lock()
	defer e.Unlock()
	if e.isBound() {
		return tcpip.ErrAlreadyBound
	}
	if addr.Addr == "" {
		// The empty string is not permitted.
		return tcpip.ErrBadLocalAddress
	}
	if commit != nil {
		if err := commit(); err != nil {
			return err
		}
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
	if mask&waiter.EventIn != 0 && e.receiver.Readable() {
		ready |= waiter.EventIn
	}

	if e.Connected() {
		if mask&waiter.EventOut != 0 && e.connected.Writable() {
			ready |= waiter.EventOut
		}
	}

	return ready
}
