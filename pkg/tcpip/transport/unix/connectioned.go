// Copyright 2018 Google Inc.
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/queue"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// UniqueIDProvider generates a sequence of unique identifiers useful for,
// among other things, lock ordering.
type UniqueIDProvider interface {
	// UniqueID returns a new unique identifier.
	UniqueID() uint64
}

// A ConnectingEndpoint is a connectioned unix endpoint that is attempting to
// establish a bidirectional connection with a BoundEndpoint.
type ConnectingEndpoint interface {
	// ID returns the endpoint's globally unique identifier. This identifier
	// must be used to determine locking order if more than one endpoint is
	// to be locked in the same codepath. The endpoint with the smaller
	// identifier must be locked before endpoints with larger identifiers.
	ID() uint64

	// Passcred implements socket.Credentialer.Passcred.
	Passcred() bool

	// Type returns the socket type, typically either SockStream or
	// SockSeqpacket. The connection attempt must be aborted if this
	// value doesn't match the ConnectableEndpoint's type.
	Type() SockType

	// GetLocalAddress returns the bound path.
	GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

	// Locker protects the following methods. While locked, only the holder of
	// the lock can change the return value of the protected methods.
	sync.Locker

	// Connected returns true iff the ConnectingEndpoint is in the connected
	// state. ConnectingEndpoints can only be connected to a single endpoint,
	// so the connection attempt must be aborted if this returns true.
	Connected() bool

	// Listening returns true iff the ConnectingEndpoint is in the listening
	// state. ConnectingEndpoints cannot make connections while listening, so
	// the connection attempt must be aborted if this returns true.
	Listening() bool

	// WaiterQueue returns a pointer to the endpoint's waiter queue.
	WaiterQueue() *waiter.Queue
}

// connectionedEndpoint is a Unix-domain connected or connectable endpoint and implements
// ConnectingEndpoint, ConnectableEndpoint and tcpip.Endpoint.
//
// connectionedEndpoints must be in connected state in order to transfer data.
//
// This implementation includes STREAM and SEQPACKET Unix sockets created with
// socket(2), accept(2) or socketpair(2) and dgram unix sockets created with
// socketpair(2). See unix_connectionless.go for the implementation of DGRAM
// Unix sockets created with socket(2).
//
// The state is much simpler than a TCP endpoint, so it is not encoded
// explicitly. Instead we enforce the following invariants:
//
// receiver != nil, connected != nil => connected.
// path != "" && acceptedChan == nil => bound, not listening.
// path != "" && acceptedChan != nil => bound and listening.
//
// Only one of these will be true at any moment.
type connectionedEndpoint struct {
	baseEndpoint

	// id is the unique endpoint identifier. This is used exclusively for
	// lock ordering within connect.
	id uint64

	// idGenerator is used to generate new unique endpoint identifiers.
	idGenerator UniqueIDProvider

	// stype is used by connecting sockets to ensure that they are the
	// same type. The value is typically either tcpip.SockSeqpacket or
	// tcpip.SockStream.
	stype SockType

	// acceptedChan is per the TCP endpoint implementation. Note that the
	// sockets in this channel are _already in the connected state_, and
	// have another associated connectionedEndpoint.
	//
	// If nil, then no listen call has been made.
	acceptedChan chan *connectionedEndpoint `state:".([]*connectionedEndpoint)"`
}

// NewConnectioned creates a new unbound connectionedEndpoint.
func NewConnectioned(stype SockType, uid UniqueIDProvider) Endpoint {
	return &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           uid.UniqueID(),
		idGenerator:  uid,
		stype:        stype,
	}
}

// NewPair allocates a new pair of connected unix-domain connectionedEndpoints.
func NewPair(stype SockType, uid UniqueIDProvider) (Endpoint, Endpoint) {
	a := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           uid.UniqueID(),
		idGenerator:  uid,
		stype:        stype,
	}
	b := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           uid.UniqueID(),
		idGenerator:  uid,
		stype:        stype,
	}

	q1 := queue.New(a.Queue, b.Queue, initialLimit)
	q2 := queue.New(b.Queue, a.Queue, initialLimit)

	if stype == SockStream {
		a.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q1}}
		b.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q2}}
	} else {
		a.receiver = &queueReceiver{q1}
		b.receiver = &queueReceiver{q2}
	}

	a.connected = &connectedEndpoint{
		endpoint:   b,
		writeQueue: q2,
	}
	b.connected = &connectedEndpoint{
		endpoint:   a,
		writeQueue: q1,
	}

	return a, b
}

// ID implements ConnectingEndpoint.ID.
func (e *connectionedEndpoint) ID() uint64 {
	return e.id
}

// Type implements ConnectingEndpoint.Type and Endpoint.Type.
func (e *connectionedEndpoint) Type() SockType {
	return e.stype
}

// WaiterQueue implements ConnectingEndpoint.WaiterQueue.
func (e *connectionedEndpoint) WaiterQueue() *waiter.Queue {
	return e.Queue
}

// isBound returns true iff the connectionedEndpoint is bound (but not
// listening).
func (e *connectionedEndpoint) isBound() bool {
	return e.path != "" && e.acceptedChan == nil
}

// Listening implements ConnectingEndpoint.Listening.
func (e *connectionedEndpoint) Listening() bool {
	return e.acceptedChan != nil
}

// Close puts the connectionedEndpoint in a closed state and frees all
// resources associated with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionedEndpoint) Close() {
	e.Lock()
	var c ConnectedEndpoint
	var r Receiver
	switch {
	case e.Connected():
		e.connected.CloseSend()
		e.receiver.CloseRecv()
		c = e.connected
		r = e.receiver
		e.connected = nil
		e.receiver = nil
	case e.isBound():
		e.path = ""
	case e.Listening():
		close(e.acceptedChan)
		for n := range e.acceptedChan {
			n.Close()
		}
		e.acceptedChan = nil
		e.path = ""
	}
	e.Unlock()
	if c != nil {
		c.CloseNotify()
		c.Release()
	}
	if r != nil {
		r.CloseNotify()
		r.Release()
	}
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *connectionedEndpoint) BidirectionalConnect(ce ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) *tcpip.Error {
	if ce.Type() != e.stype {
		return tcpip.ErrConnectionRefused
	}

	// Check if ce is e to avoid a deadlock.
	if ce, ok := ce.(*connectionedEndpoint); ok && ce == e {
		return tcpip.ErrInvalidEndpointState
	}

	// Do a dance to safely acquire locks on both endpoints.
	if e.id < ce.ID() {
		e.Lock()
		ce.Lock()
	} else {
		ce.Lock()
		e.Lock()
	}

	// Check connecting state.
	if ce.Connected() {
		e.Unlock()
		ce.Unlock()
		return tcpip.ErrAlreadyConnected
	}
	if ce.Listening() {
		e.Unlock()
		ce.Unlock()
		return tcpip.ErrInvalidEndpointState
	}

	// Check bound state.
	if !e.Listening() {
		e.Unlock()
		ce.Unlock()
		return tcpip.ErrConnectionRefused
	}

	// Create a newly bound connectionedEndpoint.
	ne := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{
			path:  e.path,
			Queue: &waiter.Queue{},
		},
		id:          e.idGenerator.UniqueID(),
		idGenerator: e.idGenerator,
		stype:       e.stype,
	}
	readQueue := queue.New(ce.WaiterQueue(), ne.Queue, initialLimit)
	writeQueue := queue.New(ne.Queue, ce.WaiterQueue(), initialLimit)
	ne.connected = &connectedEndpoint{
		endpoint:   ce,
		writeQueue: readQueue,
	}
	if e.stype == SockStream {
		ne.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{readQueue: writeQueue}}
	} else {
		ne.receiver = &queueReceiver{readQueue: writeQueue}
	}

	select {
	case e.acceptedChan <- ne:
		// Commit state.
		connected := &connectedEndpoint{
			endpoint:   ne,
			writeQueue: writeQueue,
		}
		if e.stype == SockStream {
			returnConnect(&streamQueueReceiver{queueReceiver: queueReceiver{readQueue: readQueue}}, connected)
		} else {
			returnConnect(&queueReceiver{readQueue: readQueue}, connected)
		}

		// Notify can deadlock if we are holding these locks.
		e.Unlock()
		ce.Unlock()

		// Notify on both ends.
		e.Notify(waiter.EventIn)
		ce.WaiterQueue().Notify(waiter.EventOut)

		return nil
	default:
		// Busy; return ECONNREFUSED per spec.
		ne.Close()
		e.Unlock()
		ce.Unlock()
		return tcpip.ErrConnectionRefused
	}
}

// UnidirectionalConnect implements BoundEndpoint.UnidirectionalConnect.
func (e *connectionedEndpoint) UnidirectionalConnect() (ConnectedEndpoint, *tcpip.Error) {
	return nil, tcpip.ErrConnectionRefused
}

// Connect attempts to directly connect to another Endpoint.
// Implements Endpoint.Connect.
func (e *connectionedEndpoint) Connect(server BoundEndpoint) *tcpip.Error {
	returnConnect := func(r Receiver, ce ConnectedEndpoint) {
		e.receiver = r
		e.connected = ce
	}

	return server.BidirectionalConnect(e, returnConnect)
}

// Listen starts listening on the connection.
func (e *connectionedEndpoint) Listen(backlog int) *tcpip.Error {
	e.Lock()
	defer e.Unlock()
	if e.Listening() {
		// Adjust the size of the channel iff we can fix existing
		// pending connections into the new one.
		if len(e.acceptedChan) > backlog {
			return tcpip.ErrInvalidEndpointState
		}
		origChan := e.acceptedChan
		e.acceptedChan = make(chan *connectionedEndpoint, backlog)
		close(origChan)
		for ep := range origChan {
			e.acceptedChan <- ep
		}
		return nil
	}
	if !e.isBound() {
		return tcpip.ErrInvalidEndpointState
	}

	// Normal case.
	e.acceptedChan = make(chan *connectionedEndpoint, backlog)
	return nil
}

// Accept accepts a new connection.
func (e *connectionedEndpoint) Accept() (Endpoint, *tcpip.Error) {
	e.Lock()
	defer e.Unlock()

	if !e.Listening() {
		return nil, tcpip.ErrInvalidEndpointState
	}

	select {
	case ne := <-e.acceptedChan:
		return ne, nil

	default:
		// Nothing left.
		return nil, tcpip.ErrWouldBlock
	}
}

// Bind binds the connection.
//
// For Unix connectionedEndpoints, this _only sets the address associated with
// the socket_. Work associated with sockets in the filesystem or finding those
// sockets must be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionedEndpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) *tcpip.Error {
	e.Lock()
	defer e.Unlock()
	if e.isBound() || e.Listening() {
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

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *connectionedEndpoint) SendMsg(data [][]byte, c ControlMessages, to BoundEndpoint) (uintptr, *tcpip.Error) {
	// Stream sockets do not support specifying the endpoint. Seqpacket
	// sockets ignore the passed endpoint.
	if e.stype == SockStream && to != nil {
		return 0, tcpip.ErrNotSupported
	}
	return e.baseEndpoint.SendMsg(data, c, to)
}

// Readiness returns the current readiness of the connectionedEndpoint. For
// example, if waiter.EventIn is set, the connectionedEndpoint is immediately
// readable.
func (e *connectionedEndpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	e.Lock()
	defer e.Unlock()

	ready := waiter.EventMask(0)
	switch {
	case e.Connected():
		if mask&waiter.EventIn != 0 && e.receiver.Readable() {
			ready |= waiter.EventIn
		}
		if mask&waiter.EventOut != 0 && e.connected.Writable() {
			ready |= waiter.EventOut
		}
	case e.Listening():
		if mask&waiter.EventIn != 0 && len(e.acceptedChan) > 0 {
			ready |= waiter.EventIn
		}
	}

	return ready
}
