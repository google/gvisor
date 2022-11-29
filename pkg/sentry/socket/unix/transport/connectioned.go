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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

type locker interface {
	Lock()
	Unlock()
	NestedLock(endpointlockNameIndex)
	NestedUnlock(endpointlockNameIndex)
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
	// value doesn't match the BoundEndpoint's type.
	Type() linux.SockType

	// GetLocalAddress returns the bound path.
	GetLocalAddress() (tcpip.FullAddress, tcpip.Error)

	// Locker protects the following methods. While locked, only the holder of
	// the lock can change the return value of the protected methods.
	locker

	// Connected returns true iff the ConnectingEndpoint is in the connected
	// state. ConnectingEndpoints can only be connected to a single endpoint,
	// so the connection attempt must be aborted if this returns true.
	Connected() bool

	// ListeningLocked returns true iff the ConnectingEndpoint is in the
	// listening state. ConnectingEndpoints cannot make connections while
	// listening, so the connection attempt must be aborted if this returns
	// true.
	ListeningLocked() bool

	// WaiterQueue returns a pointer to the endpoint's waiter queue.
	WaiterQueue() *waiter.Queue
}

// connectionedEndpoint is a Unix-domain connected or connectable endpoint and implements
// ConnectingEndpoint, BoundEndpoint and tcpip.Endpoint.
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
//
// +stateify savable
type connectionedEndpoint struct {
	baseEndpoint

	// id is the unique endpoint identifier. This is used exclusively for
	// lock ordering within connect.
	id uint64

	// idGenerator is used to generate new unique endpoint identifiers.
	idGenerator uniqueid.Provider

	// stype is used by connecting sockets to ensure that they are the
	// same type. The value is typically either tcpip.SockSeqpacket or
	// tcpip.SockStream.
	stype linux.SockType

	// acceptedChan is per the TCP endpoint implementation. Note that the
	// sockets in this channel are _already in the connected state_, and
	// have another associated connectionedEndpoint.
	//
	// If nil, then no listen call has been made.
	acceptedChan chan *connectionedEndpoint `state:".([]*connectionedEndpoint)"`

	// boundSocketFD corresponds to a bound socket on the host filesystem
	// that may listen and accept incoming connections.
	//
	// boundSocketFD is protected by baseEndpoint.mu.
	boundSocketFD BoundSocketFD
}

var (
	_ = BoundEndpoint((*connectionedEndpoint)(nil))
	_ = Endpoint((*connectionedEndpoint)(nil))
)

// NewConnectioned creates a new unbound connectionedEndpoint.
func NewConnectioned(ctx context.Context, stype linux.SockType, uid uniqueid.Provider) Endpoint {
	return newConnectioned(ctx, stype, uid)
}

func newConnectioned(ctx context.Context, stype linux.SockType, uid uniqueid.Provider) *connectionedEndpoint {
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: &waiter.Queue{}},
		id:           uid.UniqueID(),
		idGenerator:  uid,
		stype:        stype,
	}

	ep.ops.InitHandler(ep, &stackHandler{}, getSendBufferLimits, getReceiveBufferLimits)
	ep.ops.SetSendBufferSize(defaultBufferSize, false /* notify */)
	ep.ops.SetReceiveBufferSize(defaultBufferSize, false /* notify */)
	return ep
}

// NewPair allocates a new pair of connected unix-domain connectionedEndpoints.
func NewPair(ctx context.Context, stype linux.SockType, uid uniqueid.Provider) (Endpoint, Endpoint) {
	a := newConnectioned(ctx, stype, uid)
	b := newConnectioned(ctx, stype, uid)

	q1 := &queue{ReaderQueue: a.Queue, WriterQueue: b.Queue, limit: defaultBufferSize}
	q1.InitRefs()
	q2 := &queue{ReaderQueue: b.Queue, WriterQueue: a.Queue, limit: defaultBufferSize}
	q2.InitRefs()

	if stype == linux.SOCK_STREAM {
		a.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q1}}
		b.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{q2}}
	} else {
		a.receiver = &queueReceiver{q1}
		b.receiver = &queueReceiver{q2}
	}

	q2.IncRef()
	a.connected = &connectedEndpoint{
		endpoint:   b,
		writeQueue: q2,
	}
	q1.IncRef()
	b.connected = &connectedEndpoint{
		endpoint:   a,
		writeQueue: q1,
	}

	return a, b
}

// NewExternal creates a new externally backed Endpoint. It behaves like a
// socketpair.
func NewExternal(stype linux.SockType, uid uniqueid.Provider, queue *waiter.Queue, receiver Receiver, connected ConnectedEndpoint) Endpoint {
	ep := &connectionedEndpoint{
		baseEndpoint: baseEndpoint{Queue: queue, receiver: receiver, connected: connected},
		id:           uid.UniqueID(),
		idGenerator:  uid,
		stype:        stype,
	}
	ep.ops.InitHandler(ep, &stackHandler{}, getSendBufferLimits, getReceiveBufferLimits)
	ep.ops.SetSendBufferSize(connected.SendMaxQueueSize(), false /* notify */)
	ep.ops.SetReceiveBufferSize(defaultBufferSize, false /* notify */)
	return ep
}

// ID implements ConnectingEndpoint.ID.
func (e *connectionedEndpoint) ID() uint64 {
	return e.id
}

// Type implements ConnectingEndpoint.Type and Endpoint.Type.
func (e *connectionedEndpoint) Type() linux.SockType {
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
	e.Lock()
	defer e.Unlock()
	return e.ListeningLocked()
}

func (e *connectionedEndpoint) ListeningLocked() bool {
	return e.acceptedChan != nil
}

// Close puts the connectionedEndpoint in a closed state and frees all
// resources associated with it.
//
// The socket will be a fresh state after a call to close and may be reused.
// That is, close may be used to "unbind" or "disconnect" the socket in error
// paths.
func (e *connectionedEndpoint) Close(ctx context.Context) {
	var acceptedChan chan *connectionedEndpoint
	e.Lock()
	var (
		c ConnectedEndpoint
		r Receiver
	)
	switch {
	case e.Connected():
		e.connected.CloseSend()
		e.receiver.CloseRecv()
		// Still have unread data? If yes, we set this into the write
		// end so that the peer can get ECONNRESET) when it does read.
		if e.receiver.RecvQueuedSize() > 0 {
			e.connected.CloseUnread()
		}
		c = e.connected
		r = e.receiver
		e.connected = nil
		e.receiver = nil
	case e.isBound():
		e.path = ""
	case e.ListeningLocked():
		close(e.acceptedChan)
		acceptedChan = e.acceptedChan
		e.acceptedChan = nil
		e.path = ""
	}
	e.Unlock()
	if acceptedChan != nil {
		for n := range acceptedChan {
			n.Close(ctx)
		}
	}
	if c != nil {
		c.CloseNotify()
		c.Release(ctx)
	}
	e.ResetBoundSocketFD(ctx)
	if r != nil {
		r.CloseNotify()
		r.Release(ctx)
	}
}

// BidirectionalConnect implements BoundEndpoint.BidirectionalConnect.
func (e *connectionedEndpoint) BidirectionalConnect(ctx context.Context, ce ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) *syserr.Error {
	if ce.Type() != e.stype {
		return syserr.ErrWrongProtocolForSocket
	}

	// Check if ce is e to avoid a deadlock.
	if ce, ok := ce.(*connectionedEndpoint); ok && ce == e {
		return syserr.ErrInvalidEndpointState
	}

	// Do a dance to safely acquire locks on both endpoints.
	if e.id < ce.ID() {
		e.Lock()
		ce.NestedLock(endpointLockHigherid)
	} else {
		ce.Lock()
		e.NestedLock(endpointLockHigherid)
	}

	// Check connecting state.
	if ce.Connected() {
		e.NestedUnlock(endpointLockHigherid)
		ce.Unlock()
		return syserr.ErrAlreadyConnected
	}
	if ce.ListeningLocked() {
		e.NestedUnlock(endpointLockHigherid)
		ce.Unlock()
		return syserr.ErrInvalidEndpointState
	}

	// Check bound state.
	if !e.ListeningLocked() {
		e.NestedUnlock(endpointLockHigherid)
		ce.Unlock()
		return syserr.ErrConnectionRefused
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
	ne.ops.InitHandler(ne, &stackHandler{}, getSendBufferLimits, getReceiveBufferLimits)
	ne.ops.SetSendBufferSize(defaultBufferSize, false /* notify */)
	ne.ops.SetReceiveBufferSize(defaultBufferSize, false /* notify */)

	readQueue := &queue{ReaderQueue: ce.WaiterQueue(), WriterQueue: ne.Queue, limit: defaultBufferSize}
	readQueue.InitRefs()
	ne.connected = &connectedEndpoint{
		endpoint:   ce,
		writeQueue: readQueue,
	}

	// Make sure the accepted endpoint inherits this listening socket's SO_SNDBUF.
	writeQueue := &queue{ReaderQueue: ne.Queue, WriterQueue: ce.WaiterQueue(), limit: e.ops.GetSendBufferSize()}
	writeQueue.InitRefs()
	if e.stype == linux.SOCK_STREAM {
		ne.receiver = &streamQueueReceiver{queueReceiver: queueReceiver{readQueue: writeQueue}}
	} else {
		ne.receiver = &queueReceiver{readQueue: writeQueue}
	}

	select {
	case e.acceptedChan <- ne:
		// Commit state.
		writeQueue.IncRef()
		connected := &connectedEndpoint{
			endpoint:   ne,
			writeQueue: writeQueue,
		}
		readQueue.IncRef()
		if e.stype == linux.SOCK_STREAM {
			returnConnect(&streamQueueReceiver{queueReceiver: queueReceiver{readQueue: readQueue}}, connected)
		} else {
			returnConnect(&queueReceiver{readQueue: readQueue}, connected)
		}

		// Notify can deadlock if we are holding these locks.
		e.NestedUnlock(endpointLockHigherid)
		ce.Unlock()

		// Notify on both ends.
		e.Notify(waiter.ReadableEvents)
		ce.WaiterQueue().Notify(waiter.WritableEvents)

		return nil
	default:
		// Busy; return EAGAIN per spec.
		e.NestedUnlock(endpointLockHigherid)
		ce.Unlock()
		ne.Close(ctx)
		return syserr.ErrTryAgain
	}
}

// UnidirectionalConnect implements BoundEndpoint.UnidirectionalConnect.
func (e *connectionedEndpoint) UnidirectionalConnect(ctx context.Context) (ConnectedEndpoint, *syserr.Error) {
	return nil, syserr.ErrConnectionRefused
}

// Connect attempts to directly connect to another Endpoint.
// Implements Endpoint.Connect.
func (e *connectionedEndpoint) Connect(ctx context.Context, server BoundEndpoint) *syserr.Error {
	returnConnect := func(r Receiver, ce ConnectedEndpoint) {
		e.receiver = r
		e.connected = ce
		// Make sure the newly created connected endpoint's write queue is updated
		// to reflect this endpoint's send buffer size.
		if bufSz := e.connected.SetSendBufferSize(e.ops.GetSendBufferSize()); bufSz != e.ops.GetSendBufferSize() {
			e.ops.SetSendBufferSize(bufSz, false /* notify */)
			e.ops.SetReceiveBufferSize(bufSz, false /* notify */)
		}
	}

	return server.BidirectionalConnect(ctx, e, returnConnect)
}

// Listen starts listening on the connection.
func (e *connectionedEndpoint) Listen(ctx context.Context, backlog int) *syserr.Error {
	e.Lock()
	defer e.Unlock()
	if e.ListeningLocked() {
		// Adjust the size of the channel iff we can fix existing
		// pending connections into the new one.
		if len(e.acceptedChan) > backlog {
			return syserr.ErrInvalidEndpointState
		}
		origChan := e.acceptedChan
		e.acceptedChan = make(chan *connectionedEndpoint, backlog)
		close(origChan)
		for ep := range origChan {
			e.acceptedChan <- ep
		}
		if e.boundSocketFD != nil {
			if err := e.boundSocketFD.Listen(ctx, int32(backlog)); err != nil {
				return syserr.FromError(err)
			}
		}
		return nil
	}
	if !e.isBound() {
		return syserr.ErrInvalidEndpointState
	}

	// Normal case.
	e.acceptedChan = make(chan *connectionedEndpoint, backlog)
	if e.boundSocketFD != nil {
		if err := e.boundSocketFD.Listen(ctx, int32(backlog)); err != nil {
			return syserr.FromError(err)
		}
	}

	return nil
}

// Accept accepts a new connection.
func (e *connectionedEndpoint) Accept(ctx context.Context, peerAddr *tcpip.FullAddress) (Endpoint, *syserr.Error) {
	e.Lock()

	if !e.ListeningLocked() {
		e.Unlock()
		return nil, syserr.ErrInvalidEndpointState
	}

	ne, err := e.getAcceptedEndpointLocked(ctx)
	e.Unlock()
	if err != nil {
		return nil, err
	}

	if peerAddr != nil {
		ne.Lock()
		c := ne.connected
		ne.Unlock()
		if c != nil {
			addr, err := c.GetLocalAddress()
			if err != nil {
				return nil, syserr.TranslateNetstackError(err)
			}
			*peerAddr = addr
		}
	}
	return ne, nil
}

// Preconditions:
//   - e.Listening()
//   - e is locked.
func (e *connectionedEndpoint) getAcceptedEndpointLocked(ctx context.Context) (*connectionedEndpoint, *syserr.Error) {
	// Accept connections from within the sentry first, since this avoids
	// an RPC to the gofer on the common path.
	select {
	case ne := <-e.acceptedChan:
		return ne, nil
	default:
		// No internal connections.
	}

	if e.boundSocketFD == nil {
		return nil, syserr.ErrWouldBlock
	}

	// Check for external connections.
	nfd, err := e.boundSocketFD.Accept(ctx)
	if err == unix.EWOULDBLOCK {
		return nil, syserr.ErrWouldBlock
	}
	if err != nil {
		return nil, syserr.FromError(err)
	}
	q := &waiter.Queue{}
	scme, serr := NewSCMEndpoint(nfd, q, e.path)
	if serr != nil {
		unix.Close(nfd)
		return nil, serr
	}
	scme.Init()
	return NewExternal(e.stype, e.idGenerator, q, scme, scme).(*connectionedEndpoint), nil

}

// Bind binds the connection.
//
// For Unix connectionedEndpoints, this _only sets the address associated with
// the socket_. Work associated with sockets in the filesystem or finding those
// sockets must be done by a higher level.
//
// Bind will fail only if the socket is connected, bound or the passed address
// is invalid (the empty string).
func (e *connectionedEndpoint) Bind(addr tcpip.FullAddress) *syserr.Error {
	e.Lock()
	defer e.Unlock()
	if e.isBound() || e.ListeningLocked() {
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

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *connectionedEndpoint) SendMsg(ctx context.Context, data [][]byte, c ControlMessages, to BoundEndpoint) (int64, func(), *syserr.Error) {
	// Stream sockets do not support specifying the endpoint. Seqpacket
	// sockets ignore the passed endpoint.
	if e.stype == linux.SOCK_STREAM && to != nil {
		return 0, nil, syserr.ErrNotSupported
	}
	return e.baseEndpoint.SendMsg(ctx, data, c, to)
}

func (e *connectionedEndpoint) isBoundSocketReadable() bool {
	if e.boundSocketFD == nil {
		return false
	}
	return fdnotifier.NonBlockingPoll(e.boundSocketFD.NotificationFD(), waiter.ReadableEvents)&waiter.ReadableEvents != 0
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
		if mask&waiter.ReadableEvents != 0 && e.receiver.Readable() {
			ready |= waiter.ReadableEvents
		}
		if mask&waiter.WritableEvents != 0 && e.connected.Writable() {
			ready |= waiter.WritableEvents
		}
	case e.ListeningLocked():
		if mask&waiter.ReadableEvents != 0 && (len(e.acceptedChan) > 0 || e.isBoundSocketReadable()) {
			ready |= waiter.ReadableEvents
		}
	}

	return ready
}

// State implements socket.Socket.State.
func (e *connectionedEndpoint) State() uint32 {
	e.Lock()
	defer e.Unlock()

	if e.Connected() {
		return linux.SS_CONNECTED
	}
	return linux.SS_UNCONNECTED
}

// OnSetSendBufferSize implements tcpip.SocketOptionsHandler.OnSetSendBufferSize.
func (e *connectionedEndpoint) OnSetSendBufferSize(v int64) (newSz int64) {
	e.Lock()
	defer e.Unlock()
	if e.Connected() {
		return e.baseEndpoint.connected.SetSendBufferSize(v)
	}
	return v
}

// WakeupWriters implements tcpip.SocketOptionsHandler.WakeupWriters.
func (e *connectionedEndpoint) WakeupWriters() {}

// SetBoundSocketFD implement HostBountEndpoint.SetBoundSocketFD.
func (e *connectionedEndpoint) SetBoundSocketFD(bsFD BoundSocketFD) error {
	e.Lock()
	defer e.Unlock()
	if e.path != "" || e.boundSocketFD != nil {
		return syserr.ErrAlreadyBound.ToError()
	}
	e.boundSocketFD = bsFD
	fdnotifier.AddFD(bsFD.NotificationFD(), e.Queue)
	return nil
}

// SetBoundSocketFD implement HostBountEndpoint.ResetBoundSocketFD.
func (e *connectionedEndpoint) ResetBoundSocketFD(ctx context.Context) {
	e.Lock()
	defer e.Unlock()
	if e.boundSocketFD == nil {
		return
	}
	fdnotifier.RemoveFD(e.boundSocketFD.NotificationFD())
	e.boundSocketFD.Close(ctx)
	e.boundSocketFD = nil
}

// EventRegister implements waiter.Waitable.EventRegister.
func (e *connectionedEndpoint) EventRegister(we *waiter.Entry) error {
	if err := e.baseEndpoint.EventRegister(we); err != nil {
		return err
	}

	e.Lock()
	bsFD := e.boundSocketFD
	e.Unlock()
	if bsFD != nil {
		fdnotifier.UpdateFD(bsFD.NotificationFD())
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (e *connectionedEndpoint) EventUnregister(we *waiter.Entry) {
	e.baseEndpoint.EventUnregister(we)

	e.Lock()
	bsFD := e.boundSocketFD
	e.Unlock()
	if bsFD != nil {
		fdnotifier.UpdateFD(bsFD.NotificationFD())
	}
}
