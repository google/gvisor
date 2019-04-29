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

// Package transport contains the implementation of Unix endpoints.
package transport

import (
	"sync"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// initialLimit is the starting limit for the socket buffers.
const initialLimit = 16 * 1024

// A SockType is a type (as opposed to family) of sockets. These are enumerated
// in the syscall package as syscall.SOCK_* constants.
type SockType int

const (
	// SockStream corresponds to syscall.SOCK_STREAM.
	SockStream SockType = 1
	// SockDgram corresponds to syscall.SOCK_DGRAM.
	SockDgram SockType = 2
	// SockRaw corresponds to syscall.SOCK_RAW.
	SockRaw SockType = 3
	// SockSeqpacket corresponds to syscall.SOCK_SEQPACKET.
	SockSeqpacket SockType = 5
)

// A RightsControlMessage is a control message containing FDs.
type RightsControlMessage interface {
	// Clone returns a copy of the RightsControlMessage.
	Clone() RightsControlMessage

	// Release releases any resources owned by the RightsControlMessage.
	Release()
}

// A CredentialsControlMessage is a control message containing Unix credentials.
type CredentialsControlMessage interface {
	// Equals returns true iff the two messages are equal.
	Equals(CredentialsControlMessage) bool
}

// A ControlMessages represents a collection of socket control messages.
//
// +stateify savable
type ControlMessages struct {
	// Rights is a control message containing FDs.
	Rights RightsControlMessage

	// Credentials is a control message containing Unix credentials.
	Credentials CredentialsControlMessage
}

// Empty returns true iff the ControlMessages does not contain either
// credentials or rights.
func (c *ControlMessages) Empty() bool {
	return c.Rights == nil && c.Credentials == nil
}

// Clone clones both the credentials and the rights.
func (c *ControlMessages) Clone() ControlMessages {
	cm := ControlMessages{}
	if c.Rights != nil {
		cm.Rights = c.Rights.Clone()
	}
	cm.Credentials = c.Credentials
	return cm
}

// Release releases both the credentials and the rights.
func (c *ControlMessages) Release() {
	if c.Rights != nil {
		c.Rights.Release()
	}
	*c = ControlMessages{}
}

// Endpoint is the interface implemented by Unix transport protocol
// implementations that expose functionality like sendmsg, recvmsg, connect,
// etc. to Unix socket implementations.
type Endpoint interface {
	Credentialer
	waiter.Waitable

	// Close puts the endpoint in a closed state and frees all resources
	// associated with it.
	Close()

	// RecvMsg reads data and a control message from the endpoint. This method
	// does not block if there is no data pending.
	//
	// creds indicates if credential control messages are requested by the
	// caller. This is useful for determining if control messages can be
	// coalesced. creds is a hint and can be safely ignored by the
	// implementation if no coalescing is possible. It is fine to return
	// credential control messages when none were requested or to not return
	// credential control messages when they were requested.
	//
	// numRights is the number of SCM_RIGHTS FDs requested by the caller. This
	// is useful if one must allocate a buffer to receive a SCM_RIGHTS message
	// or determine if control messages can be coalesced. numRights is a hint
	// and can be safely ignored by the implementation if the number of
	// available SCM_RIGHTS FDs is known and no coalescing is possible. It is
	// fine for the returned number of SCM_RIGHTS FDs to be either higher or
	// lower than the requested number.
	//
	// If peek is true, no data should be consumed from the Endpoint. Any and
	// all data returned from a peek should be available in the next call to
	// RecvMsg.
	//
	// recvLen is the number of bytes copied into data.
	//
	// msgLen is the length of the read message consumed for datagram Endpoints.
	// msgLen is always the same as recvLen for stream Endpoints.
	RecvMsg(data [][]byte, creds bool, numRights uintptr, peek bool, addr *tcpip.FullAddress) (recvLen, msgLen uintptr, cm ControlMessages, err *syserr.Error)

	// SendMsg writes data and a control message to the endpoint's peer.
	// This method does not block if the data cannot be written.
	//
	// SendMsg does not take ownership of any of its arguments on error.
	SendMsg([][]byte, ControlMessages, BoundEndpoint) (uintptr, *syserr.Error)

	// Connect connects this endpoint directly to another.
	//
	// This should be called on the client endpoint, and the (bound)
	// endpoint passed in as a parameter.
	//
	// The error codes are the same as Connect.
	Connect(server BoundEndpoint) *syserr.Error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags tcpip.ShutdownFlags) *syserr.Error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(backlog int) *syserr.Error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	Accept() (Endpoint, *syserr.Error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	//
	// An optional commit function will be executed atomically with respect
	// to binding the endpoint. If this returns an error, the bind will not
	// occur and the error will be propagated back to the caller.
	Bind(address tcpip.FullAddress, commit func() *syserr.Error) *syserr.Error

	// Type return the socket type, typically either SockStream, SockDgram
	// or SockSeqpacket.
	Type() SockType

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error)

	// SetSockOpt sets a socket option. opt should be one of the tcpip.*Option
	// types.
	SetSockOpt(opt interface{}) *tcpip.Error

	// GetSockOpt gets a socket option. opt should be a pointer to one of the
	// tcpip.*Option types.
	GetSockOpt(opt interface{}) *tcpip.Error
}

// A Credentialer is a socket or endpoint that supports the SO_PASSCRED socket
// option.
type Credentialer interface {
	// Passcred returns whether or not the SO_PASSCRED socket option is
	// enabled on this end.
	Passcred() bool

	// ConnectedPasscred returns whether or not the SO_PASSCRED socket option
	// is enabled on the connected end.
	ConnectedPasscred() bool
}

// A BoundEndpoint is a unix endpoint that can be connected to.
type BoundEndpoint interface {
	// BidirectionalConnect establishes a bi-directional connection between two
	// unix endpoints in an all-or-nothing manner. If an error occurs during
	// connecting, the state of neither endpoint should be modified.
	//
	// In order for an endpoint to establish such a bidirectional connection
	// with a BoundEndpoint, the endpoint calls the BidirectionalConnect method
	// on the BoundEndpoint and sends a representation of itself (the
	// ConnectingEndpoint) and a callback (returnConnect) to receive the
	// connection information (Receiver and ConnectedEndpoint) upon a
	// successful connect. The callback should only be called on a successful
	// connect.
	//
	// For a connection attempt to be successful, the ConnectingEndpoint must
	// be unconnected and not listening and the BoundEndpoint whose
	// BidirectionalConnect method is being called must be listening.
	//
	// This method will return syserr.ErrConnectionRefused on endpoints with a
	// type that isn't SockStream or SockSeqpacket.
	BidirectionalConnect(ep ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint)) *syserr.Error

	// UnidirectionalConnect establishes a write-only connection to a unix
	// endpoint.
	//
	// An endpoint which calls UnidirectionalConnect and supports it itself must
	// not hold its own lock when calling UnidirectionalConnect.
	//
	// This method will return syserr.ErrConnectionRefused on a non-SockDgram
	// endpoint.
	UnidirectionalConnect() (ConnectedEndpoint, *syserr.Error)

	// Release releases any resources held by the BoundEndpoint. It must be
	// called before dropping all references to a BoundEndpoint returned by a
	// function.
	Release()
}

// message represents a message passed over a Unix domain socket.
//
// +stateify savable
type message struct {
	messageEntry

	// Data is the Message payload.
	Data buffer.View

	// Control is auxiliary control message data that goes along with the
	// data.
	Control ControlMessages

	// Address is the bound address of the endpoint that sent the message.
	//
	// If the endpoint that sent the message is not bound, the Address is
	// the empty string.
	Address tcpip.FullAddress
}

// Length returns number of bytes stored in the message.
func (m *message) Length() int64 {
	return int64(len(m.Data))
}

// Release releases any resources held by the message.
func (m *message) Release() {
	m.Control.Release()
}

// Peek returns a copy of the message.
func (m *message) Peek() *message {
	return &message{Data: m.Data, Control: m.Control.Clone(), Address: m.Address}
}

// Truncate reduces the length of the message payload to n bytes.
//
// Preconditions: n <= m.Length().
func (m *message) Truncate(n int64) {
	m.Data.CapLength(int(n))
}

// A Receiver can be used to receive Messages.
type Receiver interface {
	// Recv receives a single message. This method does not block.
	//
	// See Endpoint.RecvMsg for documentation on shared arguments.
	//
	// notify indicates if RecvNotify should be called.
	Recv(data [][]byte, creds bool, numRights uintptr, peek bool) (recvLen, msgLen uintptr, cm ControlMessages, source tcpip.FullAddress, notify bool, err *syserr.Error)

	// RecvNotify notifies the Receiver of a successful Recv. This must not be
	// called while holding any endpoint locks.
	RecvNotify()

	// CloseRecv prevents the receiving of additional Messages.
	//
	// After CloseRecv is called, CloseNotify must also be called.
	CloseRecv()

	// CloseNotify notifies the Receiver of recv being closed. This must not be
	// called while holding any endpoint locks.
	CloseNotify()

	// Readable returns if messages should be attempted to be received. This
	// includes when read has been shutdown.
	Readable() bool

	// RecvQueuedSize returns the total amount of data currently receivable.
	// RecvQueuedSize should return -1 if the operation isn't supported.
	RecvQueuedSize() int64

	// RecvMaxQueueSize returns maximum value for RecvQueuedSize.
	// RecvMaxQueueSize should return -1 if the operation isn't supported.
	RecvMaxQueueSize() int64

	// Release releases any resources owned by the Receiver. It should be
	// called before droping all references to a Receiver.
	Release()
}

// queueReceiver implements Receiver for datagram sockets.
//
// +stateify savable
type queueReceiver struct {
	readQueue *queue
}

// Recv implements Receiver.Recv.
func (q *queueReceiver) Recv(data [][]byte, creds bool, numRights uintptr, peek bool) (uintptr, uintptr, ControlMessages, tcpip.FullAddress, bool, *syserr.Error) {
	var m *message
	var notify bool
	var err *syserr.Error
	if peek {
		m, err = q.readQueue.Peek()
	} else {
		m, notify, err = q.readQueue.Dequeue()
	}
	if err != nil {
		return 0, 0, ControlMessages{}, tcpip.FullAddress{}, false, err
	}
	src := []byte(m.Data)
	var copied uintptr
	for i := 0; i < len(data) && len(src) > 0; i++ {
		n := copy(data[i], src)
		copied += uintptr(n)
		src = src[n:]
	}
	return copied, uintptr(len(m.Data)), m.Control, m.Address, notify, nil
}

// RecvNotify implements Receiver.RecvNotify.
func (q *queueReceiver) RecvNotify() {
	q.readQueue.WriterQueue.Notify(waiter.EventOut)
}

// CloseNotify implements Receiver.CloseNotify.
func (q *queueReceiver) CloseNotify() {
	q.readQueue.ReaderQueue.Notify(waiter.EventIn)
	q.readQueue.WriterQueue.Notify(waiter.EventOut)
}

// CloseRecv implements Receiver.CloseRecv.
func (q *queueReceiver) CloseRecv() {
	q.readQueue.Close()
}

// Readable implements Receiver.Readable.
func (q *queueReceiver) Readable() bool {
	return q.readQueue.IsReadable()
}

// RecvQueuedSize implements Receiver.RecvQueuedSize.
func (q *queueReceiver) RecvQueuedSize() int64 {
	return q.readQueue.QueuedSize()
}

// RecvMaxQueueSize implements Receiver.RecvMaxQueueSize.
func (q *queueReceiver) RecvMaxQueueSize() int64 {
	return q.readQueue.MaxQueueSize()
}

// Release implements Receiver.Release.
func (q *queueReceiver) Release() {
	q.readQueue.DecRef()
}

// streamQueueReceiver implements Receiver for stream sockets.
//
// +stateify savable
type streamQueueReceiver struct {
	queueReceiver

	mu      sync.Mutex `state:"nosave"`
	buffer  []byte
	control ControlMessages
	addr    tcpip.FullAddress
}

func vecCopy(data [][]byte, buf []byte) (uintptr, [][]byte, []byte) {
	var copied uintptr
	for len(data) > 0 && len(buf) > 0 {
		n := copy(data[0], buf)
		copied += uintptr(n)
		buf = buf[n:]
		data[0] = data[0][n:]
		if len(data[0]) == 0 {
			data = data[1:]
		}
	}
	return copied, data, buf
}

// Readable implements Receiver.Readable.
func (q *streamQueueReceiver) Readable() bool {
	q.mu.Lock()
	bl := len(q.buffer)
	r := q.readQueue.IsReadable()
	q.mu.Unlock()
	// We're readable if we have data in our buffer or if the queue receiver is
	// readable.
	return bl > 0 || r
}

// RecvQueuedSize implements Receiver.RecvQueuedSize.
func (q *streamQueueReceiver) RecvQueuedSize() int64 {
	q.mu.Lock()
	bl := len(q.buffer)
	qs := q.readQueue.QueuedSize()
	q.mu.Unlock()
	return int64(bl) + qs
}

// RecvMaxQueueSize implements Receiver.RecvMaxQueueSize.
func (q *streamQueueReceiver) RecvMaxQueueSize() int64 {
	// The RecvMaxQueueSize() is the readQueue's MaxQueueSize() plus the largest
	// message we can buffer which is also the largest message we can receive.
	return 2 * q.readQueue.MaxQueueSize()
}

// Recv implements Receiver.Recv.
func (q *streamQueueReceiver) Recv(data [][]byte, wantCreds bool, numRights uintptr, peek bool) (uintptr, uintptr, ControlMessages, tcpip.FullAddress, bool, *syserr.Error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	var notify bool

	// If we have no data in the endpoint, we need to get some.
	if len(q.buffer) == 0 {
		// Load the next message into a buffer, even if we are peeking. Peeking
		// won't consume the message, so it will be still available to be read
		// the next time Recv() is called.
		m, n, err := q.readQueue.Dequeue()
		if err != nil {
			return 0, 0, ControlMessages{}, tcpip.FullAddress{}, false, err
		}
		notify = n
		q.buffer = []byte(m.Data)
		q.control = m.Control
		q.addr = m.Address
	}

	var copied uintptr
	if peek {
		// Don't consume control message if we are peeking.
		c := q.control.Clone()

		// Don't consume data since we are peeking.
		copied, data, _ = vecCopy(data, q.buffer)

		return copied, copied, c, q.addr, notify, nil
	}

	// Consume data and control message since we are not peeking.
	copied, data, q.buffer = vecCopy(data, q.buffer)

	// Save the original state of q.control.
	c := q.control

	// Remove rights from q.control and leave behind just the creds.
	q.control.Rights = nil
	if !wantCreds {
		c.Credentials = nil
	}

	if c.Rights != nil && numRights == 0 {
		c.Rights.Release()
		c.Rights = nil
	}

	haveRights := c.Rights != nil

	// If we have more capacity for data and haven't received any usable
	// rights.
	//
	// Linux never coalesces rights control messages.
	for !haveRights && len(data) > 0 {
		// Get a message from the readQueue.
		m, n, err := q.readQueue.Dequeue()
		if err != nil {
			// We already got some data, so ignore this error. This will
			// manifest as a short read to the user, which is what Linux
			// does.
			break
		}
		notify = notify || n
		q.buffer = []byte(m.Data)
		q.control = m.Control
		q.addr = m.Address

		if wantCreds {
			if (q.control.Credentials == nil) != (c.Credentials == nil) {
				// One message has credentials, the other does not.
				break
			}

			if q.control.Credentials != nil && c.Credentials != nil && !q.control.Credentials.Equals(c.Credentials) {
				// Both messages have credentials, but they don't match.
				break
			}
		}

		if numRights != 0 && c.Rights != nil && q.control.Rights != nil {
			// Both messages have rights.
			break
		}

		var cpd uintptr
		cpd, data, q.buffer = vecCopy(data, q.buffer)
		copied += cpd

		if cpd == 0 {
			// data was actually full.
			break
		}

		if q.control.Rights != nil {
			// Consume rights.
			if numRights == 0 {
				q.control.Rights.Release()
			} else {
				c.Rights = q.control.Rights
				haveRights = true
			}
			q.control.Rights = nil
		}
	}
	return copied, copied, c, q.addr, notify, nil
}

// A ConnectedEndpoint is an Endpoint that can be used to send Messages.
type ConnectedEndpoint interface {
	// Passcred implements Endpoint.Passcred.
	Passcred() bool

	// GetLocalAddress implements Endpoint.GetLocalAddress.
	GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

	// Send sends a single message. This method does not block.
	//
	// notify indicates if SendNotify should be called.
	//
	// syserr.ErrWouldBlock can be returned along with a partial write if
	// the caller should block to send the rest of the data.
	Send(data [][]byte, controlMessages ControlMessages, from tcpip.FullAddress) (n uintptr, notify bool, err *syserr.Error)

	// SendNotify notifies the ConnectedEndpoint of a successful Send. This
	// must not be called while holding any endpoint locks.
	SendNotify()

	// CloseSend prevents the sending of additional Messages.
	//
	// After CloseSend is call, CloseNotify must also be called.
	CloseSend()

	// CloseNotify notifies the ConnectedEndpoint of send being closed. This
	// must not be called while holding any endpoint locks.
	CloseNotify()

	// Writable returns if messages should be attempted to be sent. This
	// includes when write has been shutdown.
	Writable() bool

	// EventUpdate lets the ConnectedEndpoint know that event registrations
	// have changed.
	EventUpdate()

	// SendQueuedSize returns the total amount of data currently queued for
	// sending. SendQueuedSize should return -1 if the operation isn't
	// supported.
	SendQueuedSize() int64

	// SendMaxQueueSize returns maximum value for SendQueuedSize.
	// SendMaxQueueSize should return -1 if the operation isn't supported.
	SendMaxQueueSize() int64

	// Release releases any resources owned by the ConnectedEndpoint. It should
	// be called before droping all references to a ConnectedEndpoint.
	Release()
}

// +stateify savable
type connectedEndpoint struct {
	// endpoint represents the subset of the Endpoint functionality needed by
	// the connectedEndpoint. It is implemented by both connectionedEndpoint
	// and connectionlessEndpoint and allows the use of types which don't
	// fully implement Endpoint.
	endpoint interface {
		// Passcred implements Endpoint.Passcred.
		Passcred() bool

		// GetLocalAddress implements Endpoint.GetLocalAddress.
		GetLocalAddress() (tcpip.FullAddress, *tcpip.Error)

		// Type implements Endpoint.Type.
		Type() SockType
	}

	writeQueue *queue
}

// Passcred implements ConnectedEndpoint.Passcred.
func (e *connectedEndpoint) Passcred() bool {
	return e.endpoint.Passcred()
}

// GetLocalAddress implements ConnectedEndpoint.GetLocalAddress.
func (e *connectedEndpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	return e.endpoint.GetLocalAddress()
}

// Send implements ConnectedEndpoint.Send.
func (e *connectedEndpoint) Send(data [][]byte, controlMessages ControlMessages, from tcpip.FullAddress) (uintptr, bool, *syserr.Error) {
	var l int64
	for _, d := range data {
		l += int64(len(d))
	}

	truncate := false
	if e.endpoint.Type() == SockStream {
		// Since stream sockets don't preserve message boundaries, we
		// can write only as much of the message as fits in the queue.
		truncate = true

		// Discard empty stream packets. Since stream sockets don't
		// preserve message boundaries, sending zero bytes is a no-op.
		// In Linux, the receiver actually uses a zero-length receive
		// as an indication that the stream was closed.
		if l == 0 {
			controlMessages.Release()
			return 0, false, nil
		}
	}

	v := make([]byte, 0, l)
	for _, d := range data {
		v = append(v, d...)
	}

	l, notify, err := e.writeQueue.Enqueue(&message{Data: buffer.View(v), Control: controlMessages, Address: from}, truncate)
	return uintptr(l), notify, err
}

// SendNotify implements ConnectedEndpoint.SendNotify.
func (e *connectedEndpoint) SendNotify() {
	e.writeQueue.ReaderQueue.Notify(waiter.EventIn)
}

// CloseNotify implements ConnectedEndpoint.CloseNotify.
func (e *connectedEndpoint) CloseNotify() {
	e.writeQueue.ReaderQueue.Notify(waiter.EventIn)
	e.writeQueue.WriterQueue.Notify(waiter.EventOut)
}

// CloseSend implements ConnectedEndpoint.CloseSend.
func (e *connectedEndpoint) CloseSend() {
	e.writeQueue.Close()
}

// Writable implements ConnectedEndpoint.Writable.
func (e *connectedEndpoint) Writable() bool {
	return e.writeQueue.IsWritable()
}

// EventUpdate implements ConnectedEndpoint.EventUpdate.
func (*connectedEndpoint) EventUpdate() {}

// SendQueuedSize implements ConnectedEndpoint.SendQueuedSize.
func (e *connectedEndpoint) SendQueuedSize() int64 {
	return e.writeQueue.QueuedSize()
}

// SendMaxQueueSize implements ConnectedEndpoint.SendMaxQueueSize.
func (e *connectedEndpoint) SendMaxQueueSize() int64 {
	return e.writeQueue.MaxQueueSize()
}

// Release implements ConnectedEndpoint.Release.
func (e *connectedEndpoint) Release() {
	e.writeQueue.DecRef()
}

// baseEndpoint is an embeddable unix endpoint base used in both the connected and connectionless
// unix domain socket Endpoint implementations.
//
// Not to be used on its own.
//
// +stateify savable
type baseEndpoint struct {
	*waiter.Queue

	// passcred specifies whether SCM_CREDENTIALS socket control messages are
	// enabled on this endpoint. Must be accessed atomically.
	passcred int32

	// Mutex protects the below fields.
	sync.Mutex `state:"nosave"`

	// receiver allows Messages to be received.
	receiver Receiver

	// connected allows messages to be sent and state information about the
	// connected endpoint to be read.
	connected ConnectedEndpoint

	// path is not empty if the endpoint has been bound,
	// or may be used if the endpoint is connected.
	path string
}

// EventRegister implements waiter.Waitable.EventRegister.
func (e *baseEndpoint) EventRegister(we *waiter.Entry, mask waiter.EventMask) {
	e.Queue.EventRegister(we, mask)
	e.Lock()
	if e.connected != nil {
		e.connected.EventUpdate()
	}
	e.Unlock()
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (e *baseEndpoint) EventUnregister(we *waiter.Entry) {
	e.Queue.EventUnregister(we)
	e.Lock()
	if e.connected != nil {
		e.connected.EventUpdate()
	}
	e.Unlock()
}

// Passcred implements Credentialer.Passcred.
func (e *baseEndpoint) Passcred() bool {
	return atomic.LoadInt32(&e.passcred) != 0
}

// ConnectedPasscred implements Credentialer.ConnectedPasscred.
func (e *baseEndpoint) ConnectedPasscred() bool {
	e.Lock()
	defer e.Unlock()
	return e.connected != nil && e.connected.Passcred()
}

func (e *baseEndpoint) setPasscred(pc bool) {
	if pc {
		atomic.StoreInt32(&e.passcred, 1)
	} else {
		atomic.StoreInt32(&e.passcred, 0)
	}
}

// Connected implements ConnectingEndpoint.Connected.
func (e *baseEndpoint) Connected() bool {
	return e.receiver != nil && e.connected != nil
}

// RecvMsg reads data and a control message from the endpoint.
func (e *baseEndpoint) RecvMsg(data [][]byte, creds bool, numRights uintptr, peek bool, addr *tcpip.FullAddress) (uintptr, uintptr, ControlMessages, *syserr.Error) {
	e.Lock()

	if e.receiver == nil {
		e.Unlock()
		return 0, 0, ControlMessages{}, syserr.ErrNotConnected
	}

	recvLen, msgLen, cms, a, notify, err := e.receiver.Recv(data, creds, numRights, peek)
	e.Unlock()
	if err != nil {
		return 0, 0, ControlMessages{}, err
	}

	if notify {
		e.receiver.RecvNotify()
	}

	if addr != nil {
		*addr = a
	}
	return recvLen, msgLen, cms, nil
}

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *baseEndpoint) SendMsg(data [][]byte, c ControlMessages, to BoundEndpoint) (uintptr, *syserr.Error) {
	e.Lock()
	if !e.Connected() {
		e.Unlock()
		return 0, syserr.ErrNotConnected
	}
	if to != nil {
		e.Unlock()
		return 0, syserr.ErrAlreadyConnected
	}

	n, notify, err := e.connected.Send(data, c, tcpip.FullAddress{Addr: tcpip.Address(e.path)})
	e.Unlock()

	if notify {
		e.connected.SendNotify()
	}

	return n, err
}

// SetSockOpt sets a socket option. Currently not supported.
func (e *baseEndpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.PasscredOption:
		e.setPasscred(v != 0)
		return nil
	}
	return nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *baseEndpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		return nil

	case *tcpip.SendQueueSizeOption:
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return tcpip.ErrNotConnected
		}
		qs := tcpip.SendQueueSizeOption(e.connected.SendQueuedSize())
		e.Unlock()
		if qs < 0 {
			return tcpip.ErrQueueSizeNotSupported
		}
		*o = qs
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return tcpip.ErrNotConnected
		}
		qs := tcpip.ReceiveQueueSizeOption(e.receiver.RecvQueuedSize())
		e.Unlock()
		if qs < 0 {
			return tcpip.ErrQueueSizeNotSupported
		}
		*o = qs
		return nil

	case *tcpip.PasscredOption:
		if e.Passcred() {
			*o = tcpip.PasscredOption(1)
		} else {
			*o = tcpip.PasscredOption(0)
		}
		return nil

	case *tcpip.SendBufferSizeOption:
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return tcpip.ErrNotConnected
		}
		qs := tcpip.SendBufferSizeOption(e.connected.SendMaxQueueSize())
		e.Unlock()
		if qs < 0 {
			return tcpip.ErrQueueSizeNotSupported
		}
		*o = qs
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.Lock()
		if e.receiver == nil {
			e.Unlock()
			return tcpip.ErrNotConnected
		}
		qs := tcpip.ReceiveBufferSizeOption(e.receiver.RecvMaxQueueSize())
		e.Unlock()
		if qs < 0 {
			return tcpip.ErrQueueSizeNotSupported
		}
		*o = qs
		return nil

	case *tcpip.KeepaliveEnabledOption:
		*o = 0
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *baseEndpoint) Shutdown(flags tcpip.ShutdownFlags) *syserr.Error {
	e.Lock()
	if !e.Connected() {
		e.Unlock()
		return syserr.ErrNotConnected
	}

	if flags&tcpip.ShutdownRead != 0 {
		e.receiver.CloseRecv()
	}

	if flags&tcpip.ShutdownWrite != 0 {
		e.connected.CloseSend()
	}

	e.Unlock()

	if flags&tcpip.ShutdownRead != 0 {
		e.receiver.CloseNotify()
	}

	if flags&tcpip.ShutdownWrite != 0 {
		e.connected.CloseNotify()
	}

	return nil
}

// GetLocalAddress returns the bound path.
func (e *baseEndpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.Lock()
	defer e.Unlock()
	return tcpip.FullAddress{Addr: tcpip.Address(e.path)}, nil
}

// GetRemoteAddress returns the local address of the connected endpoint (if
// available).
func (e *baseEndpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.Lock()
	c := e.connected
	e.Unlock()
	if c != nil {
		return c.GetLocalAddress()
	}
	return tcpip.FullAddress{}, tcpip.ErrNotConnected
}

// Release implements BoundEndpoint.Release.
func (*baseEndpoint) Release() {
	// Binding a baseEndpoint doesn't take a reference.
}
