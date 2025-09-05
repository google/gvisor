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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// The minimum size of the send/receive buffers.
	minimumBufferSize = 4 << 10 // 4 KiB (match default in linux)

	// The default size of the send/receive buffers.
	defaultBufferSize = 208 << 10 // 208 KiB  (default in linux for net.core.wmem_default)

	// The maximum permitted size for the send/receive buffers.
	maxBufferSize = 4 << 20 // 4 MiB 4 MiB (default in linux for net.core.wmem_max)
)

// A RightsControlMessage is a control message containing FDs.
//
// +stateify savable
type RightsControlMessage interface {
	// Clone returns a copy of the RightsControlMessage.
	Clone() RightsControlMessage

	// Release releases any resources owned by the RightsControlMessage.
	Release(ctx context.Context)
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
func (c *ControlMessages) Release(ctx context.Context) {
	if c.Rights != nil {
		c.Rights.Release(ctx)
	}
	*c = ControlMessages{}
}

// RecvArgs are the arguments to Endpoint.RecvMsg and Receiver.Recv.
type RecvArgs struct {
	// Creds indicates if credential control messages are requested by the
	// caller. This is useful for determining if control messages can be
	// coalesced. Creds is a hint and can be safely ignored by the
	// implementation if no coalescing is possible. It is fine to return
	// credential control messages when none were requested or to not
	// return credential control messages when they were requested.
	Creds bool

	// NumRights is the number of SCM_RIGHTS FDs requested by the caller.
	// This is useful if one must allocate a buffer to receive a SCM_RIGHTS
	// message or determine if control messages can be coalesced. numRights
	// is a hint and can be safely ignored by the implementation if the
	// number of available SCM_RIGHTS FDs is known and no coalescing is
	// possible. It is fine for the returned number of SCM_RIGHTS FDs to be
	// either higher or lower than the requested number.
	NumRights int

	// If Peek is true, no data should be consumed from the Endpoint. Any and
	// all data returned from a peek should be available in the next call to
	// Recv or RecvMsg.
	Peek bool
}

// RecvOutput is the output from Endpoint.RecvMsg and Receiver.Recv.
type RecvOutput struct {
	// RecvLen is the number of bytes copied into RecvArgs.Data.
	RecvLen int64

	// MsgLen is the length of the read message consumed for datagram Endpoints.
	// MsgLen is always the same as RecvLen for stream Endpoints.
	MsgLen int64

	// Source is the source address we received from.
	Source Address

	// Control is the ControlMessages read.
	Control ControlMessages

	// ControlTrunc indicates that the NumRights hint was used to receive
	// fewer than the total available SCM_RIGHTS FDs. Additional truncation
	// may be required by the caller.
	ControlTrunc bool

	// UnusedRights is a slice of unused RightsControlMessage which should
	// be Release()d.
	UnusedRights []RightsControlMessage
}

// UnixSocketOpts is a container for configuration options for gvisor's management of
// unix sockets.
// +stateify savable
type UnixSocketOpts struct {
	// If true, the endpoint will be put in a closed state before save; if false, an attempt to save
	// will throw.
	DisconnectOnSave bool
}

// Endpoint is the interface implemented by Unix transport protocol
// implementations that expose functionality like sendmsg, recvmsg, connect,
// etc. to Unix socket implementations.
type Endpoint interface {
	Credentialer
	waiter.Waitable

	// Close puts the endpoint in a closed state and frees all resources
	// associated with it.
	Close(ctx context.Context)

	// RecvMsg reads data and a control message from the endpoint. This method
	// does not block if there is no data pending.
	//
	// The returned callback should be called if not nil.
	RecvMsg(ctx context.Context, data [][]byte, args RecvArgs) (RecvOutput, func(), *syserr.Error)

	// SendMsg writes data and a control message to the endpoint's peer.
	// This method does not block if the data cannot be written.
	//
	// SendMsg does not take ownership of any of its arguments on error.
	//
	// If set, notify is a callback that should be called after RecvMesg
	// completes without mm.activeMu held.
	SendMsg(context.Context, [][]byte, ControlMessages, BoundEndpoint) (int64, func(), *syserr.Error)

	// Connect connects this endpoint directly to another.
	//
	// This should be called on the client endpoint, and the (bound)
	// endpoint passed in as a parameter.
	//
	// The error codes are the same as Connect.
	Connect(ctx context.Context, server BoundEndpoint, opts UnixSocketOpts) *syserr.Error

	// Shutdown closes the read and/or write end of the endpoint connection
	// to its peer.
	Shutdown(flags tcpip.ShutdownFlags) *syserr.Error

	// Listen puts the endpoint in "listen" mode, which allows it to accept
	// new connections.
	Listen(ctx context.Context, backlog int) *syserr.Error

	// Accept returns a new endpoint if a peer has established a connection
	// to an endpoint previously set to listen mode. This method does not
	// block if no new connections are available.
	//
	// The returned Queue is the wait queue for the newly created endpoint.
	//
	// peerAddr if not nil will be populated with the address of the connected
	// peer on a successful accept.
	Accept(ctx context.Context, peerAddr *Address, opts UnixSocketOpts) (Endpoint, *syserr.Error)

	// Bind binds the endpoint to a specific local address and port.
	// Specifying a NIC is optional.
	Bind(address Address) *syserr.Error

	// Type return the socket type, typically either SockStream, SockDgram
	// or SockSeqpacket.
	Type() linux.SockType

	// GetLocalAddress returns the address to which the endpoint is bound.
	GetLocalAddress() (Address, tcpip.Error)

	// GetRemoteAddress returns the address to which the endpoint is
	// connected.
	GetRemoteAddress() (Address, tcpip.Error)

	// SetSockOpt sets a socket option.
	SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error

	// SetSockOptInt sets a socket option for simple cases when a value has
	// the int type.
	SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error

	// GetSockOpt gets a socket option.
	GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error

	// GetSockOptInt gets a socket option for simple cases when a return
	// value has the int type.
	GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error)

	// State returns the current state of the socket, as represented by Linux in
	// procfs.
	State() uint32

	// LastError clears and returns the last error reported by the endpoint.
	LastError() tcpip.Error

	// SocketOptions returns the structure which contains all the socket
	// level options.
	SocketOptions() *tcpip.SocketOptions
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
	BidirectionalConnect(ctx context.Context, ep ConnectingEndpoint, returnConnect func(Receiver, ConnectedEndpoint), opts UnixSocketOpts) *syserr.Error

	// UnidirectionalConnect establishes a write-only connection to a unix
	// endpoint.
	//
	// An endpoint which calls UnidirectionalConnect and supports it itself must
	// not hold its own lock when calling UnidirectionalConnect.
	//
	// This method will return syserr.ErrConnectionRefused on a non-SockDgram
	// endpoint.
	UnidirectionalConnect(ctx context.Context, opts UnixSocketOpts) (ConnectedEndpoint, *syserr.Error)

	// Passcred returns whether or not the SO_PASSCRED socket option is
	// enabled on this end.
	Passcred() bool

	// Release releases any resources held by the BoundEndpoint. It must be
	// called before dropping all references to a BoundEndpoint returned by a
	// function.
	Release(ctx context.Context)
}

// HostBoundEndpoint is an interface that endpoints can implement if they support
// binding listening and accepting connections from a bound Unix domain socket
// on the host.
type HostBoundEndpoint interface {
	// SetBoundSocketFD will be called on supporting endpoints after
	// binding a socket on the host filesystem. Implementations should
	// delegate Listen and Accept calls to the BoundSocketFD. The ownership
	// of bsFD is transferred to the endpoint.
	SetBoundSocketFD(ctx context.Context, bsFD BoundSocketFD) error

	// ResetBoundSocketFD cleans up the BoundSocketFD set by the last successful
	// SetBoundSocketFD call.
	ResetBoundSocketFD(ctx context.Context)
}

// BoundSocketFD is an interface that wraps a socket FD that was bind(2)-ed.
// It allows to listen and accept on that socket.
type BoundSocketFD interface {
	// Close closes the socket FD.
	Close(ctx context.Context)

	// NotificationFD is a host FD that can be used to notify when new clients
	// connect to the socket.
	NotificationFD() int32

	// Listen is analogous to listen(2).
	Listen(ctx context.Context, backlog int32) error

	// Accept is analogous to accept(2).
	Accept(ctx context.Context) (int, error)
}

// message represents a message passed over a Unix domain socket.
//
// +stateify savable
type message struct {
	messageEntry

	// Data is the Message payload.
	Data []byte

	// Control is auxiliary control message data that goes along with the
	// data.
	Control ControlMessages

	// Address is the bound address of the endpoint that sent the message.
	//
	// If the endpoint that sent the message is not bound, the Address is
	// the empty string.
	Address Address
}

// Length returns number of bytes stored in the message.
func (m *message) Length() int64 {
	return int64(len(m.Data))
}

// Release releases any resources held by the message.
func (m *message) Release(ctx context.Context) {
	m.Control.Release(ctx)
}

// Peek returns a copy of the message.
func (m *message) Peek() *message {
	return &message{Data: m.Data, Control: m.Control.Clone(), Address: m.Address}
}

// Truncate reduces the length of the message payload to n bytes.
//
// Preconditions: n <= m.Length().
func (m *message) Truncate(n int64) {
	m.Data = m.Data[:n]
}

// A Receiver can be used to receive Messages.
type Receiver interface {
	// Recv receives a single message. This method does not block.
	//
	// notify indicates if RecvNotify should be called.
	Recv(ctx context.Context, data [][]byte, args RecvArgs) (out RecvOutput, notify bool, err *syserr.Error)

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

	// IsRecvClosed returns true if reception of additional messages is closed.
	IsRecvClosed() bool

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
	// called before dropping all references to a Receiver.
	Release(ctx context.Context)
}

// Address is a unix socket address.
//
// +stateify savable
type Address struct {
	Addr string
}

// queueReceiver implements Receiver for datagram sockets.
//
// +stateify savable
type queueReceiver struct {
	readQueue *queue
}

// Recv implements Receiver.Recv.
func (q *queueReceiver) Recv(ctx context.Context, data [][]byte, args RecvArgs) (RecvOutput, bool, *syserr.Error) {
	var m *message
	var notify bool
	var err *syserr.Error
	if args.Peek {
		m, err = q.readQueue.Peek()
	} else {
		m, notify, err = q.readQueue.Dequeue()
	}
	if err != nil {
		return RecvOutput{}, false, err
	}
	src := []byte(m.Data)
	var copied int64
	for i := 0; i < len(data) && len(src) > 0; i++ {
		n := copy(data[i], src)
		copied += int64(n)
		src = src[n:]
	}
	out := RecvOutput{
		RecvLen: copied,
		MsgLen:  int64(len(m.Data)),
		Control: m.Control,
		Source:  m.Address,
	}
	return out, notify, nil
}

// RecvNotify implements Receiver.RecvNotify.
func (q *queueReceiver) RecvNotify() {
	q.readQueue.WriterQueue.Notify(waiter.WritableEvents)
}

// CloseNotify implements Receiver.CloseNotify.
func (q *queueReceiver) CloseNotify() {
	q.readQueue.ReaderQueue.Notify(waiter.ReadableEvents)
	q.readQueue.WriterQueue.Notify(waiter.WritableEvents)
}

// CloseRecv implements Receiver.CloseRecv.
func (q *queueReceiver) CloseRecv() {
	q.readQueue.Close()
}

// IsRecvClosed implements Receiver.IsRecvClosed.
func (q *queueReceiver) IsRecvClosed() bool {
	return q.readQueue.isClosed()
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
func (q *queueReceiver) Release(ctx context.Context) {
	q.readQueue.DecRef(ctx)
}

// streamQueueReceiver implements Receiver for stream sockets.
//
// +stateify savable
type streamQueueReceiver struct {
	queueReceiver

	mu      streamQueueReceiverMutex `state:"nosave"`
	buffer  []byte
	control ControlMessages
	addr    Address
}

func vecCopy(data [][]byte, buf []byte) (int64, [][]byte, []byte) {
	var copied int64
	for len(data) > 0 && len(buf) > 0 {
		n := copy(data[0], buf)
		copied += int64(n)
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
func (q *streamQueueReceiver) Recv(ctx context.Context, data [][]byte, args RecvArgs) (RecvOutput, bool, *syserr.Error) {
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
			return RecvOutput{}, false, err
		}
		notify = n
		q.buffer = []byte(m.Data)
		q.control = m.Control
		q.addr = m.Address
	}

	var copied int64
	if args.Peek {
		// Don't consume control message if we are peeking.
		c := q.control.Clone()

		// Don't consume data since we are peeking.
		copied, _, _ = vecCopy(data, q.buffer)

		out := RecvOutput{
			RecvLen: copied,
			MsgLen:  copied,
			Control: c,
			Source:  q.addr,
		}
		return out, notify, nil
	}

	// Consume data and control message since we are not peeking.
	copied, data, q.buffer = vecCopy(data, q.buffer)

	// Save the original state of q.control.
	c := q.control

	// Remove rights from q.control and leave behind just the creds.
	q.control.Rights = nil
	if !args.Creds {
		c.Credentials = nil
	}

	var out RecvOutput
	if c.Rights != nil && args.NumRights == 0 {
		// We won't use these rights.
		out.UnusedRights = append(out.UnusedRights, c.Rights)
		c.Rights = nil
		out.ControlTrunc = true
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

		if args.Creds {
			if (q.control.Credentials == nil) != (c.Credentials == nil) {
				// One message has credentials, the other does not.
				break
			}

			if q.control.Credentials != nil && c.Credentials != nil && !q.control.Credentials.Equals(c.Credentials) {
				// Both messages have credentials, but they don't match.
				break
			}
		}

		if args.NumRights != 0 && c.Rights != nil && q.control.Rights != nil {
			// Both messages have rights.
			break
		}

		var cpd int64
		cpd, data, q.buffer = vecCopy(data, q.buffer)
		copied += cpd

		if cpd == 0 {
			// data was actually full.
			break
		}

		if q.control.Rights != nil {
			// Consume rights.
			if args.NumRights == 0 {
				out.ControlTrunc = true
				out.UnusedRights = append(out.UnusedRights, q.control.Rights)
			} else {
				c.Rights = q.control.Rights
				haveRights = true
			}
			q.control.Rights = nil
		}
	}

	out.MsgLen = copied
	out.RecvLen = copied
	out.Source = q.addr
	out.Control = c
	return out, notify, nil
}

// Release implements Receiver.Release.
func (q *streamQueueReceiver) Release(ctx context.Context) {
	q.queueReceiver.Release(ctx)
	q.control.Release(ctx)
}

// A ConnectedEndpoint is an Endpoint that can be used to send Messages.
type ConnectedEndpoint interface {
	// Passcred implements Endpoint.Passcred.
	Passcred() bool

	// GetLocalAddress implements Endpoint.GetLocalAddress.
	GetLocalAddress() (Address, tcpip.Error)

	// Send sends a single message. This method does not block.
	//
	// notify indicates if SendNotify should be called.
	//
	// syserr.ErrWouldBlock can be returned along with a partial write if
	// the caller should block to send the rest of the data.
	Send(ctx context.Context, data [][]byte, c ControlMessages, from Address) (n int64, notify bool, err *syserr.Error)

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

	// IsSendClosed returns true if transmission of additional messages is closed.
	IsSendClosed() bool

	// Writable returns if messages should be attempted to be sent. This
	// includes when write has been shutdown.
	Writable() bool

	// EventUpdate lets the ConnectedEndpoint know that event registrations
	// have changed.
	EventUpdate() error

	// SendQueuedSize returns the total amount of data currently queued for
	// sending. SendQueuedSize should return -1 if the operation isn't
	// supported.
	SendQueuedSize() int64

	// SendMaxQueueSize returns maximum value for SendQueuedSize.
	// SendMaxQueueSize should return -1 if the operation isn't supported.
	SendMaxQueueSize() int64

	// Release releases any resources owned by the ConnectedEndpoint. It should
	// be called before dropping all references to a ConnectedEndpoint.
	Release(ctx context.Context)

	// CloseUnread sets the fact that this end is closed with unread data to
	// the peer socket.
	CloseUnread()

	// SetSendBufferSize is called when the endpoint's send buffer size is
	// changed.
	SetSendBufferSize(v int64) (newSz int64)
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
		GetLocalAddress() (Address, tcpip.Error)

		// Type implements Endpoint.Type.
		Type() linux.SockType
	}

	writeQueue *queue
}

// Passcred implements ConnectedEndpoint.Passcred.
func (e *connectedEndpoint) Passcred() bool {
	return e.endpoint.Passcred()
}

// GetLocalAddress implements ConnectedEndpoint.GetLocalAddress.
func (e *connectedEndpoint) GetLocalAddress() (Address, tcpip.Error) {
	return e.endpoint.GetLocalAddress()
}

// Send implements ConnectedEndpoint.Send.
func (e *connectedEndpoint) Send(ctx context.Context, data [][]byte, c ControlMessages, from Address) (int64, bool, *syserr.Error) {
	discardEmpty := false
	truncate := false
	if e.endpoint.Type() == linux.SOCK_STREAM {
		// Discard empty stream packets. Since stream sockets don't
		// preserve message boundaries, sending zero bytes is a no-op.
		// In Linux, the receiver actually uses a zero-length receive
		// as an indication that the stream was closed.
		discardEmpty = true

		// Since stream sockets don't preserve message boundaries, we
		// can write only as much of the message as fits in the queue.
		truncate = true
	}

	return e.writeQueue.Enqueue(ctx, data, c, from, discardEmpty, truncate)
}

// SendNotify implements ConnectedEndpoint.SendNotify.
func (e *connectedEndpoint) SendNotify() {
	e.writeQueue.ReaderQueue.Notify(waiter.ReadableEvents)
}

// CloseNotify implements ConnectedEndpoint.CloseNotify.
func (e *connectedEndpoint) CloseNotify() {
	e.writeQueue.ReaderQueue.Notify(waiter.ReadableEvents)
	e.writeQueue.WriterQueue.Notify(waiter.WritableEvents)
}

// CloseSend implements ConnectedEndpoint.CloseSend.
func (e *connectedEndpoint) CloseSend() {
	e.writeQueue.Close()
}

// IsSendClosed implements ConnectedEndpoint.IsSendClosed.
func (e *connectedEndpoint) IsSendClosed() bool {
	return e.writeQueue.isClosed()
}

// Writable implements ConnectedEndpoint.Writable.
func (e *connectedEndpoint) Writable() bool {
	return e.writeQueue.IsWritable()
}

// EventUpdate implements ConnectedEndpoint.EventUpdate.
func (*connectedEndpoint) EventUpdate() error {
	return nil
}

// SendQueuedSize implements ConnectedEndpoint.SendQueuedSize.
func (e *connectedEndpoint) SendQueuedSize() int64 {
	return e.writeQueue.QueuedSize()
}

// SendMaxQueueSize implements ConnectedEndpoint.SendMaxQueueSize.
func (e *connectedEndpoint) SendMaxQueueSize() int64 {
	return e.writeQueue.MaxQueueSize()
}

// Release implements ConnectedEndpoint.Release.
func (e *connectedEndpoint) Release(ctx context.Context) {
	e.writeQueue.DecRef(ctx)
}

// CloseUnread implements ConnectedEndpoint.CloseUnread.
func (e *connectedEndpoint) CloseUnread() {
	e.writeQueue.CloseUnread()
}

// SetSendBufferSize implements ConnectedEndpoint.SetSendBufferSize.
// SetSendBufferSize sets the send buffer size for the write queue to the
// specified value.
func (e *connectedEndpoint) SetSendBufferSize(v int64) (newSz int64) {
	e.writeQueue.SetMaxQueueSize(v)
	return v
}

// baseEndpoint is an embeddable unix endpoint base used in both the connected
// and connectionless unix domain socket Endpoint implementations.
//
// Not to be used on its own.
//
// +stateify savable
type baseEndpoint struct {
	*waiter.Queue
	tcpip.DefaultSocketOptionsHandler

	// Mutex protects the below fields.
	//
	// See the lock ordering comment in package kernel/epoll regarding when
	// this lock can safely be held.
	endpointMutex `state:"nosave"`

	// receiver allows Messages to be received.
	receiver Receiver

	// connected allows messages to be sent and state information about the
	// connected endpoint to be read.
	connected ConnectedEndpoint

	// path is not empty if the endpoint has been bound,
	// or may be used if the endpoint is connected.
	path string

	// ops is used to get socket level options.
	ops tcpip.SocketOptions
}

// EventRegister implements waiter.Waitable.EventRegister.
func (e *baseEndpoint) EventRegister(we *waiter.Entry) error {
	e.Queue.EventRegister(we)
	e.Lock()
	c := e.connected
	e.Unlock()
	if c != nil {
		if err := c.EventUpdate(); err != nil {
			return err
		}
	}
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (e *baseEndpoint) EventUnregister(we *waiter.Entry) {
	e.Queue.EventUnregister(we)
	e.Lock()
	c := e.connected
	e.Unlock()
	if c != nil {
		c.EventUpdate()
	}
}

// Passcred implements Credentialer.Passcred.
func (e *baseEndpoint) Passcred() bool {
	return e.SocketOptions().GetPassCred()
}

// ConnectedPasscred implements Credentialer.ConnectedPasscred.
func (e *baseEndpoint) ConnectedPasscred() bool {
	e.Lock()
	defer e.Unlock()
	return e.connected != nil && e.connected.Passcred()
}

// Connected implements ConnectingEndpoint.Connected.
//
// Preconditions: e.mu must be held.
func (e *baseEndpoint) Connected() bool {
	return e.receiver != nil && e.connected != nil
}

// RecvMsg reads data and a control message from the endpoint.
func (e *baseEndpoint) RecvMsg(ctx context.Context, data [][]byte, args RecvArgs) (RecvOutput, func(), *syserr.Error) {
	e.Lock()
	receiver := e.receiver
	e.Unlock()

	if receiver == nil {
		return RecvOutput{}, nil, syserr.ErrNotConnected
	}

	out, notify, err := receiver.Recv(ctx, data, args)
	if err != nil {
		return RecvOutput{}, nil, err
	}

	if notify {
		return out, receiver.RecvNotify, nil
	}

	return out, nil, nil
}

// SendMsg writes data and a control message to the endpoint's peer.
// This method does not block if the data cannot be written.
func (e *baseEndpoint) SendMsg(ctx context.Context, data [][]byte, c ControlMessages, to BoundEndpoint) (int64, func(), *syserr.Error) {
	e.Lock()
	if !e.Connected() {
		e.Unlock()
		return 0, nil, syserr.ErrNotConnected
	}
	if to != nil {
		e.Unlock()
		return 0, nil, syserr.ErrAlreadyConnected
	}

	connected := e.connected
	n, notify, err := connected.Send(ctx, data, c, Address{Addr: e.path})
	e.Unlock()

	var notifyFn func()
	if notify {
		notifyFn = connected.SendNotify
	}

	return n, notifyFn, err
}

// SetSockOpt sets a socket option.
func (e *baseEndpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return nil
}

func (e *baseEndpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	log.Warningf("Unsupported socket option: %d", opt)
	return nil
}

func (e *baseEndpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		v := 0
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return -1, &tcpip.ErrNotConnected{}
		}
		v = int(e.receiver.RecvQueuedSize())
		e.Unlock()
		if v < 0 {
			return -1, &tcpip.ErrQueueSizeNotSupported{}
		}
		return v, nil

	case tcpip.SendQueueSizeOption:
		e.Lock()
		if !e.Connected() {
			e.Unlock()
			return -1, &tcpip.ErrNotConnected{}
		}
		v := e.connected.SendQueuedSize()
		e.Unlock()
		if v < 0 {
			return -1, &tcpip.ErrQueueSizeNotSupported{}
		}
		return int(v), nil

	default:
		log.Warningf("Unsupported socket option: %d", opt)
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *baseEndpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	log.Warningf("Unsupported socket option: %T", opt)
	return &tcpip.ErrUnknownProtocolOption{}
}

// LastError implements Endpoint.LastError.
func (*baseEndpoint) LastError() tcpip.Error {
	return nil
}

// SocketOptions implements Endpoint.SocketOptions.
func (e *baseEndpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *baseEndpoint) Shutdown(flags tcpip.ShutdownFlags) *syserr.Error {
	e.Lock()
	if !e.Connected() {
		e.Unlock()
		return syserr.ErrNotConnected
	}

	var (
		r             = e.receiver
		c             = e.connected
		shutdownRead  = flags&tcpip.ShutdownRead != 0
		shutdownWrite = flags&tcpip.ShutdownWrite != 0
	)
	if shutdownRead {
		r.CloseRecv()
	}
	if shutdownWrite {
		c.CloseSend()
	}
	e.Unlock()

	// Don't hold e.Mutex while calling CloseNotify.
	if shutdownRead {
		r.CloseNotify()
	}
	if shutdownWrite {
		c.CloseNotify()
	}

	return nil
}

// GetLocalAddress returns the bound path.
func (e *baseEndpoint) GetLocalAddress() (Address, tcpip.Error) {
	e.Lock()
	defer e.Unlock()
	return Address{Addr: e.path}, nil
}

// GetRemoteAddress returns the local address of the connected endpoint (if
// available).
func (e *baseEndpoint) GetRemoteAddress() (Address, tcpip.Error) {
	e.Lock()
	c := e.connected
	e.Unlock()
	if c != nil {
		return c.GetLocalAddress()
	}
	return Address{}, &tcpip.ErrNotConnected{}
}

// Release implements BoundEndpoint.Release.
func (*baseEndpoint) Release(context.Context) {
	// Binding a baseEndpoint doesn't take a reference.
}

// stackHandler is just a stub implementation of tcpip.StackHandler to provide
// when initializing socketoptions.
type stackHandler struct {
}

// Option implements tcpip.StackHandler.
func (h *stackHandler) Option(option any) tcpip.Error {
	panic("unimplemented")
}

// TransportProtocolOption implements tcpip.StackHandler.
func (h *stackHandler) TransportProtocolOption(proto tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	panic("unimplemented")
}

// getSendBufferLimits implements tcpip.GetSendBufferLimits.
//
// AF_UNIX sockets buffer sizes are not tied to the networking stack/namespace
// in linux but are bound by net.core.(wmem|rmem)_(max|default).
//
// In gVisor net.core sysctls today are not exposed or if exposed are currently
// tied to the networking stack in use. This makes it complicated for AF_UNIX
// when we are in a new namespace w/ no networking stack. As a result for now we
// define default/max values here in the unix socket implementation itself.
func getSendBufferLimits(tcpip.StackHandler) tcpip.SendBufferSizeOption {
	return tcpip.SendBufferSizeOption{
		Min:     minimumBufferSize,
		Default: defaultBufferSize,
		Max:     maxBufferSize,
	}
}

// getReceiveBufferLimits implements tcpip.GetReceiveBufferLimits.
//
// We define min, max and default values for unix socket implementation. Unix
// sockets do not use receive buffer.
func getReceiveBufferLimits(tcpip.StackHandler) tcpip.ReceiveBufferSizeOption {
	return tcpip.ReceiveBufferSizeOption{
		Min:     minimumBufferSize,
		Default: defaultBufferSize,
		Max:     maxBufferSize,
	}
}
