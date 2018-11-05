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

package tcp

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/rand"
	"gvisor.googlesource.com/gvisor/pkg/sleep"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tmutex"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

type endpointState int

const (
	stateInitial endpointState = iota
	stateBound
	stateListen
	stateConnecting
	stateConnected
	stateClosed
	stateError
)

// Reasons for notifying the protocol goroutine.
const (
	notifyNonZeroReceiveWindow = 1 << iota
	notifyReceiveWindowChanged
	notifyClose
	notifyMTUChanged
	notifyDrain
	notifyReset
	notifyKeepaliveChanged
)

// SACKInfo holds TCP SACK related information for a given endpoint.
//
// +stateify savable
type SACKInfo struct {
	// Blocks is the maximum number of SACK blocks we track
	// per endpoint.
	Blocks [MaxSACKBlocks]header.SACKBlock

	// NumBlocks is the number of valid SACK blocks stored in the
	// blocks array above.
	NumBlocks int
}

// endpoint represents a TCP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized. The protocol implementation, however, runs in a single
// goroutine.
//
// +stateify savable
type endpoint struct {
	// workMu is used to arbitrate which goroutine may perform protocol
	// work. Only the main protocol goroutine is expected to call Lock() on
	// it, but other goroutines (e.g., send) may call TryLock() to eagerly
	// perform work without having to wait for the main one to wake up.
	workMu tmutex.Mutex `state:"nosave"`

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack `state:"manual"`
	netProto    tcpip.NetworkProtocolNumber
	waiterQueue *waiter.Queue `state:"wait"`

	// lastError represents the last error that the endpoint reported;
	// access to it is protected by the following mutex.
	lastErrorMu sync.Mutex   `state:"nosave"`
	lastError   *tcpip.Error `state:".(string)"`

	// The following fields are used to manage the receive queue. The
	// protocol goroutine adds ready-for-delivery segments to rcvList,
	// which are returned by Read() calls to users.
	//
	// Once the peer has closed its send side, rcvClosed is set to true
	// to indicate to users that no more data is coming.
	//
	// rcvListMu can be taken after the endpoint mu below.
	rcvListMu  sync.Mutex  `state:"nosave"`
	rcvList    segmentList `state:"wait"`
	rcvClosed  bool
	rcvBufSize int
	rcvBufUsed int

	// The following fields are protected by the mutex.
	mu                sync.RWMutex `state:"nosave"`
	id                stack.TransportEndpointID
	state             endpointState `state:".(endpointState)"`
	isPortReserved    bool          `state:"manual"`
	isRegistered      bool
	boundNICID        tcpip.NICID `state:"manual"`
	route             stack.Route `state:"manual"`
	v6only            bool
	isConnectNotified bool

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber `state:"manual"`

	// hardError is meaningful only when state is stateError, it stores the
	// error to be returned when read/write syscalls are called and the
	// endpoint is in this state. hardError is protected by mu.
	hardError *tcpip.Error `state:".(string)"`

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// workerCleanup specifies if the worker goroutine must perform cleanup
	// before exitting. This can only be set to true when workerRunning is
	// also true, and they're both protected by the mutex.
	workerCleanup bool

	// sendTSOk is used to indicate when the TS Option has been negotiated.
	// When sendTSOk is true every non-RST segment should carry a TS as per
	// RFC7323#section-1.1
	sendTSOk bool

	// recentTS is the timestamp that should be sent in the TSEcr field of
	// the timestamp for future segments sent by the endpoint. This field is
	// updated if required when a new segment is received by this endpoint.
	recentTS uint32

	// tsOffset is a randomized offset added to the value of the
	// TSVal field in the timestamp option.
	tsOffset uint32

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// sackPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	sackPermitted bool

	// sack holds TCP SACK related information for this endpoint.
	sack SACKInfo

	// The options below aren't implemented, but we remember the user
	// settings because applications expect to be able to set/query these
	// options.
	noDelay   bool
	reuseAddr bool

	// segmentQueue is used to hand received segments to the protocol
	// goroutine. Segments are queued as long as the queue is not full,
	// and dropped when it is.
	segmentQueue segmentQueue `state:"wait"`

	// The following fields are used to manage the send buffer. When
	// segments are ready to be sent, they are added to sndQueue and the
	// protocol goroutine is signaled via sndWaker.
	//
	// When the send side is closed, the protocol goroutine is notified via
	// sndCloseWaker, and sndClosed is set to true.
	sndBufMu      sync.Mutex `state:"nosave"`
	sndBufSize    int
	sndBufUsed    int
	sndClosed     bool
	sndBufInQueue seqnum.Size
	sndQueue      segmentList `state:"wait"`
	sndWaker      sleep.Waker `state:"manual"`
	sndCloseWaker sleep.Waker `state:"manual"`

	// cc stores the name of the Congestion Control algorithm to use for
	// this endpoint.
	cc CongestionControlOption

	// The following are used when a "packet too big" control packet is
	// received. They are protected by sndBufMu. They are used to
	// communicate to the main protocol goroutine how many such control
	// messages have been received since the last notification was processed
	// and what was the smallest MTU seen.
	packetTooBigCount int
	sndMTU            int

	// newSegmentWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and handle new segments queued to it.
	newSegmentWaker sleep.Waker `state:"manual"`

	// notificationWaker is used to indicate to the protocol goroutine that
	// it needs to wake up and check for notifications.
	notificationWaker sleep.Waker `state:"manual"`

	// notifyFlags is a bitmask of flags used to indicate to the protocol
	// goroutine what it was notified; this is only accessed atomically.
	notifyFlags uint32 `state:"nosave"`

	// keepalive manages TCP keepalive state. When the connection is idle
	// (no data sent or received) for keepaliveIdle, we start sending
	// keepalives every keepalive.interval. If we send keepalive.count
	// without hearing a response, the connection is closed.
	keepalive keepalive

	// acceptedChan is used by a listening endpoint protocol goroutine to
	// send newly accepted connections to the endpoint so that they can be
	// read by Accept() calls.
	acceptedChan chan *endpoint `state:".([]*endpoint)"`

	// The following are only used from the protocol goroutine, and
	// therefore don't need locks to protect them.
	rcv *receiver `state:"wait"`
	snd *sender   `state:"wait"`

	// The goroutine drain completion notification channel.
	drainDone chan struct{} `state:"nosave"`

	// The goroutine undrain notification channel.
	undrain chan struct{} `state:"nosave"`

	// probe if not nil is invoked on every received segment. It is passed
	// a copy of the current state of the endpoint.
	probe stack.TCPProbeFunc `state:"nosave"`

	// The following are only used to assist the restore run to re-connect.
	bindAddress       tcpip.Address
	connectingAddress tcpip.Address
}

// StopWork halts packet processing. Only to be used in tests.
func (e *endpoint) StopWork() {
	e.workMu.Lock()
}

// ResumeWork resumes packet processing. Only to be used in tests.
func (e *endpoint) ResumeWork() {
	e.workMu.Unlock()
}

// keepalive is a synchronization wrapper used to appease stateify. See the
// comment in endpoint, where it is used.
//
// +stateify savable
type keepalive struct {
	sync.Mutex `state:"nosave"`
	enabled    bool
	idle       time.Duration
	interval   time.Duration
	count      int
	unacked    int
	timer      timer       `state:"nosave"`
	waker      sleep.Waker `state:"nosave"`
}

func newEndpoint(stack *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:       stack,
		netProto:    netProto,
		waiterQueue: waiterQueue,
		rcvBufSize:  DefaultBufferSize,
		sndBufSize:  DefaultBufferSize,
		sndMTU:      int(math.MaxInt32),
		noDelay:     false,
		reuseAddr:   true,
		keepalive: keepalive{
			// Linux defaults.
			idle:     2 * time.Hour,
			interval: 75 * time.Second,
			count:    9,
		},
	}

	var ss SendBufferSizeOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.sndBufSize = ss.Default
	}

	var rs ReceiveBufferSizeOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.rcvBufSize = rs.Default
	}

	var cs CongestionControlOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	if p := stack.GetTCPProbe(); p != nil {
		e.probe = p
	}

	e.segmentQueue.setLimit(2 * e.rcvBufSize)
	e.workMu.Init()
	e.workMu.Lock()
	e.tsOffset = timeStampOffset()
	return e
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.EventMask(0)

	e.mu.RLock()
	defer e.mu.RUnlock()

	switch e.state {
	case stateInitial, stateBound, stateConnecting:
		// Ready for nothing.

	case stateClosed, stateError:
		// Ready for anything.
		result = mask

	case stateListen:
		// Check if there's anything in the accepted channel.
		if (mask & waiter.EventIn) != 0 {
			if len(e.acceptedChan) > 0 {
				result |= waiter.EventIn
			}
		}

	case stateConnected:
		// Determine if the endpoint is writable if requested.
		if (mask & waiter.EventOut) != 0 {
			e.sndBufMu.Lock()
			if e.sndClosed || e.sndBufUsed < e.sndBufSize {
				result |= waiter.EventOut
			}
			e.sndBufMu.Unlock()
		}

		// Determine if the endpoint is readable if requested.
		if (mask & waiter.EventIn) != 0 {
			e.rcvListMu.Lock()
			if e.rcvBufUsed > 0 || e.rcvClosed {
				result |= waiter.EventIn
			}
			e.rcvListMu.Unlock()
		}
	}

	return result
}

func (e *endpoint) fetchNotifications() uint32 {
	return atomic.SwapUint32(&e.notifyFlags, 0)
}

func (e *endpoint) notifyProtocolGoroutine(n uint32) {
	for {
		v := atomic.LoadUint32(&e.notifyFlags)
		if v&n == n {
			// The flags are already set.
			return
		}

		if atomic.CompareAndSwapUint32(&e.notifyFlags, v, v|n) {
			if v == 0 {
				// We are causing a transition from no flags to
				// at least one flag set, so we must cause the
				// protocol goroutine to wake up.
				e.notificationWaker.Assert()
			}
			return
		}
	}
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it. It must be called only once and with no other concurrent calls to
// the endpoint.
func (e *endpoint) Close() {
	// Issue a shutdown so that the peer knows we won't send any more data
	// if we're connected, or stop accepting if we're listening.
	e.Shutdown(tcpip.ShutdownWrite | tcpip.ShutdownRead)

	e.mu.Lock()

	// We always release ports inline so that they are immediately available
	// for reuse after Close() is called. If also registered, it means this
	// is a listening socket, so we must unregister as well otherwise the
	// next user would fail in Listen() when trying to register.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
		e.isPortReserved = false

		if e.isRegistered {
			e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
			e.isRegistered = false
		}
	}

	// Either perform the local cleanup or kick the worker to make sure it
	// knows it needs to cleanup.
	tcpip.AddDanglingEndpoint(e)
	if !e.workerRunning {
		e.cleanupLocked()
	} else {
		e.workerCleanup = true
		e.notifyProtocolGoroutine(notifyClose)
	}

	e.mu.Unlock()
}

// cleanupLocked frees all resources associated with the endpoint. It is called
// after Close() is called and the worker goroutine (if any) is done with its
// work.
func (e *endpoint) cleanupLocked() {
	// Close all endpoints that might have been accepted by TCP but not by
	// the client.
	if e.acceptedChan != nil {
		close(e.acceptedChan)
		for n := range e.acceptedChan {
			n.mu.Lock()
			n.resetConnectionLocked(tcpip.ErrConnectionAborted)
			n.mu.Unlock()
			n.Close()
		}
		e.acceptedChan = nil
	}
	e.workerCleanup = false

	if e.isRegistered {
		e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id)
	}

	e.route.Release()
	tcpip.DeleteDanglingEndpoint(e)
}

// Read reads data from the endpoint.
func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()
	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data. Also note that a RST being received
	// would cause the state to become stateError so we should allow the
	// reads to proceed before returning a ECONNRESET.
	e.rcvListMu.Lock()
	bufUsed := e.rcvBufUsed
	if s := e.state; s != stateConnected && s != stateClosed && bufUsed == 0 {
		e.rcvListMu.Unlock()
		he := e.hardError
		e.mu.RUnlock()
		if s == stateError {
			return buffer.View{}, tcpip.ControlMessages{}, he
		}
		return buffer.View{}, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	v, err := e.readLocked()
	e.rcvListMu.Unlock()

	e.mu.RUnlock()

	return v, tcpip.ControlMessages{}, err
}

func (e *endpoint) readLocked() (buffer.View, *tcpip.Error) {
	if e.rcvBufUsed == 0 {
		if e.rcvClosed || e.state != stateConnected {
			return buffer.View{}, tcpip.ErrClosedForReceive
		}
		return buffer.View{}, tcpip.ErrWouldBlock
	}

	s := e.rcvList.Front()
	views := s.data.Views()
	v := views[s.viewToDeliver]
	s.viewToDeliver++

	if s.viewToDeliver >= len(views) {
		e.rcvList.Remove(s)
		s.decRef()
	}

	scale := e.rcv.rcvWndScale
	wasZero := e.zeroReceiveWindow(scale)
	e.rcvBufUsed -= len(v)
	if wasZero && !e.zeroReceiveWindow(scale) {
		e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
	}

	return v, nil
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(p tcpip.Payload, opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	// Linux completely ignores any address passed to sendto(2) for TCP sockets
	// (without the MSG_FASTOPEN flag). Corking is unimplemented, so opts.More
	// and opts.EndOfRecord are also ignored.

	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be written to if it's not connected.
	if e.state != stateConnected {
		switch e.state {
		case stateError:
			return 0, nil, e.hardError
		default:
			return 0, nil, tcpip.ErrClosedForSend
		}
	}

	// Nothing to do if the buffer is empty.
	if p.Size() == 0 {
		return 0, nil, nil
	}

	e.sndBufMu.Lock()

	// Check if the connection has already been closed for sends.
	if e.sndClosed {
		e.sndBufMu.Unlock()
		return 0, nil, tcpip.ErrClosedForSend
	}

	// Check against the limit.
	avail := e.sndBufSize - e.sndBufUsed
	if avail <= 0 {
		e.sndBufMu.Unlock()
		return 0, nil, tcpip.ErrWouldBlock
	}

	v, perr := p.Get(avail)
	if perr != nil {
		e.sndBufMu.Unlock()
		return 0, nil, perr
	}

	var err *tcpip.Error
	if p.Size() > avail {
		err = tcpip.ErrWouldBlock
	}
	l := len(v)
	s := newSegmentFromView(&e.route, e.id, v)

	// Add data to the send queue.
	e.sndBufUsed += l
	e.sndBufInQueue += seqnum.Size(l)
	e.sndQueue.PushBack(s)

	e.sndBufMu.Unlock()

	if e.workMu.TryLock() {
		// Do the work inline.
		e.handleWrite()
		e.workMu.Unlock()
	} else {
		// Let the protocol goroutine do the work.
		e.sndWaker.Assert()
	}
	return uintptr(l), nil, err
}

// Peek reads data without consuming it from the endpoint.
//
// This method does not block if there is no data pending.
func (e *endpoint) Peek(vec [][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data.
	if s := e.state; s != stateConnected && s != stateClosed {
		if s == stateError {
			return 0, tcpip.ControlMessages{}, e.hardError
		}
		return 0, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed || e.state != stateConnected {
			return 0, tcpip.ControlMessages{}, tcpip.ErrClosedForReceive
		}
		return 0, tcpip.ControlMessages{}, tcpip.ErrWouldBlock
	}

	// Make a copy of vec so we can modify the slide headers.
	vec = append([][]byte(nil), vec...)

	var num uintptr

	for s := e.rcvList.Front(); s != nil; s = s.Next() {
		views := s.data.Views()

		for i := s.viewToDeliver; i < len(views); i++ {
			v := views[i]

			for len(v) > 0 {
				if len(vec) == 0 {
					return num, tcpip.ControlMessages{}, nil
				}
				if len(vec[0]) == 0 {
					vec = vec[1:]
					continue
				}

				n := copy(vec[0], v)
				v = v[n:]
				vec[0] = vec[0][n:]
				num += uintptr(n)
			}
		}
	}

	return num, tcpip.ControlMessages{}, nil
}

// zeroReceiveWindow checks if the receive window to be announced now would be
// zero, based on the amount of available buffer and the receive window scaling.
//
// It must be called with rcvListMu held.
func (e *endpoint) zeroReceiveWindow(scale uint8) bool {
	if e.rcvBufUsed >= e.rcvBufSize {
		return true
	}

	return ((e.rcvBufSize - e.rcvBufUsed) >> scale) == 0
}

// SetSockOpt sets a socket option.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	switch v := opt.(type) {
	case tcpip.NoDelayOption:
		e.mu.Lock()
		e.noDelay = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.ReuseAddressOption:
		e.mu.Lock()
		e.reuseAddr = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.ReceiveBufferSizeOption:
		// Make sure the receive buffer size is within the min and max
		// allowed.
		var rs ReceiveBufferSizeOption
		size := int(v)
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
			if size < rs.Min {
				size = rs.Min
			}
			if size > rs.Max {
				size = rs.Max
			}
		}

		mask := uint32(notifyReceiveWindowChanged)

		e.rcvListMu.Lock()

		// Make sure the receive buffer size allows us to send a
		// non-zero window size.
		scale := uint8(0)
		if e.rcv != nil {
			scale = e.rcv.rcvWndScale
		}
		if size>>scale == 0 {
			size = 1 << scale
		}

		// Make sure 2*size doesn't overflow.
		if size > math.MaxInt32/2 {
			size = math.MaxInt32 / 2
		}

		wasZero := e.zeroReceiveWindow(scale)
		e.rcvBufSize = size
		if wasZero && !e.zeroReceiveWindow(scale) {
			mask |= notifyNonZeroReceiveWindow
		}
		e.rcvListMu.Unlock()

		e.segmentQueue.setLimit(2 * size)

		e.notifyProtocolGoroutine(mask)
		return nil

	case tcpip.SendBufferSizeOption:
		// Make sure the send buffer size is within the min and max
		// allowed.
		size := int(v)
		var ss SendBufferSizeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
			if size < ss.Min {
				size = ss.Min
			}
			if size > ss.Max {
				size = ss.Max
			}
		}

		e.sndBufMu.Lock()
		e.sndBufSize = size
		e.sndBufMu.Unlock()

		return nil

	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != stateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0

	case tcpip.KeepaliveEnabledOption:
		e.keepalive.Lock()
		e.keepalive.enabled = v != 0
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		e.keepalive.count = int(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	}

	return nil
}

// readyReceiveSize returns the number of bytes ready to be received.
func (e *endpoint) readyReceiveSize() (int, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be in listen state.
	if e.state == stateListen {
		return 0, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	return e.rcvBufUsed, nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt interface{}) *tcpip.Error {
	switch o := opt.(type) {
	case tcpip.ErrorOption:
		e.lastErrorMu.Lock()
		err := e.lastError
		e.lastError = nil
		e.lastErrorMu.Unlock()
		return err

	case *tcpip.SendBufferSizeOption:
		e.sndBufMu.Lock()
		*o = tcpip.SendBufferSizeOption(e.sndBufSize)
		e.sndBufMu.Unlock()
		return nil

	case *tcpip.ReceiveBufferSizeOption:
		e.rcvListMu.Lock()
		*o = tcpip.ReceiveBufferSizeOption(e.rcvBufSize)
		e.rcvListMu.Unlock()
		return nil

	case *tcpip.ReceiveQueueSizeOption:
		v, err := e.readyReceiveSize()
		if err != nil {
			return err
		}

		*o = tcpip.ReceiveQueueSizeOption(v)
		return nil

	case *tcpip.NoDelayOption:
		e.mu.RLock()
		v := e.noDelay
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.ReuseAddressOption:
		e.mu.RLock()
		v := e.reuseAddr
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.netProto != header.IPv6ProtocolNumber {
			return tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.TCPInfoOption:
		*o = tcpip.TCPInfoOption{}
		e.mu.RLock()
		snd := e.snd
		e.mu.RUnlock()
		if snd != nil {
			snd.rtt.Lock()
			o.RTT = snd.rtt.srtt
			o.RTTVar = snd.rtt.rttvar
			snd.rtt.Unlock()
		}

		return nil

	case *tcpip.KeepaliveEnabledOption:
		e.keepalive.Lock()
		v := e.keepalive.enabled
		e.keepalive.Unlock()

		*o = 0
		if v {
			*o = 1
		}

	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIdleOption(e.keepalive.idle)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIntervalOption(e.keepalive.interval)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveCountOption(e.keepalive.count)
		e.keepalive.Unlock()

	}

	return tcpip.ErrUnknownProtocolOption
}

func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto := e.netProto
	if header.IsV4MappedAddress(addr.Addr) {
		// Fail if using a v4 mapped address on a v6only endpoint.
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		netProto = header.IPv4ProtocolNumber
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		if addr.Addr == "\x00\x00\x00\x00" {
			addr.Addr = ""
		}
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	if l := len(e.id.LocalAddress); l != 0 && len(addr.Addr) != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Connect connects the endpoint to its peer.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	return e.connect(addr, true, true)
}

// connect connects the endpoint to its peer. In the normal non-S/R case, the
// new connection is expected to run the main goroutine and perform handshake.
// In restore of previously connected endpoints, both ends will be passively
// created (so no new handshaking is done); for stack-accepted connections not
// yet accepted by the app, they are restored without running the main goroutine
// here.
func (e *endpoint) connect(addr tcpip.FullAddress, handshake bool, run bool) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil && !err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		}
	}()

	connectingAddr := addr.Addr

	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}

	nicid := addr.NIC
	switch e.state {
	case stateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicid != 0 && nicid != e.boundNICID {
			return tcpip.ErrNoRoute
		}

		nicid = e.boundNICID

	case stateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID
		// (if any) when we find a route.

	case stateConnecting:
		// A connection request has already been issued but hasn't
		// completed yet.
		return tcpip.ErrAlreadyConnecting

	case stateConnected:
		// The endpoint is already connected. If caller hasn't been notified yet, return success.
		if !e.isConnectNotified {
			e.isConnectNotified = true
			return nil
		}
		// Otherwise return that it's already connected.
		return tcpip.ErrAlreadyConnected

	case stateError:
		return e.hardError

	default:
		return tcpip.ErrInvalidEndpointState
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

	origID := e.id

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	e.id.LocalAddress = r.LocalAddress
	e.id.RemoteAddress = r.RemoteAddress
	e.id.RemotePort = addr.Port

	if e.id.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, e.id, e)
		if err != nil {
			return err
		}
	} else {
		// The endpoint doesn't have a local port yet, so try to get
		// one. Make sure that it isn't one that will result in the same
		// address/port for both local and remote (otherwise this
		// endpoint would be trying to connect to itself).
		sameAddr := e.id.LocalAddress == e.id.RemoteAddress
		if _, err := e.stack.PickEphemeralPort(func(p uint16) (bool, *tcpip.Error) {
			if sameAddr && p == e.id.RemotePort {
				return false, nil
			}
			if !e.stack.IsPortAvailable(netProtos, ProtocolNumber, e.id.LocalAddress, p) {
				return false, nil
			}

			id := e.id
			id.LocalPort = p
			switch e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e) {
			case nil:
				e.id = id
				return true, nil
			case tcpip.ErrPortInUse:
				return false, nil
			default:
				return false, err
			}
		}); err != nil {
			return err
		}
	}

	// Remove the port reservation. This can happen when Bind is called
	// before Connect: in such a case we don't want to hold on to
	// reservations anymore.
	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, origID.LocalAddress, origID.LocalPort)
		e.isPortReserved = false
	}

	e.isRegistered = true
	e.state = stateConnecting
	e.route = r.Clone()
	e.boundNICID = nicid
	e.effectiveNetProtos = netProtos
	e.connectingAddress = connectingAddr

	// Connect in the restore phase does not perform handshake. Restore its
	// connection setting here.
	if !handshake {
		e.segmentQueue.mu.Lock()
		for _, l := range []segmentList{e.segmentQueue.list, e.sndQueue, e.snd.writeList} {
			for s := l.Front(); s != nil; s = s.Next() {
				s.id = e.id
				s.route = r.Clone()
				e.sndWaker.Assert()
			}
		}
		e.segmentQueue.mu.Unlock()
		e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		e.state = stateConnected
	}

	if run {
		e.workerRunning = true
		e.stack.Stats().TCP.ActiveConnectionOpenings.Increment()
		go e.protocolMainLoop(handshake) // S/R-SAFE: will be drained before save.
	}

	return tcpip.ErrConnectStarted
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) *tcpip.Error {
	return tcpip.ErrInvalidEndpointState
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.shutdownFlags |= flags

	switch e.state {
	case stateConnected:
		// Close for write.
		if (e.shutdownFlags & tcpip.ShutdownWrite) != 0 {
			if (e.shutdownFlags & tcpip.ShutdownRead) != 0 {
				// We're fully closed, if we have unread data we need to abort
				// the connection with a RST.
				e.rcvListMu.Lock()
				rcvBufUsed := e.rcvBufUsed
				e.rcvListMu.Unlock()

				if rcvBufUsed > 0 {
					e.notifyProtocolGoroutine(notifyReset)
					return nil
				}
			}

			e.sndBufMu.Lock()

			if e.sndClosed {
				// Already closed.
				e.sndBufMu.Unlock()
				break
			}

			// Queue fin segment.
			s := newSegmentFromView(&e.route, e.id, nil)
			e.sndQueue.PushBack(s)
			e.sndBufInQueue++

			// Mark endpoint as closed.
			e.sndClosed = true

			e.sndBufMu.Unlock()

			// Tell protocol goroutine to close.
			e.sndCloseWaker.Assert()
		}

	case stateListen:
		// Tell protocolListenLoop to stop.
		if flags&tcpip.ShutdownRead != 0 {
			e.notifyProtocolGoroutine(notifyClose)
		}

	default:
		return tcpip.ErrNotConnected
	}

	return nil
}

// Listen puts the endpoint in "listen" mode, which allows it to accept
// new connections.
func (e *endpoint) Listen(backlog int) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	defer func() {
		if err != nil && !err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		}
	}()

	// Allow the backlog to be adjusted if the endpoint is not shutting down.
	// When the endpoint shuts down, it sets workerCleanup to true, and from
	// that point onward, acceptedChan is the responsibility of the cleanup()
	// method (and should not be touched anywhere else, including here).
	if e.state == stateListen && !e.workerCleanup {
		// Adjust the size of the channel iff we can fix existing
		// pending connections into the new one.
		if len(e.acceptedChan) > backlog {
			return tcpip.ErrInvalidEndpointState
		}
		if cap(e.acceptedChan) == backlog {
			return nil
		}
		origChan := e.acceptedChan
		e.acceptedChan = make(chan *endpoint, backlog)
		close(origChan)
		for ep := range origChan {
			e.acceptedChan <- ep
		}
		return nil
	}

	// Endpoint must be bound before it can transition to listen mode.
	if e.state != stateBound {
		return tcpip.ErrInvalidEndpointState
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e); err != nil {
		return err
	}

	e.isRegistered = true
	e.state = stateListen
	if e.acceptedChan == nil {
		e.acceptedChan = make(chan *endpoint, backlog)
	}
	e.workerRunning = true

	e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()
	go e.protocolListenLoop( // S/R-SAFE: drained on save.
		seqnum.Size(e.receiveBufferAvailable()))

	return nil
}

// startAcceptedLoop sets up required state and starts a goroutine with the
// main loop for accepted connections.
func (e *endpoint) startAcceptedLoop(waiterQueue *waiter.Queue) {
	e.waiterQueue = waiterQueue
	e.workerRunning = true
	go e.protocolMainLoop(false) // S/R-SAFE: drained on save.
}

// Accept returns a new endpoint if a peer has established a connection
// to an endpoint previously set to listen mode.
func (e *endpoint) Accept() (tcpip.Endpoint, *waiter.Queue, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Endpoint must be in listen state before it can accept connections.
	if e.state != stateListen {
		return nil, nil, tcpip.ErrInvalidEndpointState
	}

	// Get the new accepted endpoint.
	var n *endpoint
	select {
	case n = <-e.acceptedChan:
	default:
		return nil, nil, tcpip.ErrWouldBlock
	}

	// Start the protocol goroutine.
	wq := &waiter.Queue{}
	n.startAcceptedLoop(wq)

	return n, wq, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
func (e *endpoint) Bind(addr tcpip.FullAddress, commit func() *tcpip.Error) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.state != stateInitial {
		return tcpip.ErrAlreadyBound
	}

	e.bindAddress = addr.Addr
	netProto, err := e.checkV4Mapped(&addr)
	if err != nil {
		return err
	}

	// Expand netProtos to include v4 and v6 if the caller is binding to a
	// wildcard (empty) address, and this is an IPv6 endpoint with v6only
	// set to false.
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if netProto == header.IPv6ProtocolNumber && !e.v6only && addr.Addr == "" {
		netProtos = []tcpip.NetworkProtocolNumber{
			header.IPv6ProtocolNumber,
			header.IPv4ProtocolNumber,
		}
	}

	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port)
	if err != nil {
		return err
	}

	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.id.LocalPort = port

	// Any failures beyond this point must remove the port registration.
	defer func() {
		if err != nil {
			e.stack.ReleasePort(netProtos, ProtocolNumber, addr.Addr, port)
			e.isPortReserved = false
			e.effectiveNetProtos = nil
			e.id.LocalPort = 0
			e.id.LocalAddress = ""
			e.boundNICID = 0
		}
	}()

	// If an address is specified, we must ensure that it's one of our
	// local addresses.
	if len(addr.Addr) != 0 {
		nic := e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nic == 0 {
			return tcpip.ErrBadLocalAddress
		}

		e.boundNICID = nic
		e.id.LocalAddress = addr.Addr
	}

	// Check the commit function.
	if commit != nil {
		if err := commit(); err != nil {
			// The defer takes care of unwind.
			return err
		}
	}

	// Mark endpoint as bound.
	e.state = stateBound

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return tcpip.FullAddress{
		Addr: e.id.LocalAddress,
		Port: e.id.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.state != stateConnected {
		return tcpip.FullAddress{}, tcpip.ErrNotConnected
	}

	return tcpip.FullAddress{
		Addr: e.id.RemoteAddress,
		Port: e.id.RemotePort,
		NIC:  e.boundNICID,
	}, nil
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	s := newSegment(r, id, vv)
	if !s.parse() {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		s.decRef()
		return
	}

	e.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	if (s.flags & flagRst) != 0 {
		e.stack.Stats().TCP.ResetsReceived.Increment()
	}

	// Send packet to worker goroutine.
	if e.segmentQueue.enqueue(s) {
		e.newSegmentWaker.Assert()
	} else {
		// The queue is full, so we drop the segment.
		e.stack.Stats().DroppedPackets.Increment()
		s.decRef()
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
	switch typ {
	case stack.ControlPacketTooBig:
		e.sndBufMu.Lock()
		e.packetTooBigCount++
		if v := int(extra); v < e.sndMTU {
			e.sndMTU = v
		}
		e.sndBufMu.Unlock()

		e.notifyProtocolGoroutine(notifyMTUChanged)
	}
}

// updateSndBufferUsage is called by the protocol goroutine when room opens up
// in the send buffer. The number of newly available bytes is v.
func (e *endpoint) updateSndBufferUsage(v int) {
	e.sndBufMu.Lock()
	notify := e.sndBufUsed >= e.sndBufSize>>1
	e.sndBufUsed -= v
	// We only notify when there is half the sndBufSize available after
	// a full buffer event occurs. This ensures that we don't wake up
	// writers to queue just 1-2 segments and go back to sleep.
	notify = notify && e.sndBufUsed < e.sndBufSize>>1
	e.sndBufMu.Unlock()

	if notify {
		e.waiterQueue.Notify(waiter.EventOut)
	}
}

// readyToRead is called by the protocol goroutine when a new segment is ready
// to be read, or when the connection is closed for receiving (in which case
// s will be nil).
func (e *endpoint) readyToRead(s *segment) {
	e.rcvListMu.Lock()
	if s != nil {
		s.incRef()
		e.rcvBufUsed += s.data.Size()
		e.rcvList.PushBack(s)
	} else {
		e.rcvClosed = true
	}
	e.rcvListMu.Unlock()

	e.waiterQueue.Notify(waiter.EventIn)
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer.
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	used := e.rcvBufUsed
	e.rcvListMu.Unlock()

	// We may use more bytes than the buffer size when the receive buffer
	// shrinks.
	if used >= size {
		return 0
	}

	return size - used
}

func (e *endpoint) receiveBufferSize() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	e.rcvListMu.Unlock()

	return size
}

// updateRecentTimestamp updates the recent timestamp using the algorithm
// described in https://tools.ietf.org/html/rfc7323#section-4.3
func (e *endpoint) updateRecentTimestamp(tsVal uint32, maxSentAck seqnum.Value, segSeq seqnum.Value) {
	if e.sendTSOk && seqnum.Value(e.recentTS).LessThan(seqnum.Value(tsVal)) && segSeq.LessThanEq(maxSentAck) {
		e.recentTS = tsVal
	}
}

// maybeEnableTimestamp marks the timestamp option enabled for this endpoint if
// the SYN options indicate that timestamp option was negotiated. It also
// initializes the recentTS with the value provided in synOpts.TSval.
func (e *endpoint) maybeEnableTimestamp(synOpts *header.TCPSynOptions) {
	if synOpts.TS {
		e.sendTSOk = true
		e.recentTS = synOpts.TSVal
	}
}

// timestamp returns the timestamp value to be used in the TSVal field of the
// timestamp option for outgoing TCP segments for a given endpoint.
func (e *endpoint) timestamp() uint32 {
	return tcpTimeStamp(e.tsOffset)
}

// tcpTimeStamp returns a timestamp offset by the provided offset. This is
// not inlined above as it's used when SYN cookies are in use and endpoint
// is not created at the time when the SYN cookie is sent.
func tcpTimeStamp(offset uint32) uint32 {
	now := time.Now()
	return uint32(now.Unix()*1000+int64(now.Nanosecond()/1e6)) + offset
}

// timeStampOffset returns a randomized timestamp offset to be used when sending
// timestamp values in a timestamp option for a TCP segment.
func timeStampOffset() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// Initialize a random tsOffset that will be added to the recentTS
	// everytime the timestamp is sent when the Timestamp option is enabled.
	//
	// See https://tools.ietf.org/html/rfc7323#section-5.4 for details on
	// why this is required.
	//
	// NOTE: This is not completely to spec as normally this should be
	// initialized in a manner analogous to how sequence numbers are
	// randomized per connection basis. But for now this is sufficient.
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// maybeEnableSACKPermitted marks the SACKPermitted option enabled for this endpoint
// if the SYN options indicate that the SACK option was negotiated and the TCP
// stack is configured to enable TCP SACK option.
func (e *endpoint) maybeEnableSACKPermitted(synOpts *header.TCPSynOptions) {
	var v SACKEnabled
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &v); err != nil {
		// Stack doesn't support SACK. So just return.
		return
	}
	if bool(v) && synOpts.SACKPermitted {
		e.sackPermitted = true
	}
}

// completeState makes a full copy of the endpoint and returns it. This is used
// before invoking the probe. The state returned may not be fully consistent if
// there are intervening syscalls when the state is being copied.
func (e *endpoint) completeState() stack.TCPEndpointState {
	var s stack.TCPEndpointState
	s.SegTime = time.Now()

	// Copy EndpointID.
	e.mu.Lock()
	s.ID = stack.TCPEndpointID(e.id)
	e.mu.Unlock()

	// Copy endpoint rcv state.
	e.rcvListMu.Lock()
	s.RcvBufSize = e.rcvBufSize
	s.RcvBufUsed = e.rcvBufUsed
	s.RcvClosed = e.rcvClosed
	e.rcvListMu.Unlock()

	// Endpoint TCP Option state.
	s.SendTSOk = e.sendTSOk
	s.RecentTS = e.recentTS
	s.TSOffset = e.tsOffset
	s.SACKPermitted = e.sackPermitted
	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])

	// Copy endpoint send state.
	e.sndBufMu.Lock()
	s.SndBufSize = e.sndBufSize
	s.SndBufUsed = e.sndBufUsed
	s.SndClosed = e.sndClosed
	s.SndBufInQueue = e.sndBufInQueue
	s.PacketTooBigCount = e.packetTooBigCount
	s.SndMTU = e.sndMTU
	e.sndBufMu.Unlock()

	// Copy receiver state.
	s.Receiver = stack.TCPReceiverState{
		RcvNxt:         e.rcv.rcvNxt,
		RcvAcc:         e.rcv.rcvAcc,
		RcvWndScale:    e.rcv.rcvWndScale,
		PendingBufUsed: e.rcv.pendingBufUsed,
		PendingBufSize: e.rcv.pendingBufSize,
	}

	// Copy sender state.
	s.Sender = stack.TCPSenderState{
		LastSendTime: e.snd.lastSendTime,
		DupAckCount:  e.snd.dupAckCount,
		FastRecovery: stack.TCPFastRecoveryState{
			Active:  e.snd.fr.active,
			First:   e.snd.fr.first,
			Last:    e.snd.fr.last,
			MaxCwnd: e.snd.fr.maxCwnd,
		},
		SndCwnd:          e.snd.sndCwnd,
		Ssthresh:         e.snd.sndSsthresh,
		SndCAAckCount:    e.snd.sndCAAckCount,
		Outstanding:      e.snd.outstanding,
		SndWnd:           e.snd.sndWnd,
		SndUna:           e.snd.sndUna,
		SndNxt:           e.snd.sndNxt,
		RTTMeasureSeqNum: e.snd.rttMeasureSeqNum,
		RTTMeasureTime:   e.snd.rttMeasureTime,
		Closed:           e.snd.closed,
		RTO:              e.snd.rto,
		SRTTInited:       e.snd.srttInited,
		MaxPayloadSize:   e.snd.maxPayloadSize,
		SndWndScale:      e.snd.sndWndScale,
		MaxSentAck:       e.snd.maxSentAck,
	}
	e.snd.rtt.Lock()
	s.Sender.SRTT = e.snd.rtt.srtt
	e.snd.rtt.Unlock()

	if cubic, ok := e.snd.cc.(*cubicState); ok {
		s.Sender.Cubic = stack.TCPCubicState{
			WMax:                    cubic.wMax,
			WLastMax:                cubic.wLastMax,
			T:                       cubic.t,
			TimeSinceLastCongestion: time.Since(cubic.t),
			C:                       cubic.c,
			K:                       cubic.k,
			Beta:                    cubic.beta,
			WC:                      cubic.wC,
			WEst:                    cubic.wEst,
		}
	}
	return s
}
