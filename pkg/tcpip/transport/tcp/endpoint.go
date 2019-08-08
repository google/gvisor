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

package tcp

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tmutex"
	"gvisor.dev/gvisor/pkg/waiter"
)

// EndpointState represents the state of a TCP endpoint.
type EndpointState uint32

// Endpoint states. Note that are represented in a netstack-specific manner and
// may not be meaningful externally. Specifically, they need to be translated to
// Linux's representation for these states if presented to userspace.
const (
	// Endpoint states internal to netstack. These map to the TCP state CLOSED.
	StateInitial EndpointState = iota
	StateBound
	StateConnecting // Connect() called, but the initial SYN hasn't been sent.
	StateError

	// TCP protocol states.
	StateEstablished
	StateSynSent
	StateSynRecv
	StateFinWait1
	StateFinWait2
	StateTimeWait
	StateClose
	StateCloseWait
	StateLastAck
	StateListen
	StateClosing
)

// connected is the set of states where an endpoint is connected to a peer.
func (s EndpointState) connected() bool {
	switch s {
	case StateEstablished, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.String.
func (s EndpointState) String() string {
	switch s {
	case StateInitial:
		return "INITIAL"
	case StateBound:
		return "BOUND"
	case StateConnecting:
		return "CONNECTING"
	case StateError:
		return "ERROR"
	case StateEstablished:
		return "ESTABLISHED"
	case StateSynSent:
		return "SYN-SENT"
	case StateSynRecv:
		return "SYN-RCVD"
	case StateFinWait1:
		return "FIN-WAIT1"
	case StateFinWait2:
		return "FIN-WAIT2"
	case StateTimeWait:
		return "TIME-WAIT"
	case StateClose:
		return "CLOSED"
	case StateCloseWait:
		return "CLOSE-WAIT"
	case StateLastAck:
		return "LAST-ACK"
	case StateListen:
		return "LISTEN"
	case StateClosing:
		return "CLOSING"
	default:
		panic("unreachable")
	}
}

// Reasons for notifying the protocol goroutine.
const (
	notifyNonZeroReceiveWindow = 1 << iota
	notifyReceiveWindowChanged
	notifyClose
	notifyMTUChanged
	notifyDrain
	notifyReset
	notifyKeepaliveChanged
	notifyMSSChanged
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

// rcvBufAutoTuneParams are used to hold state variables to compute
// the auto tuned recv buffer size.
//
// +stateify savable
type rcvBufAutoTuneParams struct {
	// measureTime is the time at which the current measurement
	// was started.
	measureTime time.Time `state:".(unixTime)"`

	// copied is the number of bytes copied out of the receive
	// buffers since this measure began.
	copied int

	// prevCopied is the number of bytes copied out of the receive
	// buffers in the previous RTT period.
	prevCopied int

	// rtt is the non-smoothed minimum RTT as measured by observing the time
	// between when a byte is first acknowledged and the receipt of data
	// that is at least one window beyond the sequence number that was
	// acknowledged.
	rtt time.Duration

	// rttMeasureSeqNumber is the highest acceptable sequence number at the
	// time this RTT measurement period began.
	rttMeasureSeqNumber seqnum.Value

	// rttMeasureTime is the absolute time at which the current rtt
	// measurement period began.
	rttMeasureTime time.Time `state:".(unixTime)"`

	// disabled is true if an explicit receive buffer is set for the
	// endpoint.
	disabled bool
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
	rcvListMu     sync.Mutex  `state:"nosave"`
	rcvList       segmentList `state:"wait"`
	rcvClosed     bool
	rcvBufSize    int
	rcvBufUsed    int
	rcvAutoParams rcvBufAutoTuneParams
	// zeroWindow indicates that the window was closed due to receive buffer
	// space being filled up. This is set by the worker goroutine before
	// moving a segment to the rcvList. This setting is cleared by the
	// endpoint when a Read() call reads enough data for the new window to
	// be non-zero.
	zeroWindow bool

	// The following fields are protected by the mutex.
	mu sync.RWMutex `state:"nosave"`
	id stack.TransportEndpointID

	state EndpointState `state:".(EndpointState)"`

	isPortReserved    bool `state:"manual"`
	isRegistered      bool
	boundNICID        tcpip.NICID `state:"manual"`
	route             stack.Route `state:"manual"`
	v6only            bool
	isConnectNotified bool
	// TCP should never broadcast but Linux nevertheless supports enabling/
	// disabling SO_BROADCAST, albeit as a NOOP.
	broadcast bool

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

	// reusePort is set to true if SO_REUSEPORT is enabled.
	reusePort bool

	// delay enables Nagle's algorithm.
	//
	// delay is a boolean (0 is false) and must be accessed atomically.
	delay uint32

	// cork holds back segments until full.
	//
	// cork is a boolean (0 is false) and must be accessed atomically.
	cork uint32

	// scoreboard holds TCP SACK Scoreboard information for this endpoint.
	scoreboard *SACKScoreboard

	// The options below aren't implemented, but we remember the user
	// settings because applications expect to be able to set/query these
	// options.
	reuseAddr bool

	// slowAck holds the negated state of quick ack. It is stubbed out and
	// does nothing.
	//
	// slowAck is a boolean (0 is false) and must be accessed atomically.
	slowAck uint32

	// segmentQueue is used to hand received segments to the protocol
	// goroutine. Segments are queued as long as the queue is not full,
	// and dropped when it is.
	segmentQueue segmentQueue `state:"wait"`

	// synRcvdCount is the number of connections for this endpoint that are
	// in SYN-RCVD state.
	synRcvdCount int

	// userMSS if non-zero is the MSS value explicitly set by the user
	// for this endpoint using the TCP_MAXSEG setsockopt.
	userMSS int

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
	cc tcpip.CongestionControlOption

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

	// pendingAccepted is a synchronization primitive used to track number
	// of connections that are queued up to be delivered to the accepted
	// channel. We use this to ensure that all goroutines blocked on writing
	// to the acceptedChan below terminate before we close acceptedChan.
	pendingAccepted sync.WaitGroup `state:"nosave"`

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

	// The goroutine undrain notification channel. This is currently used as
	// a way to block the worker goroutines. Today nothing closes/writes
	// this channel and this causes any goroutines waiting on this to just
	// block. This is used during save/restore to prevent worker goroutines
	// from mutating state as it's being saved.
	undrain chan struct{} `state:"nosave"`

	// probe if not nil is invoked on every received segment. It is passed
	// a copy of the current state of the endpoint.
	probe stack.TCPProbeFunc `state:"nosave"`

	// The following are only used to assist the restore run to re-connect.
	bindAddress       tcpip.Address
	connectingAddress tcpip.Address

	// amss is the advertised MSS to the peer by this endpoint.
	amss uint16

	gso *stack.GSO
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
		state:       StateInitial,
		rcvBufSize:  DefaultReceiveBufferSize,
		sndBufSize:  DefaultSendBufferSize,
		sndMTU:      int(math.MaxInt32),
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

	var cs tcpip.CongestionControlOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	var mrb tcpip.ModerateReceiveBufferOption
	if err := stack.TransportProtocolOption(ProtocolNumber, &mrb); err == nil {
		e.rcvAutoParams.disabled = !bool(mrb)
	}

	if p := stack.GetTCPProbe(); p != nil {
		e.probe = p
	}

	e.segmentQueue.setLimit(MaxUnprocessedSegments)
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
	case StateInitial, StateBound, StateConnecting, StateSynSent, StateSynRecv:
		// Ready for nothing.

	case StateClose, StateError:
		// Ready for anything.
		result = mask

	case StateListen:
		// Check if there's anything in the accepted channel.
		if (mask & waiter.EventIn) != 0 {
			if len(e.acceptedChan) > 0 {
				result |= waiter.EventIn
			}
		}
	}
	if e.state.connected() {
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

	// For listening sockets, we always release ports inline so that they
	// are immediately available for reuse after Close() is called. If also
	// registered, we unregister as well otherwise the next user would fail
	// in Listen() when trying to register.
	if e.state == StateListen && e.isPortReserved {
		if e.isRegistered {
			e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e)
			e.isRegistered = false
		}

		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
		e.isPortReserved = false
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

// closePendingAcceptableConnections closes all connections that have completed
// handshake but not yet been delivered to the application.
func (e *endpoint) closePendingAcceptableConnectionsLocked() {
	done := make(chan struct{})
	// Spin a goroutine up as ranging on e.acceptedChan will just block when
	// there are no more connections in the channel. Using a non-blocking
	// select does not work as it can potentially select the default case
	// even when there are pending writes but that are not yet written to
	// the channel.
	go func() {
		defer close(done)
		for n := range e.acceptedChan {
			n.mu.Lock()
			n.resetConnectionLocked(tcpip.ErrConnectionAborted)
			n.mu.Unlock()
			n.Close()
		}
	}()
	// pendingAccepted(see endpoint.deliverAccepted) tracks the number of
	// endpoints which have completed handshake but are not yet written to
	// the e.acceptedChan. We wait here till the goroutine above can drain
	// all such connections from e.acceptedChan.
	e.pendingAccepted.Wait()
	close(e.acceptedChan)
	<-done
	e.acceptedChan = nil
}

// cleanupLocked frees all resources associated with the endpoint. It is called
// after Close() is called and the worker goroutine (if any) is done with its
// work.
func (e *endpoint) cleanupLocked() {
	// Close all endpoints that might have been accepted by TCP but not by
	// the client.
	if e.acceptedChan != nil {
		e.closePendingAcceptableConnectionsLocked()
	}
	e.workerCleanup = false

	if e.isRegistered {
		e.stack.UnregisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e)
		e.isRegistered = false
	}

	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.id.LocalAddress, e.id.LocalPort)
		e.isPortReserved = false
	}

	e.route.Release()
	tcpip.DeleteDanglingEndpoint(e)
}

// initialReceiveWindow returns the initial receive window to advertise in the
// SYN/SYN-ACK.
func (e *endpoint) initialReceiveWindow() int {
	rcvWnd := e.receiveBufferAvailable()
	if rcvWnd > math.MaxUint16 {
		rcvWnd = math.MaxUint16
	}
	routeWnd := InitialCwnd * int(mssForRoute(&e.route)) * 2
	if rcvWnd > routeWnd {
		rcvWnd = routeWnd
	}
	return rcvWnd
}

// ModerateRecvBuf adjusts the receive buffer and the advertised window
// based on the number of bytes copied to user space.
func (e *endpoint) ModerateRecvBuf(copied int) {
	e.rcvListMu.Lock()
	if e.rcvAutoParams.disabled {
		e.rcvListMu.Unlock()
		return
	}
	now := time.Now()
	if rtt := e.rcvAutoParams.rtt; rtt == 0 || now.Sub(e.rcvAutoParams.measureTime) < rtt {
		e.rcvAutoParams.copied += copied
		e.rcvListMu.Unlock()
		return
	}
	prevRTTCopied := e.rcvAutoParams.copied + copied
	prevCopied := e.rcvAutoParams.prevCopied
	rcvWnd := 0
	if prevRTTCopied > prevCopied {
		// The minimal receive window based on what was copied by the app
		// in the immediate preceding RTT and some extra buffer for 16
		// segments to account for variations.
		// We multiply by 2 to account for packet losses.
		rcvWnd = prevRTTCopied*2 + 16*int(e.amss)

		// Scale for slow start based on bytes copied in this RTT vs previous.
		grow := (rcvWnd * (prevRTTCopied - prevCopied)) / prevCopied

		// Multiply growth factor by 2 again to account for sender being
		// in slow-start where the sender grows it's congestion window
		// by 100% per RTT.
		rcvWnd += grow * 2

		// Make sure auto tuned buffer size can always receive upto 2x
		// the initial window of 10 segments.
		if minRcvWnd := int(e.amss) * InitialCwnd * 2; rcvWnd < minRcvWnd {
			rcvWnd = minRcvWnd
		}

		// Cap the auto tuned buffer size by the maximum permissible
		// receive buffer size.
		if max := e.maxReceiveBufferSize(); rcvWnd > max {
			rcvWnd = max
		}

		// We do not adjust downwards as that can cause the receiver to
		// reject valid data that might already be in flight as the
		// acceptable window will shrink.
		if rcvWnd > e.rcvBufSize {
			e.rcvBufSize = rcvWnd
			e.notifyProtocolGoroutine(notifyReceiveWindowChanged)
		}

		// We only update prevCopied when we grow the buffer because in cases
		// where prevCopied > prevRTTCopied the existing buffer is already big
		// enough to handle the current rate and we don't need to do any
		// adjustments.
		e.rcvAutoParams.prevCopied = prevRTTCopied
	}
	e.rcvAutoParams.measureTime = now
	e.rcvAutoParams.copied = 0
	e.rcvListMu.Unlock()
}

// IPTables implements tcpip.Endpoint.IPTables.
func (e *endpoint) IPTables() (iptables.IPTables, error) {
	return e.stack.IPTables(), nil
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.stack = s
	e.segmentQueue.setLimit(MaxUnprocessedSegments)
	e.workMu.Init()

	state := e.state
	switch state {
	case StateInitial, StateBound, StateListen, StateConnecting, StateEstablished:
		var ss SendBufferSizeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
			if e.sndBufSize < ss.Min || e.sndBufSize > ss.Max {
				panic(fmt.Sprintf("endpoint.sndBufSize %d is outside the min and max allowed [%d, %d]", e.sndBufSize, ss.Min, ss.Max))
			}
			if e.rcvBufSize < ss.Min || e.rcvBufSize > ss.Max {
				panic(fmt.Sprintf("endpoint.rcvBufSize %d is outside the min and max allowed [%d, %d]", e.rcvBufSize, ss.Min, ss.Max))
			}
		}
	}

	bind := func() {
		e.state = StateInitial
		if len(e.bindAddress) == 0 {
			e.bindAddress = e.id.LocalAddress
		}
		if err := e.Bind(tcpip.FullAddress{Addr: e.bindAddress, Port: e.id.LocalPort}); err != nil {
			panic("endpoint binding failed: " + err.String())
		}
	}

	switch state {
	case StateEstablished, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		bind()
		if len(e.connectingAddress) == 0 {
			e.connectingAddress = e.id.RemoteAddress
			// This endpoint is accepted by netstack but not yet by
			// the app. If the endpoint is IPv6 but the remote
			// address is IPv4, we need to connect as IPv6 so that
			// dual-stack mode can be properly activated.
			if e.netProto == header.IPv6ProtocolNumber && len(e.id.RemoteAddress) != header.IPv6AddressSize {
				e.connectingAddress = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + e.id.RemoteAddress
			}
		}
		// Reset the scoreboard to reinitialize the sack information as
		// we do not restore SACK information.
		e.scoreboard.Reset()
		if err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.id.RemotePort}, false, e.workerRunning); err != tcpip.ErrConnectStarted {
			panic("endpoint connecting failed: " + err.String())
		}
		connectedLoading.Done()
	case StateListen:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			bind()
			backlog := cap(e.acceptedChan)
			if err := e.Listen(backlog); err != nil {
				panic("endpoint listening failed: " + err.String())
			}
			listenLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case StateConnecting, StateSynSent, StateSynRecv:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			bind()
			if err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.id.RemotePort}); err != tcpip.ErrConnectStarted {
				panic("endpoint connecting failed: " + err.String())
			}
			connectingLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case StateBound:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			connectingLoading.Wait()
			bind()
			tcpip.AsyncLoading.Done()
		}()
	case StateClose:
		if e.isPortReserved {
			tcpip.AsyncLoading.Add(1)
			go func() {
				connectedLoading.Wait()
				listenLoading.Wait()
				connectingLoading.Wait()
				bind()
				e.state = StateClose
				tcpip.AsyncLoading.Done()
			}()
		}
		fallthrough
	case StateError:
		tcpip.DeleteDanglingEndpoint(e)
	}
}

// Read reads data from the endpoint.
func (e *endpoint) Read(*tcpip.FullAddress) (buffer.View, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()
	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data. Also note that a RST being received
	// would cause the state to become StateError so we should allow the
	// reads to proceed before returning a ECONNRESET.
	e.rcvListMu.Lock()
	bufUsed := e.rcvBufUsed
	if s := e.state; !s.connected() && s != StateClose && bufUsed == 0 {
		e.rcvListMu.Unlock()
		he := e.hardError
		e.mu.RUnlock()
		if s == StateError {
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
		if e.rcvClosed || !e.state.connected() {
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

	e.rcvBufUsed -= len(v)
	// If the window was zero before this read and if the read freed up
	// enough buffer space for the scaled window to be non-zero then notify
	// the protocol goroutine to send a window update.
	if e.zeroWindow && !e.zeroReceiveWindow(e.rcv.rcvWndScale) {
		e.zeroWindow = false
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
	if !e.state.connected() {
		switch e.state {
		case StateError:
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
	return uintptr(l), nil, nil
}

// Peek reads data without consuming it from the endpoint.
//
// This method does not block if there is no data pending.
func (e *endpoint) Peek(vec [][]byte) (uintptr, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data.
	if s := e.state; !s.connected() && s != StateClose {
		if s == StateError {
			return 0, tcpip.ControlMessages{}, e.hardError
		}
		return 0, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed || !e.state.connected() {
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
	case tcpip.DelayOption:
		if v == 0 {
			atomic.StoreUint32(&e.delay, 0)

			// Handle delayed data.
			e.sndWaker.Assert()
		} else {
			atomic.StoreUint32(&e.delay, 1)
		}
		return nil

	case tcpip.CorkOption:
		if v == 0 {
			atomic.StoreUint32(&e.cork, 0)

			// Handle the corked data.
			e.sndWaker.Assert()
		} else {
			atomic.StoreUint32(&e.cork, 1)
		}
		return nil

	case tcpip.ReuseAddressOption:
		e.mu.Lock()
		e.reuseAddr = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.ReusePortOption:
		e.mu.Lock()
		e.reusePort = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.QuickAckOption:
		if v == 0 {
			atomic.StoreUint32(&e.slowAck, 1)
		} else {
			atomic.StoreUint32(&e.slowAck, 0)
		}
		return nil

	case tcpip.MaxSegOption:
		userMSS := v
		if userMSS < header.TCPMinimumMSS || userMSS > header.TCPMaximumMSS {
			return tcpip.ErrInvalidOptionValue
		}
		e.mu.Lock()
		e.userMSS = int(userMSS)
		e.mu.Unlock()
		e.notifyProtocolGoroutine(notifyMSSChanged)
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

		e.rcvBufSize = size
		e.rcvAutoParams.disabled = true
		if e.zeroWindow && !e.zeroReceiveWindow(scale) {
			e.zeroWindow = false
			mask |= notifyNonZeroReceiveWindow
		}
		e.rcvListMu.Unlock()

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
		if e.state != StateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v != 0
		return nil

	case tcpip.KeepaliveEnabledOption:
		e.keepalive.Lock()
		e.keepalive.enabled = v != 0
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)
		return nil

	case tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)
		return nil

	case tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)
		return nil

	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		e.keepalive.count = int(v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)
		return nil

	case tcpip.BroadcastOption:
		e.mu.Lock()
		e.broadcast = v != 0
		e.mu.Unlock()
		return nil

	case tcpip.CongestionControlOption:
		// Query the available cc algorithms in the stack and
		// validate that the specified algorithm is actually
		// supported in the stack.
		var avail tcpip.AvailableCongestionControlOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &avail); err != nil {
			return err
		}
		availCC := strings.Split(string(avail), " ")
		for _, cc := range availCC {
			if v == tcpip.CongestionControlOption(cc) {
				// Acquire the work mutex as we may need to
				// reinitialize the congestion control state.
				e.mu.Lock()
				state := e.state
				e.cc = v
				e.mu.Unlock()
				switch state {
				case StateEstablished:
					e.workMu.Lock()
					e.mu.Lock()
					if e.state == state {
						e.snd.cc = e.snd.initCongestionControl(e.cc)
					}
					e.mu.Unlock()
					e.workMu.Unlock()
				}
				return nil
			}
		}

		// Linux returns ENOENT when an invalid congestion
		// control algorithm is specified.
		return tcpip.ErrNoSuchFile
	default:
		return nil
	}
}

// readyReceiveSize returns the number of bytes ready to be received.
func (e *endpoint) readyReceiveSize() (int, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint cannot be in listen state.
	if e.state == StateListen {
		return 0, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	return e.rcvBufUsed, nil
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOpt) (int, *tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		return e.readyReceiveSize()
	}
	return -1, tcpip.ErrUnknownProtocolOption
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

	case *tcpip.MaxSegOption:
		// This is just stubbed out. Linux never returns the user_mss
		// value as it either returns the defaultMSS or returns the
		// actual current MSS. Netstack just returns the defaultMSS
		// always for now.
		*o = header.TCPDefaultMSS
		return nil

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

	case *tcpip.DelayOption:
		*o = 0
		if v := atomic.LoadUint32(&e.delay); v != 0 {
			*o = 1
		}
		return nil

	case *tcpip.CorkOption:
		*o = 0
		if v := atomic.LoadUint32(&e.cork); v != 0 {
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

	case *tcpip.ReusePortOption:
		e.mu.RLock()
		v := e.reusePort
		e.mu.RUnlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.QuickAckOption:
		*o = 1
		if v := atomic.LoadUint32(&e.slowAck); v != 0 {
			*o = 0
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
		return nil

	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIdleOption(e.keepalive.idle)
		e.keepalive.Unlock()
		return nil

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIntervalOption(e.keepalive.interval)
		e.keepalive.Unlock()
		return nil

	case *tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveCountOption(e.keepalive.count)
		e.keepalive.Unlock()
		return nil

	case *tcpip.OutOfBandInlineOption:
		// We don't currently support disabling this option.
		*o = 1
		return nil

	case *tcpip.BroadcastOption:
		e.mu.Lock()
		v := e.broadcast
		e.mu.Unlock()

		*o = 0
		if v {
			*o = 1
		}
		return nil

	case *tcpip.CongestionControlOption:
		e.mu.Lock()
		*o = e.cc
		e.mu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
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
	if addr.Addr == "" && addr.Port == 0 {
		// AF_UNSPEC isn't supported.
		return tcpip.ErrAddressFamilyNotSupported
	}

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

	if e.state.connected() {
		// The endpoint is already connected. If caller hasn't been
		// notified yet, return success.
		if !e.isConnectNotified {
			e.isConnectNotified = true
			return nil
		}
		// Otherwise return that it's already connected.
		return tcpip.ErrAlreadyConnected
	}

	nicid := addr.NIC
	switch e.state {
	case StateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicid != 0 && nicid != e.boundNICID {
			return tcpip.ErrNoRoute
		}

		nicid = e.boundNICID

	case StateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID (if any)
		// when we find a route.

	case StateConnecting, StateSynSent, StateSynRecv:
		// A connection request has already been issued but hasn't completed
		// yet.
		return tcpip.ErrAlreadyConnecting

	case StateError:
		return e.hardError

	default:
		return tcpip.ErrInvalidEndpointState
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto, false /* multicastLoop */)
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
		err := e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, e.id, e, e.reusePort)
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
			if !e.stack.IsPortAvailable(netProtos, ProtocolNumber, e.id.LocalAddress, p, false) {
				return false, nil
			}

			id := e.id
			id.LocalPort = p
			switch e.stack.RegisterTransportEndpoint(nicid, netProtos, ProtocolNumber, id, e, e.reusePort) {
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
	e.state = StateConnecting
	e.route = r.Clone()
	e.boundNICID = nicid
	e.effectiveNetProtos = netProtos
	e.connectingAddress = connectingAddr

	e.initGSO()

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
		e.state = StateEstablished
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

	switch {
	case e.state.connected():
		// Close for read.
		if (e.shutdownFlags & tcpip.ShutdownRead) != 0 {
			// Mark read side as closed.
			e.rcvListMu.Lock()
			e.rcvClosed = true
			rcvBufUsed := e.rcvBufUsed
			e.rcvListMu.Unlock()

			// If we're fully closed and we have unread data we need to abort
			// the connection with a RST.
			if (e.shutdownFlags&tcpip.ShutdownWrite) != 0 && rcvBufUsed > 0 {
				e.notifyProtocolGoroutine(notifyReset)
				return nil
			}
		}

		// Close for write.
		if (e.shutdownFlags & tcpip.ShutdownWrite) != 0 {
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

	case e.state == StateListen:
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
	if e.state == StateListen && !e.workerCleanup {
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
	if e.state != StateBound {
		return tcpip.ErrInvalidEndpointState
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.id, e, e.reusePort); err != nil {
		return err
	}

	e.isRegistered = true
	e.state = StateListen
	if e.acceptedChan == nil {
		e.acceptedChan = make(chan *endpoint, backlog)
	}
	e.workerRunning = true

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
	if e.state != StateListen {
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
	e.stack.Stats().TCP.PassiveConnectionOpenings.Increment()

	return n, wq, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
func (e *endpoint) Bind(addr tcpip.FullAddress) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.state != StateInitial {
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

	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port, e.reusePort)
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

	// Mark endpoint as bound.
	e.state = StateBound

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

	if !e.state.connected() {
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

	if !s.csumValid {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	e.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
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
		// Check if the receive window is now closed. If so make sure
		// we set the zero window before we deliver the segment to ensure
		// that a subsequent read of the segment will correctly trigger
		// a non-zero notification.
		if avail := e.receiveBufferAvailableLocked(); avail>>e.rcv.rcvWndScale == 0 {
			e.zeroWindow = true
		}
		e.rcvList.PushBack(s)
	} else {
		e.rcvClosed = true
	}
	e.rcvListMu.Unlock()

	e.waiterQueue.Notify(waiter.EventIn)
}

// receiveBufferAvailableLocked calculates how many bytes are still available
// in the receive buffer.
// rcvListMu must be held when this function is called.
func (e *endpoint) receiveBufferAvailableLocked() int {
	// We may use more bytes than the buffer size when the receive buffer
	// shrinks.
	if e.rcvBufUsed >= e.rcvBufSize {
		return 0
	}

	return e.rcvBufSize - e.rcvBufUsed
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer.
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvListMu.Lock()
	available := e.receiveBufferAvailableLocked()
	e.rcvListMu.Unlock()
	return available
}

func (e *endpoint) receiveBufferSize() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	e.rcvListMu.Unlock()

	return size
}

func (e *endpoint) maxReceiveBufferSize() int {
	var rs ReceiveBufferSizeOption
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err != nil {
		// As a fallback return the hardcoded max buffer size.
		return MaxBufferSize
	}
	return rs.Max
}

// rcvWndScaleForHandshake computes the receive window scale to offer to the
// peer when window scaling is enabled (true by default). If auto-tuning is
// disabled then the window scaling factor is based on the size of the
// receiveBuffer otherwise we use the max permissible receive buffer size to
// compute the scale.
func (e *endpoint) rcvWndScaleForHandshake() int {
	bufSizeForScale := e.receiveBufferSize()

	e.rcvListMu.Lock()
	autoTuningDisabled := e.rcvAutoParams.disabled
	e.rcvListMu.Unlock()
	if autoTuningDisabled {
		return FindWndScale(seqnum.Size(bufSizeForScale))
	}

	return FindWndScale(seqnum.Size(e.maxReceiveBufferSize()))
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

// maxOptionSize return the maximum size of TCP options.
func (e *endpoint) maxOptionSize() (size int) {
	var maxSackBlocks [header.TCPMaxSACKBlocks]header.SACKBlock
	options := e.makeOptions(maxSackBlocks[:])
	size = len(options)
	putOptions(options)

	return size
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
	s.RcvAutoParams.MeasureTime = e.rcvAutoParams.measureTime
	s.RcvAutoParams.CopiedBytes = e.rcvAutoParams.copied
	s.RcvAutoParams.PrevCopiedBytes = e.rcvAutoParams.prevCopied
	s.RcvAutoParams.RTT = e.rcvAutoParams.rtt
	s.RcvAutoParams.RTTMeasureSeqNumber = e.rcvAutoParams.rttMeasureSeqNumber
	s.RcvAutoParams.RTTMeasureTime = e.rcvAutoParams.rttMeasureTime
	s.RcvAutoParams.Disabled = e.rcvAutoParams.disabled
	e.rcvListMu.Unlock()

	// Endpoint TCP Option state.
	s.SendTSOk = e.sendTSOk
	s.RecentTS = e.recentTS
	s.TSOffset = e.tsOffset
	s.SACKPermitted = e.sackPermitted
	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])
	s.SACK.ReceivedBlocks, s.SACK.MaxSACKED = e.scoreboard.Copy()

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
			Active:    e.snd.fr.active,
			First:     e.snd.fr.first,
			Last:      e.snd.fr.last,
			MaxCwnd:   e.snd.fr.maxCwnd,
			HighRxt:   e.snd.fr.highRxt,
			RescueRxt: e.snd.fr.rescueRxt,
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
		MaxPayloadSize:   e.snd.maxPayloadSize,
		SndWndScale:      e.snd.sndWndScale,
		MaxSentAck:       e.snd.maxSentAck,
	}
	e.snd.rtt.Lock()
	s.Sender.SRTT = e.snd.rtt.srtt
	s.Sender.SRTTInited = e.snd.rtt.srttInited
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

func (e *endpoint) initGSO() {
	if e.route.Capabilities()&stack.CapabilityGSO == 0 {
		return
	}

	gso := &stack.GSO{}
	switch e.route.NetProto {
	case header.IPv4ProtocolNumber:
		gso.Type = stack.GSOTCPv4
		gso.L3HdrLen = header.IPv4MinimumSize
	case header.IPv6ProtocolNumber:
		gso.Type = stack.GSOTCPv6
		gso.L3HdrLen = header.IPv6MinimumSize
	default:
		panic(fmt.Sprintf("Unknown netProto: %v", e.netProto))
	}
	gso.NeedsCsum = true
	gso.CsumOffset = header.TCPChecksumOffset
	gso.MaxSize = e.route.GSOMaxSize()
	e.gso = gso
}

// State implements tcpip.Endpoint.State. It exports the endpoint's protocol
// state for diagnostics.
func (e *endpoint) State() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint32(e.state)
}

func mssForRoute(r *stack.Route) uint16 {
	return uint16(r.MTU() - header.TCPMinimumSize)
}
