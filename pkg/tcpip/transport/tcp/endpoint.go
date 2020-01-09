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
	"encoding/binary"
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
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/iptables"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
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
	// notifyTickleWorker is used to tickle the protocol main loop during a
	// restore after we update the endpoint state to the correct one. This
	// ensures the loop terminates if the final state of the endpoint is
	// say TIME_WAIT.
	notifyTickleWorker
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

// ReceiveErrors collect segment receive errors within transport layer.
type ReceiveErrors struct {
	tcpip.ReceiveErrors

	// SegmentQueueDropped is the number of segments dropped due to
	// a full segment queue.
	SegmentQueueDropped tcpip.StatCounter

	// ChecksumErrors is the number of segments dropped due to bad checksums.
	ChecksumErrors tcpip.StatCounter

	// ListenOverflowSynDrop is the number of times the listen queue overflowed
	// and a SYN was dropped.
	ListenOverflowSynDrop tcpip.StatCounter

	// ListenOverflowAckDrop is the number of times the final ACK
	// in the handshake was dropped due to overflow.
	ListenOverflowAckDrop tcpip.StatCounter

	// ZeroRcvWindowState is the number of times we advertised
	// a zero receive window when rcvList is full.
	ZeroRcvWindowState tcpip.StatCounter
}

// SendErrors collect segment send errors within the transport layer.
type SendErrors struct {
	tcpip.SendErrors

	// SegmentSendToNetworkFailed is the number of TCP segments failed to be sent
	// to the network endpoint.
	SegmentSendToNetworkFailed tcpip.StatCounter

	// SynSendToNetworkFailed is the number of TCP SYNs failed to be sent
	// to the network endpoint.
	SynSendToNetworkFailed tcpip.StatCounter

	// Retransmits is the number of TCP segments retransmitted.
	Retransmits tcpip.StatCounter

	// FastRetransmit is the number of segments retransmitted in fast
	// recovery.
	FastRetransmit tcpip.StatCounter

	// Timeouts is the number of times the RTO expired.
	Timeouts tcpip.StatCounter
}

// Stats holds statistics about the endpoint.
type Stats struct {
	// SegmentsReceived is the number of TCP segments received that
	// the transport layer successfully parsed.
	SegmentsReceived tcpip.StatCounter

	// SegmentsSent is the number of TCP segments sent.
	SegmentsSent tcpip.StatCounter

	// FailedConnectionAttempts is the number of times we saw Connect and
	// Accept errors.
	FailedConnectionAttempts tcpip.StatCounter

	// ReceiveErrors collects segment receive errors within the
	// transport layer.
	ReceiveErrors ReceiveErrors

	// ReadErrors collects segment read errors from an endpoint read call.
	ReadErrors tcpip.ReadErrors

	// SendErrors collects segment send errors within the transport layer.
	SendErrors SendErrors

	// WriteErrors collects segment write errors from an endpoint write call.
	WriteErrors tcpip.WriteErrors
}

// IsEndpointStats is an empty method to implement the tcpip.EndpointStats
// marker interface.
func (*Stats) IsEndpointStats() {}

// EndpointInfo holds useful information about a transport endpoint which
// can be queried by monitoring tools.
//
// +stateify savable
type EndpointInfo struct {
	stack.TransportEndpointInfo

	// HardError is meaningful only when state is stateError. It stores the
	// error to be returned when read/write syscalls are called and the
	// endpoint is in this state. HardError is protected by endpoint mu.
	HardError *tcpip.Error `state:".(string)"`
}

// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
// marker interface.
func (*EndpointInfo) IsEndpointInfo() {}

// endpoint represents a TCP endpoint. This struct serves as the interface
// between users of the endpoint and the protocol implementation; it is legal to
// have concurrent goroutines make calls into the endpoint, they are properly
// synchronized. The protocol implementation, however, runs in a single
// goroutine.
//
// +stateify savable
type endpoint struct {
	EndpointInfo

	// workMu is used to arbitrate which goroutine may perform protocol
	// work. Only the main protocol goroutine is expected to call Lock() on
	// it, but other goroutines (e.g., send) may call TryLock() to eagerly
	// perform work without having to wait for the main one to wake up.
	workMu tmutex.Mutex `state:"nosave"`

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack  `state:"manual"`
	waiterQueue *waiter.Queue `state:"wait"`
	uniqueID    uint64

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

	state EndpointState `state:".(EndpointState)"`

	// origEndpointState is only used during a restore phase to save the
	// endpoint state at restore time as the socket is moved to it's correct
	// state.
	origEndpointState EndpointState `state:"nosave"`

	isPortReserved    bool `state:"manual"`
	isRegistered      bool
	boundNICID        tcpip.NICID `state:"manual"`
	route             stack.Route `state:"manual"`
	ttl               uint8
	v6only            bool
	isConnectNotified bool
	// TCP should never broadcast but Linux nevertheless supports enabling/
	// disabling SO_BROADCAST, albeit as a NOOP.
	broadcast bool

	// Values used to reserve a port or register a transport endpoint
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber `state:"manual"`

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

	// bindToDevice is set to the NIC on which to bind or disabled if 0.
	bindToDevice tcpip.NICID

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
	userMSS uint16

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

	// userTimeout if non-zero specifies a user specified timeout for
	// a connection w/ pending data to send. A connection that has pending
	// unacked data will be forcibily aborted if the timeout is reached
	// without any data being acked.
	userTimeout time.Duration

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
	connectingAddress tcpip.Address

	// amss is the advertised MSS to the peer by this endpoint.
	amss uint16

	// sendTOS represents IPv4 TOS or IPv6 TrafficClass,
	// applied while sending packets. Defaults to 0 as on Linux.
	sendTOS uint8

	gso *stack.GSO

	// TODO(b/142022063): Add ability to save and restore per endpoint stats.
	stats Stats `state:"nosave"`

	// tcpLingerTimeout is the maximum amount of a time a socket
	// a socket stays in TIME_WAIT state before being marked
	// closed.
	tcpLingerTimeout time.Duration

	// closed indicates that the user has called closed on the
	// endpoint and at this point the endpoint is only around
	// to complete the TCP shutdown.
	closed bool
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

// calculateAdvertisedMSS calculates the MSS to advertise.
//
// If userMSS is non-zero and is not greater than the maximum possible MSS for
// r, it will be used; otherwise, the maximum possible MSS will be used.
func calculateAdvertisedMSS(userMSS uint16, r stack.Route) uint16 {
	// The maximum possible MSS is dependent on the route.
	maxMSS := mssForRoute(&r)

	if userMSS != 0 && userMSS < maxMSS {
		return userMSS
	}

	return maxMSS
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

func newEndpoint(s *stack.Stack, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack: s,
		EndpointInfo: EndpointInfo{
			TransportEndpointInfo: stack.TransportEndpointInfo{
				NetProto:   netProto,
				TransProto: header.TCPProtocolNumber,
			},
		},
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
		uniqueID: s.UniqueID(),
	}

	var ss SendBufferSizeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.sndBufSize = ss.Default
	}

	var rs ReceiveBufferSizeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.rcvBufSize = rs.Default
	}

	var cs tcpip.CongestionControlOption
	if err := s.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	var mrb tcpip.ModerateReceiveBufferOption
	if err := s.TransportProtocolOption(ProtocolNumber, &mrb); err == nil {
		e.rcvAutoParams.disabled = !bool(mrb)
	}

	var de DelayEnabled
	if err := s.TransportProtocolOption(ProtocolNumber, &de); err == nil && de {
		e.SetSockOptInt(tcpip.DelayOption, 1)
	}

	var tcpLT tcpip.TCPLingerTimeoutOption
	if err := s.TransportProtocolOption(ProtocolNumber, &tcpLT); err == nil {
		e.tcpLingerTimeout = time.Duration(tcpLT)
	}

	if p := s.GetTCPProbe(); p != nil {
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
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return
	}

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
			e.stack.StartTransportEndpointCleanup(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundBindToDevice)
			e.isRegistered = false
		}

		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.boundPortFlags, e.boundBindToDevice)
		e.isPortReserved = false
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
	}

	// Mark endpoint as closed.
	e.closed = true
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
			n.notifyProtocolGoroutine(notifyReset)
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
		e.stack.StartTransportEndpointCleanup(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundBindToDevice)
		e.isRegistered = false
	}

	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.boundPortFlags, e.boundBindToDevice)
		e.isPortReserved = false
	}
	e.boundBindToDevice = 0
	e.boundPortFlags = ports.Flags{}

	e.route.Release()
	e.stack.CompleteTransportEndpointCleanup(e)
	tcpip.DeleteDanglingEndpoint(e)
}

// initialReceiveWindow returns the initial receive window to advertise in the
// SYN/SYN-ACK.
func (e *endpoint) initialReceiveWindow() int {
	rcvWnd := e.receiveBufferAvailable()
	if rcvWnd > math.MaxUint16 {
		rcvWnd = math.MaxUint16
	}

	// Use the user supplied MSS, if available.
	routeWnd := InitialCwnd * int(calculateAdvertisedMSS(e.userMSS, e.route)) * 2
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
		he := e.HardError
		e.mu.RUnlock()
		if s == StateError {
			return buffer.View{}, tcpip.ControlMessages{}, he
		}
		e.stats.ReadErrors.InvalidEndpointState.Increment()
		return buffer.View{}, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	v, err := e.readLocked()
	e.rcvListMu.Unlock()

	e.mu.RUnlock()

	if err == tcpip.ErrClosedForReceive {
		e.stats.ReadErrors.ReadClosed.Increment()
	}
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

// isEndpointWritableLocked checks if a given endpoint is writable
// and also returns the number of bytes that can be written at this
// moment. If the endpoint is not writable then it returns an error
// indicating the reason why it's not writable.
// Caller must hold e.mu and e.sndBufMu
func (e *endpoint) isEndpointWritableLocked() (int, *tcpip.Error) {
	// The endpoint cannot be written to if it's not connected.
	if !e.state.connected() {
		switch e.state {
		case StateError:
			return 0, e.HardError
		default:
			return 0, tcpip.ErrClosedForSend
		}
	}

	// Check if the connection has already been closed for sends.
	if e.sndClosed {
		return 0, tcpip.ErrClosedForSend
	}

	avail := e.sndBufSize - e.sndBufUsed
	if avail <= 0 {
		return 0, tcpip.ErrWouldBlock
	}
	return avail, nil
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, <-chan struct{}, *tcpip.Error) {
	// Linux completely ignores any address passed to sendto(2) for TCP sockets
	// (without the MSG_FASTOPEN flag). Corking is unimplemented, so opts.More
	// and opts.EndOfRecord are also ignored.

	e.mu.RLock()
	e.sndBufMu.Lock()

	avail, err := e.isEndpointWritableLocked()
	if err != nil {
		e.sndBufMu.Unlock()
		e.mu.RUnlock()
		e.stats.WriteErrors.WriteClosed.Increment()
		return 0, nil, err
	}

	// We can release locks while copying data.
	//
	// This is not possible if atomic is set, because we can't allow the
	// available buffer space to be consumed by some other caller while we
	// are copying data in.
	if !opts.Atomic {
		e.sndBufMu.Unlock()
		e.mu.RUnlock()
	}

	// Fetch data.
	v, perr := p.Payload(avail)
	if perr != nil || len(v) == 0 {
		if opts.Atomic { // See above.
			e.sndBufMu.Unlock()
			e.mu.RUnlock()
		}
		// Note that perr may be nil if len(v) == 0.
		return 0, nil, perr
	}

	if !opts.Atomic { // See above.
		e.mu.RLock()
		e.sndBufMu.Lock()

		// Because we released the lock before copying, check state again
		// to make sure the endpoint is still in a valid state for a write.
		avail, err = e.isEndpointWritableLocked()
		if err != nil {
			e.sndBufMu.Unlock()
			e.mu.RUnlock()
			e.stats.WriteErrors.WriteClosed.Increment()
			return 0, nil, err
		}

		// Discard any excess data copied in due to avail being reduced due
		// to a simultaneous write call to the socket.
		if avail < len(v) {
			v = v[:avail]
		}
	}

	// Add data to the send queue.
	s := newSegmentFromView(&e.route, e.ID, v)
	e.sndBufUsed += len(v)
	e.sndBufInQueue += seqnum.Size(len(v))
	e.sndQueue.PushBack(s)
	e.sndBufMu.Unlock()
	// Release the endpoint lock to prevent deadlocks due to lock
	// order inversion when acquiring workMu.
	e.mu.RUnlock()

	if e.workMu.TryLock() {
		// Do the work inline.
		e.handleWrite()
		e.workMu.Unlock()
	} else {
		// Let the protocol goroutine do the work.
		e.sndWaker.Assert()
	}

	return int64(len(v)), nil, nil
}

// Peek reads data without consuming it from the endpoint.
//
// This method does not block if there is no data pending.
func (e *endpoint) Peek(vec [][]byte) (int64, tcpip.ControlMessages, *tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data.
	if s := e.state; !s.connected() && s != StateClose {
		if s == StateError {
			return 0, tcpip.ControlMessages{}, e.HardError
		}
		e.stats.ReadErrors.InvalidEndpointState.Increment()
		return 0, tcpip.ControlMessages{}, tcpip.ErrInvalidEndpointState
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	if e.rcvBufUsed == 0 {
		if e.rcvClosed || !e.state.connected() {
			e.stats.ReadErrors.ReadClosed.Increment()
			return 0, tcpip.ControlMessages{}, tcpip.ErrClosedForReceive
		}
		return 0, tcpip.ControlMessages{}, tcpip.ErrWouldBlock
	}

	// Make a copy of vec so we can modify the slide headers.
	vec = append([][]byte(nil), vec...)

	var num int64
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
				num += int64(n)
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

// SetSockOptBool sets a socket option.
func (e *endpoint) SetSockOptBool(opt tcpip.SockOptBool, v bool) *tcpip.Error {
	switch opt {
	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return tcpip.ErrInvalidEndpointState
		}

		e.mu.Lock()
		defer e.mu.Unlock()

		// We only allow this to be set when we're in the initial state.
		if e.state != StateInitial {
			return tcpip.ErrInvalidEndpointState
		}

		e.v6only = v
	}

	return nil
}

// SetSockOptInt sets a socket option.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) *tcpip.Error {
	switch opt {
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

	case tcpip.DelayOption:
		if v == 0 {
			atomic.StoreUint32(&e.delay, 0)

			// Handle delayed data.
			e.sndWaker.Assert()
		} else {
			atomic.StoreUint32(&e.delay, 1)
		}
		return nil

	default:
		return nil
	}
}

// SetSockOpt sets a socket option.
func (e *endpoint) SetSockOpt(opt interface{}) *tcpip.Error {
	// Lower 2 bits represents ECN bits. RFC 3168, section 23.1
	const inetECNMask = 3
	switch v := opt.(type) {
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

	case tcpip.BindToDeviceOption:
		id := tcpip.NICID(v)
		if id != 0 && !e.stack.HasNIC(id) {
			return tcpip.ErrUnknownDevice
		}
		e.mu.Lock()
		e.bindToDevice = id
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
		e.userMSS = uint16(userMSS)
		e.mu.Unlock()
		e.notifyProtocolGoroutine(notifyMSSChanged)
		return nil

	case tcpip.TTLOption:
		e.mu.Lock()
		e.ttl = uint8(v)
		e.mu.Unlock()
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

	case tcpip.TCPUserTimeoutOption:
		e.mu.Lock()
		e.userTimeout = time.Duration(v)
		e.mu.Unlock()
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

	case tcpip.IPv4TOSOption:
		e.mu.Lock()
		// TODO(gvisor.dev/issue/995): ECN is not currently supported,
		// ignore the bits for now.
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.mu.Unlock()
		return nil

	case tcpip.IPv6TrafficClassOption:
		e.mu.Lock()
		// TODO(gvisor.dev/issue/995): ECN is not currently supported,
		// ignore the bits for now.
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.mu.Unlock()
		return nil

	case tcpip.TCPLingerTimeoutOption:
		e.mu.Lock()
		if v < 0 {
			// Same as effectively disabling TCPLinger timeout.
			v = 0
		}
		var stkTCPLingerTimeout tcpip.TCPLingerTimeoutOption
		if err := e.stack.TransportProtocolOption(header.TCPProtocolNumber, &stkTCPLingerTimeout); err != nil {
			// We were unable to retrieve a stack config, just use
			// the DefaultTCPLingerTimeout.
			if v > tcpip.TCPLingerTimeoutOption(DefaultTCPLingerTimeout) {
				stkTCPLingerTimeout = tcpip.TCPLingerTimeoutOption(DefaultTCPLingerTimeout)
			}
		}
		// Cap it to the stack wide TCPLinger timeout.
		if v > stkTCPLingerTimeout {
			v = stkTCPLingerTimeout
		}
		e.tcpLingerTimeout = time.Duration(v)
		e.mu.Unlock()
		return nil

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

// GetSockOptBool implements tcpip.Endpoint.GetSockOptBool.
func (e *endpoint) GetSockOptBool(opt tcpip.SockOptBool) (bool, *tcpip.Error) {
	switch opt {
	case tcpip.V6OnlyOption:
		// We only recognize this option on v6 endpoints.
		if e.NetProto != header.IPv6ProtocolNumber {
			return false, tcpip.ErrUnknownProtocolOption
		}

		e.mu.Lock()
		v := e.v6only
		e.mu.Unlock()

		return v, nil
	}

	return false, tcpip.ErrUnknownProtocolOption
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, *tcpip.Error) {
	switch opt {
	case tcpip.ReceiveQueueSizeOption:
		return e.readyReceiveSize()

	case tcpip.SendBufferSizeOption:
		e.sndBufMu.Lock()
		v := e.sndBufSize
		e.sndBufMu.Unlock()
		return v, nil

	case tcpip.ReceiveBufferSizeOption:
		e.rcvListMu.Lock()
		v := e.rcvBufSize
		e.rcvListMu.Unlock()
		return v, nil

	case tcpip.DelayOption:
		var o int
		if v := atomic.LoadUint32(&e.delay); v != 0 {
			o = 1
		}
		return o, nil

	default:
		return -1, tcpip.ErrUnknownProtocolOption
	}
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

	case *tcpip.BindToDeviceOption:
		e.mu.RLock()
		*o = tcpip.BindToDeviceOption(e.bindToDevice)
		e.mu.RUnlock()
		return nil

	case *tcpip.QuickAckOption:
		*o = 1
		if v := atomic.LoadUint32(&e.slowAck); v != 0 {
			*o = 0
		}
		return nil

	case *tcpip.TTLOption:
		e.mu.Lock()
		*o = tcpip.TTLOption(e.ttl)
		e.mu.Unlock()
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

	case *tcpip.TCPUserTimeoutOption:
		e.mu.Lock()
		*o = tcpip.TCPUserTimeoutOption(e.userTimeout)
		e.mu.Unlock()
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

	case *tcpip.IPv4TOSOption:
		e.mu.RLock()
		*o = tcpip.IPv4TOSOption(e.sendTOS)
		e.mu.RUnlock()
		return nil

	case *tcpip.IPv6TrafficClassOption:
		e.mu.RLock()
		*o = tcpip.IPv6TrafficClassOption(e.sendTOS)
		e.mu.RUnlock()
		return nil

	case *tcpip.TCPLingerTimeoutOption:
		e.mu.Lock()
		*o = tcpip.TCPLingerTimeoutOption(e.tcpLingerTimeout)
		e.mu.Unlock()
		return nil

	default:
		return tcpip.ErrUnknownProtocolOption
	}
}

func (e *endpoint) checkV4Mapped(addr *tcpip.FullAddress) (tcpip.NetworkProtocolNumber, *tcpip.Error) {
	netProto := e.NetProto
	if header.IsV4MappedAddress(addr.Addr) {
		// Fail if using a v4 mapped address on a v6only endpoint.
		if e.v6only {
			return 0, tcpip.ErrNoRoute
		}

		netProto = header.IPv4ProtocolNumber
		addr.Addr = addr.Addr[header.IPv6AddressSize-header.IPv4AddressSize:]
		if addr.Addr == header.IPv4Any {
			addr.Addr = ""
		}
	}

	// Fail if we're bound to an address length different from the one we're
	// checking.
	if l := len(e.ID.LocalAddress); l != 0 && len(addr.Addr) != 0 && l != len(addr.Addr) {
		return 0, tcpip.ErrInvalidEndpointState
	}

	return netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() *tcpip.Error {
	return tcpip.ErrNotSupported
}

// Connect connects the endpoint to its peer.
func (e *endpoint) Connect(addr tcpip.FullAddress) *tcpip.Error {
	err := e.connect(addr, true, true)
	if err != nil && !err.IgnoreStats() {
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		e.stats.FailedConnectionAttempts.Increment()
	}
	return err
}

// connect connects the endpoint to its peer. In the normal non-S/R case, the
// new connection is expected to run the main goroutine and perform handshake.
// In restore of previously connected endpoints, both ends will be passively
// created (so no new handshaking is done); for stack-accepted connections not
// yet accepted by the app, they are restored without running the main goroutine
// here.
func (e *endpoint) connect(addr tcpip.FullAddress, handshake bool, run bool) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

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

	nicID := addr.NIC
	switch e.state {
	case StateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicID != 0 && nicID != e.boundNICID {
			return tcpip.ErrNoRoute
		}

		nicID = e.boundNICID

	case StateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID (if any)
		// when we find a route.

	case StateConnecting, StateSynSent, StateSynRecv:
		// A connection request has already been issued but hasn't completed
		// yet.
		return tcpip.ErrAlreadyConnecting

	case StateError:
		return e.HardError

	default:
		return tcpip.ErrInvalidEndpointState
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, e.ID.LocalAddress, addr.Addr, netProto, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer r.Release()

	origID := e.ID

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	e.ID.LocalAddress = r.LocalAddress
	e.ID.RemoteAddress = r.RemoteAddress
	e.ID.RemotePort = addr.Port

	if e.ID.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(nicID, netProtos, ProtocolNumber, e.ID, e, e.reusePort, e.boundBindToDevice)
		if err != nil {
			return err
		}
	} else {
		// The endpoint doesn't have a local port yet, so try to get
		// one. Make sure that it isn't one that will result in the same
		// address/port for both local and remote (otherwise this
		// endpoint would be trying to connect to itself).
		sameAddr := e.ID.LocalAddress == e.ID.RemoteAddress

		// Calculate a port offset based on the destination IP/port and
		// src IP to ensure that for a given tuple (srcIP, destIP,
		// destPort) the offset used as a starting point is the same to
		// ensure that we can cycle through the port space effectively.
		h := jenkins.Sum32(e.stack.Seed())
		h.Write([]byte(e.ID.LocalAddress))
		h.Write([]byte(e.ID.RemoteAddress))
		portBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(portBuf, e.ID.RemotePort)
		h.Write(portBuf)
		portOffset := h.Sum32()

		if _, err := e.stack.PickEphemeralPortStable(portOffset, func(p uint16) (bool, *tcpip.Error) {
			if sameAddr && p == e.ID.RemotePort {
				return false, nil
			}
			// reusePort is false below because connect cannot reuse a port even if
			// reusePort was set.
			if !e.stack.IsPortAvailable(netProtos, ProtocolNumber, e.ID.LocalAddress, p, ports.Flags{LoadBalanced: false}, e.bindToDevice) {
				return false, nil
			}

			id := e.ID
			id.LocalPort = p
			switch e.stack.RegisterTransportEndpoint(nicID, netProtos, ProtocolNumber, id, e, e.reusePort, e.bindToDevice) {
			case nil:
				// Port picking successful. Save the details of
				// the selected port.
				e.ID = id
				e.boundBindToDevice = e.bindToDevice
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
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, origID.LocalAddress, origID.LocalPort, e.boundPortFlags, e.boundBindToDevice)
		e.isPortReserved = false
	}

	e.isRegistered = true
	e.state = StateConnecting
	e.route = r.Clone()
	e.boundNICID = nicID
	e.effectiveNetProtos = netProtos
	e.connectingAddress = connectingAddr

	e.initGSO()

	// Connect in the restore phase does not perform handshake. Restore its
	// connection setting here.
	if !handshake {
		e.segmentQueue.mu.Lock()
		for _, l := range []segmentList{e.segmentQueue.list, e.sndQueue, e.snd.writeList} {
			for s := l.Front(); s != nil; s = s.Next() {
				s.id = e.ID
				s.route = r.Clone()
				e.sndWaker.Assert()
			}
		}
		e.segmentQueue.mu.Unlock()
		e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		e.state = StateEstablished
		e.stack.Stats().TCP.CurrentEstablished.Increment()
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
	e.shutdownFlags |= flags
	finQueued := false
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
				e.mu.Unlock()
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
			s := newSegmentFromView(&e.route, e.ID, nil)
			e.sndQueue.PushBack(s)
			e.sndBufInQueue++
			finQueued = true
			// Mark endpoint as closed.
			e.sndClosed = true

			e.sndBufMu.Unlock()
		}

	case e.state == StateListen:
		// Tell protocolListenLoop to stop.
		if flags&tcpip.ShutdownRead != 0 {
			e.notifyProtocolGoroutine(notifyClose)
		}
	default:
		e.mu.Unlock()
		return tcpip.ErrNotConnected
	}
	e.mu.Unlock()
	if finQueued {
		if e.workMu.TryLock() {
			e.handleClose()
			e.workMu.Unlock()
		} else {
			// Tell protocol goroutine to close.
			e.sndCloseWaker.Assert()
		}
	}
	return nil
}

// Listen puts the endpoint in "listen" mode, which allows it to accept
// new connections.
func (e *endpoint) Listen(backlog int) *tcpip.Error {
	err := e.listen(backlog)
	if err != nil && !err.IgnoreStats() {
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		e.stats.FailedConnectionAttempts.Increment()
	}
	return err
}

func (e *endpoint) listen(backlog int) *tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()

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

	if e.state == StateInitial {
		// The listen is called on an unbound socket, the socket is
		// automatically bound to a random free port with the local
		// address set to INADDR_ANY.
		if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
			return err
		}
	}

	// Endpoint must be bound before it can transition to listen mode.
	if e.state != StateBound {
		e.stats.ReadErrors.InvalidEndpointState.Increment()
		return tcpip.ErrInvalidEndpointState
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.boundNICID, e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.reusePort, e.boundBindToDevice); err != nil {
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

	return n, n.waiterQueue, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
func (e *endpoint) Bind(addr tcpip.FullAddress) (err *tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.bindLocked(addr)
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) (err *tcpip.Error) {
	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.state != StateInitial {
		return tcpip.ErrAlreadyBound
	}

	e.BindAddr = addr.Addr
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

	flags := ports.Flags{
		LoadBalanced: e.reusePort,
	}
	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port, flags, e.bindToDevice)
	if err != nil {
		return err
	}

	e.boundBindToDevice = e.bindToDevice
	e.boundPortFlags = flags
	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.ID.LocalPort = port

	// Any failures beyond this point must remove the port registration.
	defer func(portFlags ports.Flags, bindToDevice tcpip.NICID) {
		if err != nil {
			e.stack.ReleasePort(netProtos, ProtocolNumber, addr.Addr, port, portFlags, bindToDevice)
			e.isPortReserved = false
			e.effectiveNetProtos = nil
			e.ID.LocalPort = 0
			e.ID.LocalAddress = ""
			e.boundNICID = 0
			e.boundBindToDevice = 0
			e.boundPortFlags = ports.Flags{}
		}
	}(e.boundPortFlags, e.boundBindToDevice)

	// If an address is specified, we must ensure that it's one of our
	// local addresses.
	if len(addr.Addr) != 0 {
		nic := e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nic == 0 {
			return tcpip.ErrBadLocalAddress
		}

		e.boundNICID = nic
		e.ID.LocalAddress = addr.Addr
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
		Addr: e.ID.LocalAddress,
		Port: e.ID.LocalPort,
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
		Addr: e.ID.RemoteAddress,
		Port: e.ID.RemotePort,
		NIC:  e.boundNICID,
	}, nil
}

// HandlePacket is called by the stack when new packets arrive to this transport
// endpoint.
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, pkt tcpip.PacketBuffer) {
	s := newSegment(r, id, pkt)
	if !s.parse() {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.InvalidSegmentsReceived.Increment()
		e.stats.ReceiveErrors.MalformedPacketsReceived.Increment()
		s.decRef()
		return
	}

	if !s.csumValid {
		e.stack.Stats().MalformedRcvdPackets.Increment()
		e.stack.Stats().TCP.ChecksumErrors.Increment()
		e.stats.ReceiveErrors.ChecksumErrors.Increment()
		s.decRef()
		return
	}

	e.stack.Stats().TCP.ValidSegmentsReceived.Increment()
	e.stats.SegmentsReceived.Increment()
	if (s.flags & header.TCPFlagRst) != 0 {
		e.stack.Stats().TCP.ResetsReceived.Increment()
	}

	e.enqueueSegment(s)
}

func (e *endpoint) enqueueSegment(s *segment) {
	// Send packet to worker goroutine.
	if e.segmentQueue.enqueue(s) {
		e.newSegmentWaker.Assert()
	} else {
		// The queue is full, so we drop the segment.
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.SegmentQueueDropped.Increment()
		s.decRef()
	}
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(id stack.TransportEndpointID, typ stack.ControlType, extra uint32, pkt tcpip.PacketBuffer) {
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
			e.stats.ReceiveErrors.ZeroRcvWindowState.Increment()
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
	s.ID = stack.TCPEndpointID(e.ID)
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

func (e *endpoint) initHardwareGSO() {
	gso := &stack.GSO{}
	switch e.route.NetProto {
	case header.IPv4ProtocolNumber:
		gso.Type = stack.GSOTCPv4
		gso.L3HdrLen = header.IPv4MinimumSize
	case header.IPv6ProtocolNumber:
		gso.Type = stack.GSOTCPv6
		gso.L3HdrLen = header.IPv6MinimumSize
	default:
		panic(fmt.Sprintf("Unknown netProto: %v", e.NetProto))
	}
	gso.NeedsCsum = true
	gso.CsumOffset = header.TCPChecksumOffset
	gso.MaxSize = e.route.GSOMaxSize()
	e.gso = gso
}

func (e *endpoint) initGSO() {
	if e.route.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		e.initHardwareGSO()
	} else if e.route.Capabilities()&stack.CapabilitySoftwareGSO != 0 {
		e.gso = &stack.GSO{
			MaxSize:   e.route.GSOMaxSize(),
			Type:      stack.GSOSW,
			NeedsCsum: false,
		}
	}
}

// State implements tcpip.Endpoint.State. It exports the endpoint's protocol
// state for diagnostics.
func (e *endpoint) State() uint32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return uint32(e.state)
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.mu.RLock()
	// Make a copy of the endpoint info.
	ret := e.EndpointInfo
	e.mu.RUnlock()
	return &ret
}

// Stats returns a pointer to the endpoint stats.
func (e *endpoint) Stats() tcpip.EndpointStats {
	return &e.stats
}

// Wait implements stack.TransportEndpoint.Wait.
func (e *endpoint) Wait() {
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	e.waiterQueue.EventRegister(&waitEntry, waiter.EventHUp)
	defer e.waiterQueue.EventUnregister(&waitEntry)
	for {
		e.mu.Lock()
		running := e.workerRunning
		e.mu.Unlock()
		if !running {
			break
		}
		<-notifyCh
	}
}

func mssForRoute(r *stack.Route) uint16 {
	// TODO(b/143359391): Respect TCP Min and Max size.
	return uint16(r.MTU() - header.TCPMinimumSize)
}
