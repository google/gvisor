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
	"io"
	"math"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
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

const (
	// rcvAdvWndScale is used to split the available socket buffer into
	// application buffer and the window to be advertised to the peer. This is
	// currently hard coded to split the available space equally.
	rcvAdvWndScale = 1

	// SegOverheadFactor is used to multiply the value provided by the
	// user on a SetSockOpt for setting the socket send/receive buffer sizes.
	SegOverheadFactor = 2
)

// connected returns true when s is one of the states representing an
// endpoint connected to a peer.
func (s EndpointState) connected() bool {
	switch s {
	case StateEstablished, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		return true
	default:
		return false
	}
}

// connecting returns true when s is one of the states representing a
// connection in progress, but not yet fully established.
func (s EndpointState) connecting() bool {
	switch s {
	case StateConnecting, StateSynSent, StateSynRecv:
		return true
	default:
		return false
	}
}

// handshake returns true when s is one of the states representing an endpoint
// in the middle of a TCP handshake.
func (s EndpointState) handshake() bool {
	switch s {
	case StateSynSent, StateSynRecv:
		return true
	default:
		return false
	}
}

// closed returns true when s is one of the states an endpoint transitions to
// when closed or when it encounters an error. This is distinct from a newly
// initialized endpoint that was never connected.
func (s EndpointState) closed() bool {
	switch s {
	case StateClose, StateError:
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
	notifyClose
	notifyMTUChanged
	notifyDrain
	notifyReset
	notifyResetByPeer
	// notifyAbort is a request for an expedited teardown.
	notifyAbort
	notifyKeepaliveChanged
	notifyMSSChanged
	// notifyTickleWorker is used to tickle the protocol main loop during a
	// restore after we update the endpoint state to the correct one. This
	// ensures the loop terminates if the final state of the endpoint is
	// say TIME_WAIT.
	notifyTickleWorker
	notifyError
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

	// WantZeroWindow is the number of times we wanted to advertise a
	// zero receive window but couldn't because it would have caused
	// the receive window's right edge to shrink.
	WantZeroRcvWindow tcpip.StatCounter
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
// can be queried by monitoring tools. This exists to allow tcp-only state to
// be exposed.
//
// +stateify savable
type EndpointInfo struct {
	stack.TransportEndpointInfo
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
// Each endpoint has a few mutexes:
//
// e.mu -> Primary mutex for an endpoint must be held for all operations except
// in e.Readiness where acquiring it will result in a deadlock in epoll
// implementation.
//
// The following three mutexes can be acquired independent of e.mu but if
// acquired with e.mu then e.mu must be acquired first.
//
// e.acceptMu -> protects acceptedChan.
// e.rcvListMu -> Protects the rcvList and associated fields.
// e.sndBufMu -> Protects the sndQueue and associated fields.
// e.lastErrorMu -> Protects the lastError field.
//
// LOCKING/UNLOCKING of the endpoint.  The locking of an endpoint is different
// based on the context in which the lock is acquired. In the syscall context
// e.LockUser/e.UnlockUser should be used and when doing background processing
// e.mu.Lock/e.mu.Unlock should be used. The distinction is described below
// in brief.
//
// The reason for this locking behaviour is to avoid wakeups to handle packets.
// In cases where the endpoint is already locked the background processor can
// queue the packet up and go its merry way and the lock owner will eventually
// process the backlog when releasing the lock. Similarly when acquiring the
// lock from say a syscall goroutine we can implement a bit of spinning if we
// know that the lock is not held by another syscall goroutine. Background
// processors should never hold the lock for long and we can avoid an expensive
// sleep/wakeup by spinning for a shortwhile.
//
// For more details please see the detailed documentation on
// e.LockUser/e.UnlockUser methods.
//
// +stateify savable
type endpoint struct {
	EndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// endpointEntry is used to queue endpoints for processing to the
	// a given tcp processor goroutine.
	//
	// Precondition: epQueue.mu must be held to read/write this field..
	endpointEntry `state:"nosave"`

	// pendingProcessing is true if this endpoint is queued for processing
	// to a TCP processor.
	//
	// Precondition: epQueue.mu must be held to read/write this field..
	pendingProcessing bool `state:"nosave"`

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack  `state:"manual"`
	waiterQueue *waiter.Queue `state:"wait"`
	uniqueID    uint64

	// hardError is meaningful only when state is stateError. It stores the
	// error to be returned when read/write syscalls are called and the
	// endpoint is in this state. hardError is protected by endpoint mu.
	hardError tcpip.Error

	// lastError represents the last error that the endpoint reported;
	// access to it is protected by the following mutex.
	lastErrorMu sync.Mutex `state:"nosave"`
	lastError   tcpip.Error

	// rcvReadMu synchronizes calls to Read.
	//
	// mu and rcvListMu are temporarily released during data copying. rcvReadMu
	// must be held during each read to ensure atomicity, so that multiple reads
	// do not interleave.
	//
	// rcvReadMu should be held before holding mu.
	rcvReadMu sync.Mutex `state:"nosave"`

	// rcvListMu synchronizes access to rcvList.
	//
	// rcvListMu can be taken after the endpoint mu below.
	rcvListMu sync.Mutex `state:"nosave"`

	// rcvList is the queue for ready-for-delivery segments.
	//
	// rcvReadMu, mu and rcvListMu must be held, in the stated order, to read data
	// and removing segments from list. A range of segment can be determined, then
	// temporarily release mu and rcvListMu while processing the segment range.
	// This allows new segments to be appended to the list while processing.
	//
	// rcvListMu must be held to append segments to list.
	rcvList   segmentList `state:"wait"`
	rcvClosed bool
	// rcvBufSize is the total size of the receive buffer.
	rcvBufSize int
	// rcvBufUsed is the actual number of payload bytes held in the receive buffer
	// not counting any overheads of the segments itself. NOTE: This will always
	// be strictly <= rcvMemUsed below.
	rcvBufUsed    int
	rcvAutoParams rcvBufAutoTuneParams

	// rcvMemUsed tracks the total amount of memory in use by received segments
	// held in rcvList, pendingRcvdSegments and the segment queue. This is used to
	// compute the window and the actual available buffer space. This is distinct
	// from rcvBufUsed above which is the actual number of payload bytes held in
	// the buffer not including any segment overheads.
	//
	// rcvMemUsed must be accessed atomically.
	rcvMemUsed int32

	// mu protects all endpoint fields unless documented otherwise. mu must
	// be acquired before interacting with the endpoint fields.
	//
	// During handshake, mu is locked by the protocol listen goroutine and
	// released by the handshake completion goroutine.
	mu          sync.CrossGoroutineMutex `state:"nosave"`
	ownedByUser uint32

	// state must be read/set using the EndpointState()/setEndpointState()
	// methods.
	state EndpointState `state:".(EndpointState)"`

	// origEndpointState is only used during a restore phase to save the
	// endpoint state at restore time as the socket is moved to it's correct
	// state.
	origEndpointState EndpointState `state:"nosave"`

	isPortReserved    bool `state:"manual"`
	isRegistered      bool `state:"manual"`
	boundNICID        tcpip.NICID
	route             *stack.Route `state:"manual"`
	ttl               uint8
	isConnectNotified bool

	// h stores a reference to the current handshake state if the endpoint is in
	// the SYN-SENT or SYN-RECV states, in which case endpoint == endpoint.h.ep.
	// nil otherwise.
	h *handshake `state:"nosave"`

	// portFlags stores the current values of port related flags.
	portFlags ports.Flags

	// Values used to reserve a port or register a transport endpoint
	// (which ever happens first).
	boundBindToDevice tcpip.NICID
	boundPortFlags    ports.Flags
	boundDest         tcpip.FullAddress

	// effectiveNetProtos contains the network protocols actually in use. In
	// most cases it will only contain "netProto", but in cases like IPv6
	// endpoints with v6only set to false, this could include multiple
	// protocols (e.g., IPv6 and IPv4) or a single different protocol (e.g.,
	// IPv4 when IPv6 endpoint is bound or connected to an IPv4 mapped
	// address).
	effectiveNetProtos []tcpip.NetworkProtocolNumber

	// workerRunning specifies if a worker goroutine is running.
	workerRunning bool

	// workerCleanup specifies if the worker goroutine must perform cleanup
	// before exiting. This can only be set to true when workerRunning is
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

	// recentTSTime is the unix time when we updated recentTS last.
	recentTSTime time.Time `state:".(unixTime)"`

	// tsOffset is a randomized offset added to the value of the
	// TSVal field in the timestamp option.
	tsOffset uint32

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// tcpRecovery is the loss deteoction algorithm used by TCP.
	tcpRecovery tcpip.TCPRecovery

	// sackPermitted is set to true if the peer sends the TCPSACKPermitted
	// option in the SYN/SYN-ACK.
	sackPermitted bool

	// sack holds TCP SACK related information for this endpoint.
	sack SACKInfo

	// delay enables Nagle's algorithm.
	//
	// delay is a boolean (0 is false) and must be accessed atomically.
	delay uint32

	// scoreboard holds TCP SACK Scoreboard information for this endpoint.
	scoreboard *SACKScoreboard

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

	// maxSynRetries is the maximum number of SYN retransmits that TCP should
	// send before aborting the attempt to connect. It cannot exceed 255.
	//
	// NOTE: This is currently a no-op and does not change the SYN
	// retransmissions.
	maxSynRetries uint8

	// windowClamp is used to bound the size of the advertised window to
	// this value.
	windowClamp uint32

	// The following fields are used to manage the send buffer. When
	// segments are ready to be sent, they are added to sndQueue and the
	// protocol goroutine is signaled via sndWaker.
	//
	// When the send side is closed, the protocol goroutine is notified via
	// sndCloseWaker, and sndClosed is set to true.
	sndBufMu      sync.Mutex `state:"nosave"`
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

	// deferAccept if non-zero specifies a user specified time during
	// which the final ACK of a handshake will be dropped provided the
	// ACK is a bare ACK and carries no data. If the timeout is crossed then
	// the bare ACK is accepted and the connection is delivered to the
	// listener.
	deferAccept time.Duration

	// pendingAccepted is a synchronization primitive used to track number
	// of connections that are queued up to be delivered to the accepted
	// channel. We use this to ensure that all goroutines blocked on writing
	// to the acceptedChan below terminate before we close acceptedChan.
	pendingAccepted sync.WaitGroup `state:"nosave"`

	// acceptMu protects acceptedChan.
	acceptMu sync.Mutex `state:"nosave"`

	// acceptCond is a condition variable that can be used to block on when
	// acceptedChan is full and an endpoint is ready to be delivered.
	//
	// This condition variable is required because just blocking on sending
	// to acceptedChan does not work in cases where endpoint.Listen is
	// called twice with different backlog values. In such cases the channel
	// is closed and a new one created. Any pending goroutines blocking on
	// the write to the channel will panic.
	//
	// We use this condition variable to block/unblock goroutines which
	// tried to deliver an endpoint but couldn't because accept backlog was
	// full ( See: endpoint.deliverAccepted ).
	acceptCond *sync.Cond `state:"nosave"`

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

	// txHash is the transport layer hash to be set on outbound packets
	// emitted by this endpoint.
	txHash uint32

	// owner is used to get uid and gid of the packet.
	owner tcpip.PacketOwner

	// ops is used to get socket level options.
	ops tcpip.SocketOptions
}

// UniqueID implements stack.TransportEndpoint.UniqueID.
func (e *endpoint) UniqueID() uint64 {
	return e.uniqueID
}

// calculateAdvertisedMSS calculates the MSS to advertise.
//
// If userMSS is non-zero and is not greater than the maximum possible MSS for
// r, it will be used; otherwise, the maximum possible MSS will be used.
func calculateAdvertisedMSS(userMSS uint16, r *stack.Route) uint16 {
	// The maximum possible MSS is dependent on the route.
	// TODO(b/143359391): Respect TCP Min and Max size.
	maxMSS := uint16(r.MTU() - header.TCPMinimumSize)

	if userMSS != 0 && userMSS < maxMSS {
		return userMSS
	}

	return maxMSS
}

// LockUser tries to lock e.mu and if it fails it will check if the lock is held
// by another syscall goroutine. If yes, then it will goto sleep waiting for the
// lock to be released, if not then it will spin till it acquires the lock or
// another syscall goroutine acquires it in which case it will goto sleep as
// described above.
//
// The assumption behind spinning here being that background packet processing
// should not be holding the lock for long and spinning reduces latency as we
// avoid an expensive sleep/wakeup of of the syscall goroutine).
func (e *endpoint) LockUser() {
	for {
		// Try first if the sock is locked then check if it's owned
		// by another user goroutine if not then we spin, otherwise
		// we just go to sleep on the Lock() and wait.
		if !e.mu.TryLock() {
			// If socket is owned by the user then just go to sleep
			// as the lock could be held for a reasonably long time.
			if atomic.LoadUint32(&e.ownedByUser) == 1 {
				e.mu.Lock()
				atomic.StoreUint32(&e.ownedByUser, 1)
				return
			}
			// Spin but yield the processor since the lower half
			// should yield the lock soon.
			runtime.Gosched()
			continue
		}
		atomic.StoreUint32(&e.ownedByUser, 1)
		return
	}
}

// UnlockUser will check if there are any segments already queued for processing
// and process any such segments before unlocking e.mu. This is required because
// we when packets arrive and endpoint lock is already held then such packets
// are queued up to be processed. If the lock is held by the endpoint goroutine
// then it will process these packets but if the lock is instead held by the
// syscall goroutine then we can have the syscall goroutine process the backlog
// before unlocking.
//
// This avoids an unnecessary wakeup of the endpoint protocol goroutine for the
// endpoint. It's also required eventually when we get rid of the endpoint
// protocol goroutine altogether.
//
// Precondition: e.LockUser() must have been called before calling e.UnlockUser()
func (e *endpoint) UnlockUser() {
	// Lock segment queue before checking so that we avoid a race where
	// segments can be queued between the time we check if queue is empty
	// and actually unlock the endpoint mutex.
	for {
		e.segmentQueue.mu.Lock()
		if e.segmentQueue.emptyLocked() {
			if atomic.SwapUint32(&e.ownedByUser, 0) != 1 {
				panic("e.UnlockUser() called without calling e.LockUser()")
			}
			e.mu.Unlock()
			e.segmentQueue.mu.Unlock()
			return
		}
		e.segmentQueue.mu.Unlock()

		switch e.EndpointState() {
		case StateEstablished:
			if err := e.handleSegments(true /* fastPath */); err != nil {
				e.notifyProtocolGoroutine(notifyTickleWorker)
			}
		default:
			// Since we are waking the endpoint goroutine here just unlock
			// and let it process the queued segments.
			e.newSegmentWaker.Assert()
			if atomic.SwapUint32(&e.ownedByUser, 0) != 1 {
				panic("e.UnlockUser() called without calling e.LockUser()")
			}
			e.mu.Unlock()
			return
		}
	}
}

// StopWork halts packet processing. Only to be used in tests.
func (e *endpoint) StopWork() {
	e.mu.Lock()
}

// ResumeWork resumes packet processing. Only to be used in tests.
func (e *endpoint) ResumeWork() {
	e.mu.Unlock()
}

// setEndpointState updates the state of the endpoint to state atomically. This
// method is unexported as the only place we should update the state is in this
// package but we allow the state to be read freely without holding e.mu.
//
// Precondition: e.mu must be held to call this method.
func (e *endpoint) setEndpointState(state EndpointState) {
	oldstate := EndpointState(atomic.LoadUint32((*uint32)(&e.state)))
	switch state {
	case StateEstablished:
		e.stack.Stats().TCP.CurrentEstablished.Increment()
		e.stack.Stats().TCP.CurrentConnected.Increment()
	case StateError:
		fallthrough
	case StateClose:
		if oldstate == StateCloseWait || oldstate == StateEstablished {
			e.stack.Stats().TCP.EstablishedResets.Increment()
		}
		fallthrough
	default:
		if oldstate == StateEstablished {
			e.stack.Stats().TCP.CurrentEstablished.Decrement()
		}
	}
	atomic.StoreUint32((*uint32)(&e.state), uint32(state))
}

// EndpointState returns the current state of the endpoint.
func (e *endpoint) EndpointState() EndpointState {
	return EndpointState(atomic.LoadUint32((*uint32)(&e.state)))
}

// setRecentTimestamp sets the recentTS field to the provided value.
func (e *endpoint) setRecentTimestamp(recentTS uint32) {
	e.recentTS = recentTS
	e.recentTSTime = time.Now()
}

// recentTimestamp returns the value of the recentTS field.
func (e *endpoint) recentTimestamp() uint32 {
	return e.recentTS
}

// keepalive is a synchronization wrapper used to appease stateify. See the
// comment in endpoint, where it is used.
//
// +stateify savable
type keepalive struct {
	sync.Mutex `state:"nosave"`
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
		sndMTU:      int(math.MaxInt32),
		keepalive: keepalive{
			// Linux defaults.
			idle:     2 * time.Hour,
			interval: 75 * time.Second,
			count:    9,
		},
		uniqueID:      s.UniqueID(),
		txHash:        s.Rand().Uint32(),
		windowClamp:   DefaultReceiveBufferSize,
		maxSynRetries: DefaultSynRetries,
	}
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetQuickAck(true)
	e.ops.SetSendBufferSize(DefaultSendBufferSize, false /* notify */)

	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}

	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.rcvBufSize = rs.Default
	}

	var cs tcpip.CongestionControlOption
	if err := s.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	var mrb tcpip.TCPModerateReceiveBufferOption
	if err := s.TransportProtocolOption(ProtocolNumber, &mrb); err == nil {
		e.rcvAutoParams.disabled = !bool(mrb)
	}

	var de tcpip.TCPDelayEnabled
	if err := s.TransportProtocolOption(ProtocolNumber, &de); err == nil && de {
		e.ops.SetDelayOption(true)
	}

	var tcpLT tcpip.TCPLingerTimeoutOption
	if err := s.TransportProtocolOption(ProtocolNumber, &tcpLT); err == nil {
		e.tcpLingerTimeout = time.Duration(tcpLT)
	}

	var synRetries tcpip.TCPSynRetriesOption
	if err := s.TransportProtocolOption(ProtocolNumber, &synRetries); err == nil {
		e.maxSynRetries = uint8(synRetries)
	}

	s.TransportProtocolOption(ProtocolNumber, &e.tcpRecovery)

	if p := s.GetTCPProbe(); p != nil {
		e.probe = p
	}

	e.segmentQueue.ep = e
	e.tsOffset = timeStampOffset()
	e.acceptCond = sync.NewCond(&e.acceptMu)
	e.keepalive.timer.init(&e.keepalive.waker)

	return e
}

// Readiness returns the current readiness of the endpoint. For example, if
// waiter.EventIn is set, the endpoint is immediately readable.
func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	result := waiter.EventMask(0)

	switch e.EndpointState() {
	case StateInitial, StateBound:
		// This prevents blocking of new sockets which are not
		// connected when SO_LINGER is set.
		result |= waiter.EventHUp

	case StateConnecting, StateSynSent, StateSynRecv:
		// Ready for nothing.

	case StateClose, StateError, StateTimeWait:
		// Ready for anything.
		result = mask

	case StateListen:
		// Check if there's anything in the accepted channel.
		if (mask & waiter.EventIn) != 0 {
			e.acceptMu.Lock()
			if len(e.acceptedChan) > 0 {
				result |= waiter.EventIn
			}
			e.acceptMu.Unlock()
		}
	}
	if e.EndpointState().connected() {
		// Determine if the endpoint is writable if requested.
		if (mask & waiter.EventOut) != 0 {
			e.sndBufMu.Lock()
			sndBufSize := e.getSendBufferSize()
			if e.sndClosed || e.sndBufUsed < sndBufSize {
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

// Abort implements stack.TransportEndpoint.Abort.
func (e *endpoint) Abort() {
	// The abort notification is not processed synchronously, so no
	// synchronization is needed.
	//
	// If the endpoint becomes connected after this check, we still close
	// the endpoint. This worst case results in a slower abort.
	//
	// If the endpoint disconnected after the check, nothing needs to be
	// done, so sending a notification which will potentially be ignored is
	// fine.
	//
	// If the endpoint connecting finishes after the check, the endpoint
	// is either in a connected state (where we would notifyAbort anyway),
	// SYN-RECV (where we would also notifyAbort anyway), or in an error
	// state where nothing is required and the notification can be safely
	// ignored.
	//
	// Endpoints where a Close during connecting or SYN-RECV state would be
	// problematic are set to state connecting before being registered (and
	// thus possible to be Aborted). They are never available in initial
	// state.
	//
	// Endpoints transitioning from initial to connecting state may be
	// safely either closed or sent notifyAbort.
	if s := e.EndpointState(); s == StateConnecting || s == StateSynRecv || s.connected() {
		e.notifyProtocolGoroutine(notifyAbort)
		return
	}
	e.Close()
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it. It must be called only once and with no other concurrent calls to
// the endpoint.
func (e *endpoint) Close() {
	e.LockUser()
	defer e.UnlockUser()
	if e.closed {
		return
	}

	linger := e.SocketOptions().GetLinger()
	if linger.Enabled && linger.Timeout == 0 {
		s := e.EndpointState()
		isResetState := s == StateEstablished || s == StateCloseWait || s == StateFinWait1 || s == StateFinWait2 || s == StateSynRecv
		if isResetState {
			// Close the endpoint without doing full shutdown and
			// send a RST.
			e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			e.closeNoShutdownLocked()

			// Wake up worker to close the endpoint.
			switch s {
			case StateSynRecv:
				e.notifyProtocolGoroutine(notifyClose)
			default:
				e.notifyProtocolGoroutine(notifyTickleWorker)
			}
			return
		}
	}

	// Issue a shutdown so that the peer knows we won't send any more data
	// if we're connected, or stop accepting if we're listening.
	e.shutdownLocked(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	e.closeNoShutdownLocked()
}

// closeNoShutdown closes the endpoint without doing a full shutdown.
func (e *endpoint) closeNoShutdownLocked() {
	// For listening sockets, we always release ports inline so that they
	// are immediately available for reuse after Close() is called. If also
	// registered, we unregister as well otherwise the next user would fail
	// in Listen() when trying to register.
	if e.EndpointState() == StateListen && e.isPortReserved {
		if e.isRegistered {
			e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice)
			e.isRegistered = false
		}

		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.boundPortFlags, e.boundBindToDevice, e.boundDest)
		e.isPortReserved = false
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
		e.boundDest = tcpip.FullAddress{}
	}

	// Mark endpoint as closed.
	e.closed = true

	switch e.EndpointState() {
	case StateClose, StateError:
		return
	}

	eventMask := waiter.EventIn | waiter.EventOut
	// Either perform the local cleanup or kick the worker to make sure it
	// knows it needs to cleanup.
	if e.workerRunning {
		e.workerCleanup = true
		tcpip.AddDanglingEndpoint(e)
		// Worker will remove the dangling endpoint when the endpoint
		// goroutine terminates.
		e.notifyProtocolGoroutine(notifyClose)
	} else {
		e.transitionToStateCloseLocked()
		// Notify that the endpoint is closed.
		eventMask |= waiter.EventHUp
	}

	// The TCP closing state-machine would eventually notify EventHUp, but we
	// notify EventIn|EventOut immediately to unblock any blocked waiters.
	e.waiterQueue.Notify(eventMask)
}

// closePendingAcceptableConnections closes all connections that have completed
// handshake but not yet been delivered to the application.
func (e *endpoint) closePendingAcceptableConnectionsLocked() {
	e.acceptMu.Lock()
	if e.acceptedChan == nil {
		e.acceptMu.Unlock()
		return
	}
	close(e.acceptedChan)
	ch := e.acceptedChan
	e.acceptedChan = nil
	e.acceptCond.Broadcast()
	e.acceptMu.Unlock()

	// Reset all connections that are waiting to be accepted.
	for n := range ch {
		n.notifyProtocolGoroutine(notifyReset)
	}
	// Wait for reset of all endpoints that are still waiting to be delivered to
	// the now closed acceptedChan.
	e.pendingAccepted.Wait()
}

// cleanupLocked frees all resources associated with the endpoint. It is called
// after Close() is called and the worker goroutine (if any) is done with its
// work.
func (e *endpoint) cleanupLocked() {
	// Close all endpoints that might have been accepted by TCP but not by
	// the client.
	e.closePendingAcceptableConnectionsLocked()
	e.keepalive.timer.cleanup()

	e.workerCleanup = false

	if e.isRegistered {
		e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice)
		e.isRegistered = false
	}

	if e.isPortReserved {
		e.stack.ReleasePort(e.effectiveNetProtos, ProtocolNumber, e.ID.LocalAddress, e.ID.LocalPort, e.boundPortFlags, e.boundBindToDevice, e.boundDest)
		e.isPortReserved = false
	}
	e.boundBindToDevice = 0
	e.boundPortFlags = ports.Flags{}
	e.boundDest = tcpip.FullAddress{}

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	e.stack.CompleteTransportEndpointCleanup(e)
	tcpip.DeleteDanglingEndpoint(e)
}

// wndFromSpace returns the window that we can advertise based on the available
// receive buffer space.
func wndFromSpace(space int) int {
	return space >> rcvAdvWndScale
}

// initialReceiveWindow returns the initial receive window to advertise in the
// SYN/SYN-ACK.
func (e *endpoint) initialReceiveWindow() int {
	rcvWnd := wndFromSpace(e.receiveBufferAvailable())
	if rcvWnd > math.MaxUint16 {
		rcvWnd = math.MaxUint16
	}

	// Use the user supplied MSS, if available.
	routeWnd := InitialCwnd * int(calculateAdvertisedMSS(e.userMSS, e.route)) * 2
	if rcvWnd > routeWnd {
		rcvWnd = routeWnd
	}
	rcvWndScale := e.rcvWndScaleForHandshake()

	// Round-down the rcvWnd to a multiple of wndScale. This ensures that the
	// window offered in SYN won't be reduced due to the loss of precision if
	// window scaling is enabled after the handshake.
	rcvWnd = (rcvWnd >> uint8(rcvWndScale)) << uint8(rcvWndScale)

	// Ensure we can always accept at least 1 byte if the scale specified
	// was too high for the provided rcvWnd.
	if rcvWnd == 0 {
		rcvWnd = 1
	}

	return rcvWnd
}

// ModerateRecvBuf adjusts the receive buffer and the advertised window
// based on the number of bytes copied to userspace.
func (e *endpoint) ModerateRecvBuf(copied int) {
	e.LockUser()
	defer e.UnlockUser()

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
			availBefore := wndFromSpace(e.receiveBufferAvailableLocked())
			e.rcvBufSize = rcvWnd
			availAfter := wndFromSpace(e.receiveBufferAvailableLocked())
			if crossed, above := e.windowCrossedACKThresholdLocked(availAfter - availBefore); crossed && above {
				e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
			}
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

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}

// Preconditions: e.mu must be held to call this function.
func (e *endpoint) hardErrorLocked() tcpip.Error {
	err := e.hardError
	e.hardError = nil
	return err
}

// Preconditions: e.mu must be held to call this function.
func (e *endpoint) lastErrorLocked() tcpip.Error {
	e.lastErrorMu.Lock()
	defer e.lastErrorMu.Unlock()
	err := e.lastError
	e.lastError = nil
	return err
}

// LastError implements tcpip.Endpoint.LastError.
func (e *endpoint) LastError() tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()
	if err := e.hardErrorLocked(); err != nil {
		return err
	}
	return e.lastErrorLocked()
}

// UpdateLastError implements tcpip.SocketOptionsHandler.UpdateLastError.
func (e *endpoint) UpdateLastError(err tcpip.Error) {
	e.LockUser()
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()
	e.UnlockUser()
}

// Read implements tcpip.Endpoint.Read.
func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	e.rcvReadMu.Lock()
	defer e.rcvReadMu.Unlock()

	// N.B. Here we get a range of segments to be processed. It is safe to not
	// hold rcvListMu when processing, since we hold rcvReadMu to ensure only we
	// can remove segments from the list through commitRead().
	first, last, serr := e.startRead()
	if serr != nil {
		if _, ok := serr.(*tcpip.ErrClosedForReceive); ok {
			e.stats.ReadErrors.ReadClosed.Increment()
		}
		return tcpip.ReadResult{}, serr
	}

	var err error
	done := 0
	s := first
	for s != nil {
		var n int
		n, err = s.data.ReadTo(dst, opts.Peek)
		// Book keeping first then error handling.

		done += n

		if opts.Peek {
			// For peek, we use the (first, last) range of segment returned from
			// startRead. We don't consume the receive buffer, so commitRead should
			// not be called.
			//
			// N.B. It is important to use `last` to determine the last segment, since
			// appending can happen while we process, and will lead to data race.
			if s == last {
				break
			}
			s = s.Next()
		} else {
			// N.B. commitRead() conveniently returns the next segment to read, after
			// removing the data/segment that is read.
			s = e.commitRead(n)
		}

		if err != nil {
			break
		}
	}

	// If something is read, we must report it. Report error when nothing is read.
	if done == 0 && err != nil {
		return tcpip.ReadResult{}, &tcpip.ErrBadBuffer{}
	}
	return tcpip.ReadResult{
		Count: done,
		Total: done,
	}, nil
}

// startRead checks that endpoint is in a readable state, and return the
// inclusive range of segments that can be read.
//
// Precondition: e.rcvReadMu must be held.
func (e *endpoint) startRead() (first, last *segment, err tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	// When in SYN-SENT state, let the caller block on the receive.
	// An application can initiate a non-blocking connect and then block
	// on a receive. It can expect to read any data after the handshake
	// is complete. RFC793, section 3.9, p58.
	if e.EndpointState() == StateSynSent {
		return nil, nil, &tcpip.ErrWouldBlock{}
	}

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data. Also note that a RST being received
	// would cause the state to become StateError so we should allow the
	// reads to proceed before returning a ECONNRESET.
	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	bufUsed := e.rcvBufUsed
	if s := e.EndpointState(); !s.connected() && s != StateClose && bufUsed == 0 {
		if s == StateError {
			if err := e.hardErrorLocked(); err != nil {
				return nil, nil, err
			}
			return nil, nil, &tcpip.ErrClosedForReceive{}
		}
		e.stats.ReadErrors.NotConnected.Increment()
		return nil, nil, &tcpip.ErrNotConnected{}
	}

	if e.rcvBufUsed == 0 {
		if e.rcvClosed || !e.EndpointState().connected() {
			return nil, nil, &tcpip.ErrClosedForReceive{}
		}
		return nil, nil, &tcpip.ErrWouldBlock{}
	}

	return e.rcvList.Front(), e.rcvList.Back(), nil
}

// commitRead commits a read of done bytes and returns the next non-empty
// segment to read. Data read from the segment must have also been removed from
// the segment in order for this method to work correctly.
//
// It is performance critical to call commitRead frequently when servicing a big
// Read request, so TCP can make progress timely. Right now, it is designed to
// do this per segment read, hence this method conveniently returns the next
// segment to read while holding the lock.
//
// Precondition: e.rcvReadMu must be held.
func (e *endpoint) commitRead(done int) *segment {
	e.LockUser()
	defer e.UnlockUser()
	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	memDelta := 0
	s := e.rcvList.Front()
	for s != nil && s.data.Size() == 0 {
		e.rcvList.Remove(s)
		// Memory is only considered released when the whole segment has been
		// read.
		memDelta += s.segMemSize()
		s.decRef()
		s = e.rcvList.Front()
	}
	e.rcvBufUsed -= done

	if memDelta > 0 {
		// If the window was small before this read and if the read freed up
		// enough buffer space, to either fit an aMSS or half a receive buffer
		// (whichever smaller), then notify the protocol goroutine to send a
		// window update.
		if crossed, above := e.windowCrossedACKThresholdLocked(memDelta); crossed && above {
			e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
		}
	}

	return e.rcvList.Front()
}

// isEndpointWritableLocked checks if a given endpoint is writable
// and also returns the number of bytes that can be written at this
// moment. If the endpoint is not writable then it returns an error
// indicating the reason why it's not writable.
// Caller must hold e.mu and e.sndBufMu
func (e *endpoint) isEndpointWritableLocked() (int, tcpip.Error) {
	// The endpoint cannot be written to if it's not connected.
	switch s := e.EndpointState(); {
	case s == StateError:
		if err := e.hardErrorLocked(); err != nil {
			return 0, err
		}
		return 0, &tcpip.ErrClosedForSend{}
	case !s.connecting() && !s.connected():
		return 0, &tcpip.ErrClosedForSend{}
	case s.connecting():
		// As per RFC793, page 56, a send request arriving when in connecting
		// state, can be queued to be completed after the state becomes
		// connected. Return an error code for the caller of endpoint Write to
		// try again, until the connection handshake is complete.
		return 0, &tcpip.ErrWouldBlock{}
	}

	// Check if the connection has already been closed for sends.
	if e.sndClosed {
		return 0, &tcpip.ErrClosedForSend{}
	}

	sndBufSize := e.getSendBufferSize()
	avail := sndBufSize - e.sndBufUsed
	if avail <= 0 {
		return 0, &tcpip.ErrWouldBlock{}
	}
	return avail, nil
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// Linux completely ignores any address passed to sendto(2) for TCP sockets
	// (without the MSG_FASTOPEN flag). Corking is unimplemented, so opts.More
	// and opts.EndOfRecord are also ignored.

	e.LockUser()
	defer e.UnlockUser()

	nextSeg, n, err := func() (*segment, int, tcpip.Error) {
		e.sndBufMu.Lock()
		defer e.sndBufMu.Unlock()

		avail, err := e.isEndpointWritableLocked()
		if err != nil {
			e.stats.WriteErrors.WriteClosed.Increment()
			return nil, 0, err
		}

		v, err := func() ([]byte, tcpip.Error) {
			// We can release locks while copying data.
			//
			// This is not possible if atomic is set, because we can't allow the
			// available buffer space to be consumed by some other caller while we
			// are copying data in.
			if !opts.Atomic {
				e.sndBufMu.Unlock()
				defer e.sndBufMu.Lock()

				e.UnlockUser()
				defer e.LockUser()
			}

			// Fetch data.
			if l := p.Len(); l < avail {
				avail = l
			}
			if avail == 0 {
				return nil, nil
			}
			v := make([]byte, avail)
			if _, err := io.ReadFull(p, v); err != nil {
				return nil, &tcpip.ErrBadBuffer{}
			}
			return v, nil
		}()
		if len(v) == 0 || err != nil {
			return nil, 0, err
		}

		if !opts.Atomic {
			// Since we released locks in between it's possible that the
			// endpoint transitioned to a CLOSED/ERROR states so make
			// sure endpoint is still writable before trying to write.
			avail, err := e.isEndpointWritableLocked()
			if err != nil {
				e.stats.WriteErrors.WriteClosed.Increment()
				return nil, 0, err
			}

			// Discard any excess data copied in due to avail being reduced due
			// to a simultaneous write call to the socket.
			if avail < len(v) {
				v = v[:avail]
			}
		}

		// Add data to the send queue.
		s := newOutgoingSegment(e.ID, v)
		e.sndBufUsed += len(v)
		e.sndBufInQueue += seqnum.Size(len(v))
		e.sndQueue.PushBack(s)

		return e.drainSendQueueLocked(), len(v), nil
	}()
	if err != nil {
		return 0, err
	}
	e.sendData(nextSeg)
	return int64(n), nil
}

// selectWindowLocked returns the new window without checking for shrinking or scaling
// applied.
// Precondition: e.mu and e.rcvListMu must be held.
func (e *endpoint) selectWindowLocked() (wnd seqnum.Size) {
	wndFromAvailable := wndFromSpace(e.receiveBufferAvailableLocked())
	maxWindow := wndFromSpace(e.rcvBufSize)
	wndFromUsedBytes := maxWindow - e.rcvBufUsed

	// We take the lesser of the wndFromAvailable and wndFromUsedBytes because in
	// cases where we receive a lot of small segments the segment overhead is a
	// lot higher and we can run out socket buffer space before we can fill the
	// previous window we advertised. In cases where we receive MSS sized or close
	// MSS sized segments we will probably run out of window space before we
	// exhaust receive buffer.
	newWnd := wndFromAvailable
	if newWnd > wndFromUsedBytes {
		newWnd = wndFromUsedBytes
	}
	if newWnd < 0 {
		newWnd = 0
	}
	return seqnum.Size(newWnd)
}

// selectWindow invokes selectWindowLocked after acquiring e.rcvListMu.
func (e *endpoint) selectWindow() (wnd seqnum.Size) {
	e.rcvListMu.Lock()
	wnd = e.selectWindowLocked()
	e.rcvListMu.Unlock()
	return wnd
}

// windowCrossedACKThresholdLocked checks if the receive window to be announced
// would be under aMSS or under the window derived from half receive buffer,
// whichever smaller. This is useful as a receive side silly window syndrome
// prevention mechanism. If window grows to reasonable value, we should send ACK
// to the sender to inform the rx space is now large. We also want ensure a
// series of small read()'s won't trigger a flood of spurious tiny ACK's.
//
// For large receive buffers, the threshold is aMSS - once reader reads more
// than aMSS we'll send ACK. For tiny receive buffers, the threshold is half of
// receive buffer size. This is chosen arbitrairly.
// crossed will be true if the window size crossed the ACK threshold.
// above will be true if the new window is >= ACK threshold and false
// otherwise.
//
// Precondition: e.mu and e.rcvListMu must be held.
func (e *endpoint) windowCrossedACKThresholdLocked(deltaBefore int) (crossed bool, above bool) {
	newAvail := int(e.selectWindowLocked())
	oldAvail := newAvail - deltaBefore
	if oldAvail < 0 {
		oldAvail = 0
	}
	threshold := int(e.amss)
	// rcvBufFraction is the inverse of the fraction of receive buffer size that
	// is used to decide if the available buffer space is now above it.
	const rcvBufFraction = 2
	if wndThreshold := wndFromSpace(e.rcvBufSize / rcvBufFraction); threshold > wndThreshold {
		threshold = wndThreshold
	}
	switch {
	case oldAvail < threshold && newAvail >= threshold:
		return true, true
	case oldAvail >= threshold && newAvail < threshold:
		return true, false
	}
	return false, false
}

// OnReuseAddressSet implements tcpip.SocketOptionsHandler.OnReuseAddressSet.
func (e *endpoint) OnReuseAddressSet(v bool) {
	e.LockUser()
	e.portFlags.TupleOnly = v
	e.UnlockUser()
}

// OnReusePortSet implements tcpip.SocketOptionsHandler.OnReusePortSet.
func (e *endpoint) OnReusePortSet(v bool) {
	e.LockUser()
	e.portFlags.LoadBalanced = v
	e.UnlockUser()
}

// OnKeepAliveSet implements tcpip.SocketOptionsHandler.OnKeepAliveSet.
func (e *endpoint) OnKeepAliveSet(v bool) {
	e.notifyProtocolGoroutine(notifyKeepaliveChanged)
}

// OnDelayOptionSet implements tcpip.SocketOptionsHandler.OnDelayOptionSet.
func (e *endpoint) OnDelayOptionSet(v bool) {
	if !v {
		// Handle delayed data.
		e.sndWaker.Assert()
	}
}

// OnCorkOptionSet implements tcpip.SocketOptionsHandler.OnCorkOptionSet.
func (e *endpoint) OnCorkOptionSet(v bool) {
	if !v {
		// Handle the corked data.
		e.sndWaker.Assert()
	}
}

func (e *endpoint) getSendBufferSize() int {
	sndBufSize, err := e.ops.GetSendBufferSize()
	if err != nil {
		panic(fmt.Sprintf("e.ops.GetSendBufferSize() = %s", err))
	}
	return int(sndBufSize)
}

// SetSockOptInt sets a socket option.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	// Lower 2 bits represents ECN bits. RFC 3168, section 23.1
	const inetECNMask = 3

	switch opt {
	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		e.keepalive.count = v
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case tcpip.IPv4TOSOption:
		e.LockUser()
		// TODO(gvisor.dev/issue/995): ECN is not currently supported,
		// ignore the bits for now.
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.UnlockUser()

	case tcpip.IPv6TrafficClassOption:
		e.LockUser()
		// TODO(gvisor.dev/issue/995): ECN is not currently supported,
		// ignore the bits for now.
		e.sendTOS = uint8(v) & ^uint8(inetECNMask)
		e.UnlockUser()

	case tcpip.MaxSegOption:
		userMSS := v
		if userMSS < header.TCPMinimumMSS || userMSS > header.TCPMaximumMSS {
			return &tcpip.ErrInvalidOptionValue{}
		}
		e.LockUser()
		e.userMSS = uint16(userMSS)
		e.UnlockUser()
		e.notifyProtocolGoroutine(notifyMSSChanged)

	case tcpip.MTUDiscoverOption:
		// Return not supported if attempting to set this option to
		// anything other than path MTU discovery disabled.
		if v != tcpip.PMTUDiscoveryDont {
			return &tcpip.ErrNotSupported{}
		}

	case tcpip.ReceiveBufferSizeOption:
		// Make sure the receive buffer size is within the min and max
		// allowed.
		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err != nil {
			panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %#v) = %s", ProtocolNumber, &rs, err))
		}

		if v > rs.Max {
			v = rs.Max
		}

		if v < math.MaxInt32/SegOverheadFactor {
			v *= SegOverheadFactor
			if v < rs.Min {
				v = rs.Min
			}
		} else {
			v = math.MaxInt32
		}

		e.LockUser()
		e.rcvListMu.Lock()

		// Make sure the receive buffer size allows us to send a
		// non-zero window size.
		scale := uint8(0)
		if e.rcv != nil {
			scale = e.rcv.rcvWndScale
		}
		if v>>scale == 0 {
			v = 1 << scale
		}

		availBefore := wndFromSpace(e.receiveBufferAvailableLocked())
		e.rcvBufSize = v
		availAfter := wndFromSpace(e.receiveBufferAvailableLocked())

		e.rcvAutoParams.disabled = true

		// Immediately send an ACK to uncork the sender silly window
		// syndrome prevetion, when our available space grows above aMSS
		// or half receive buffer, whichever smaller.
		if crossed, above := e.windowCrossedACKThresholdLocked(availAfter - availBefore); crossed && above {
			e.notifyProtocolGoroutine(notifyNonZeroReceiveWindow)
		}

		e.rcvListMu.Unlock()
		e.UnlockUser()

	case tcpip.TTLOption:
		e.LockUser()
		e.ttl = uint8(v)
		e.UnlockUser()

	case tcpip.TCPSynCountOption:
		if v < 1 || v > 255 {
			return &tcpip.ErrInvalidOptionValue{}
		}
		e.LockUser()
		e.maxSynRetries = uint8(v)
		e.UnlockUser()

	case tcpip.TCPWindowClampOption:
		if v == 0 {
			e.LockUser()
			switch e.EndpointState() {
			case StateClose, StateInitial:
				e.windowClamp = 0
				e.UnlockUser()
				return nil
			default:
				e.UnlockUser()
				return &tcpip.ErrInvalidOptionValue{}
			}
		}
		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
			if v < rs.Min/2 {
				v = rs.Min / 2
			}
		}
		e.LockUser()
		e.windowClamp = uint32(v)
		e.UnlockUser()
	}
	return nil
}

func (e *endpoint) HasNIC(id int32) bool {
	return id == 0 || e.stack.HasNIC(tcpip.NICID(id))
}

// SetSockOpt sets a socket option.
func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	switch v := opt.(type) {
	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(*v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(*v)
		e.keepalive.Unlock()
		e.notifyProtocolGoroutine(notifyKeepaliveChanged)

	case *tcpip.TCPUserTimeoutOption:
		e.LockUser()
		e.userTimeout = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.CongestionControlOption:
		// Query the available cc algorithms in the stack and
		// validate that the specified algorithm is actually
		// supported in the stack.
		var avail tcpip.TCPAvailableCongestionControlOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &avail); err != nil {
			return err
		}
		availCC := strings.Split(string(avail), " ")
		for _, cc := range availCC {
			if *v == tcpip.CongestionControlOption(cc) {
				e.LockUser()
				state := e.EndpointState()
				e.cc = *v
				switch state {
				case StateEstablished:
					if e.EndpointState() == state {
						e.snd.cc = e.snd.initCongestionControl(e.cc)
					}
				}
				e.UnlockUser()
				return nil
			}
		}

		// Linux returns ENOENT when an invalid congestion
		// control algorithm is specified.
		return &tcpip.ErrNoSuchFile{}

	case *tcpip.TCPLingerTimeoutOption:
		e.LockUser()

		switch {
		case *v < 0:
			// Same as effectively disabling TCPLinger timeout.
			*v = -1
		case *v == 0:
			// Same as the stack default.
			var stackLingerTimeout tcpip.TCPLingerTimeoutOption
			if err := e.stack.TransportProtocolOption(ProtocolNumber, &stackLingerTimeout); err != nil {
				panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %+v) = %v", ProtocolNumber, &stackLingerTimeout, err))
			}
			*v = stackLingerTimeout
		case *v > tcpip.TCPLingerTimeoutOption(MaxTCPLingerTimeout):
			// Cap it to Stack's default TCP_LINGER2 timeout.
			*v = tcpip.TCPLingerTimeoutOption(MaxTCPLingerTimeout)
		default:
		}

		e.tcpLingerTimeout = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.TCPDeferAcceptOption:
		e.LockUser()
		if time.Duration(*v) > MaxRTO {
			*v = tcpip.TCPDeferAcceptOption(MaxRTO)
		}
		e.deferAccept = time.Duration(*v)
		e.UnlockUser()

	case *tcpip.SocketDetachFilterOption:
		return nil

	default:
		return nil
	}
	return nil
}

// readyReceiveSize returns the number of bytes ready to be received.
func (e *endpoint) readyReceiveSize() (int, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	// The endpoint cannot be in listen state.
	if e.EndpointState() == StateListen {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	e.rcvListMu.Lock()
	defer e.rcvListMu.Unlock()

	return e.rcvBufUsed, nil
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	switch opt {
	case tcpip.KeepaliveCountOption:
		e.keepalive.Lock()
		v := e.keepalive.count
		e.keepalive.Unlock()
		return v, nil

	case tcpip.IPv4TOSOption:
		e.LockUser()
		v := int(e.sendTOS)
		e.UnlockUser()
		return v, nil

	case tcpip.IPv6TrafficClassOption:
		e.LockUser()
		v := int(e.sendTOS)
		e.UnlockUser()
		return v, nil

	case tcpip.MaxSegOption:
		// This is just stubbed out. Linux never returns the user_mss
		// value as it either returns the defaultMSS or returns the
		// actual current MSS. Netstack just returns the defaultMSS
		// always for now.
		v := header.TCPDefaultMSS
		return v, nil

	case tcpip.MTUDiscoverOption:
		// Always return the path MTU discovery disabled setting since
		// it's the only one supported.
		return tcpip.PMTUDiscoveryDont, nil

	case tcpip.ReceiveQueueSizeOption:
		return e.readyReceiveSize()

	case tcpip.ReceiveBufferSizeOption:
		e.rcvListMu.Lock()
		v := e.rcvBufSize
		e.rcvListMu.Unlock()
		return v, nil

	case tcpip.TTLOption:
		e.LockUser()
		v := int(e.ttl)
		e.UnlockUser()
		return v, nil

	case tcpip.TCPSynCountOption:
		e.LockUser()
		v := int(e.maxSynRetries)
		e.UnlockUser()
		return v, nil

	case tcpip.TCPWindowClampOption:
		e.LockUser()
		v := int(e.windowClamp)
		e.UnlockUser()
		return v, nil

	case tcpip.MulticastTTLOption:
		return 1, nil

	default:
		return -1, &tcpip.ErrUnknownProtocolOption{}
	}
}

func (e *endpoint) getTCPInfo() tcpip.TCPInfoOption {
	info := tcpip.TCPInfoOption{}
	e.LockUser()
	snd := e.snd
	if snd != nil {
		// We do not calculate RTT before sending the data packets. If
		// the connection did not send and receive data, then RTT will
		// be zero.
		snd.rtt.Lock()
		info.RTT = snd.rtt.srtt
		info.RTTVar = snd.rtt.rttvar
		snd.rtt.Unlock()

		info.RTO = snd.rto
		info.CcState = snd.state
		info.SndSsthresh = uint32(snd.sndSsthresh)
		info.SndCwnd = uint32(snd.sndCwnd)
		info.ReorderSeen = snd.rc.reorderSeen
	}
	e.UnlockUser()
	return info
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	switch o := opt.(type) {
	case *tcpip.TCPInfoOption:
		*o = e.getTCPInfo()

	case *tcpip.KeepaliveIdleOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIdleOption(e.keepalive.idle)
		e.keepalive.Unlock()

	case *tcpip.KeepaliveIntervalOption:
		e.keepalive.Lock()
		*o = tcpip.KeepaliveIntervalOption(e.keepalive.interval)
		e.keepalive.Unlock()

	case *tcpip.TCPUserTimeoutOption:
		e.LockUser()
		*o = tcpip.TCPUserTimeoutOption(e.userTimeout)
		e.UnlockUser()

	case *tcpip.CongestionControlOption:
		e.LockUser()
		*o = e.cc
		e.UnlockUser()

	case *tcpip.TCPLingerTimeoutOption:
		e.LockUser()
		*o = tcpip.TCPLingerTimeoutOption(e.tcpLingerTimeout)
		e.UnlockUser()

	case *tcpip.TCPDeferAcceptOption:
		e.LockUser()
		*o = tcpip.TCPDeferAcceptOption(e.deferAccept)
		e.UnlockUser()

	case *tcpip.OriginalDestinationOption:
		e.LockUser()
		ipt := e.stack.IPTables()
		addr, port, err := ipt.OriginalDst(e.ID, e.NetProto)
		e.UnlockUser()
		if err != nil {
			return err
		}
		*o = tcpip.OriginalDestinationOption{
			Addr: addr,
			Port: port,
		}

	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
	return nil
}

// checkV4MappedLocked determines the effective network protocol and converts
// addr to its canonical form.
func (e *endpoint) checkV4MappedLocked(addr tcpip.FullAddress) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	unwrapped, netProto, err := e.TransportEndpointInfo.AddrNetProtoLocked(addr, e.ops.GetV6Only())
	if err != nil {
		return tcpip.FullAddress{}, 0, err
	}
	return unwrapped, netProto, nil
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (*endpoint) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Connect connects the endpoint to its peer.
func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	err := e.connect(addr, true, true)
	if err != nil {
		if !err.IgnoreStats() {
			// Connect failed. Let's wake up any waiters.
			e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.EventIn | waiter.EventOut)
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
		}
	}
	return err
}

// connect connects the endpoint to its peer. In the normal non-S/R case, the
// new connection is expected to run the main goroutine and perform handshake.
// In restore of previously connected endpoints, both ends will be passively
// created (so no new handshaking is done); for stack-accepted connections not
// yet accepted by the app, they are restored without running the main goroutine
// here.
func (e *endpoint) connect(addr tcpip.FullAddress, handshake bool, run bool) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()

	connectingAddr := addr.Addr

	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	if e.EndpointState().connected() {
		// The endpoint is already connected. If caller hasn't been
		// notified yet, return success.
		if !e.isConnectNotified {
			e.isConnectNotified = true
			return nil
		}
		// Otherwise return that it's already connected.
		return &tcpip.ErrAlreadyConnected{}
	}

	nicID := addr.NIC
	switch e.EndpointState() {
	case StateBound:
		// If we're already bound to a NIC but the caller is requesting
		// that we use a different one now, we cannot proceed.
		if e.boundNICID == 0 {
			break
		}

		if nicID != 0 && nicID != e.boundNICID {
			return &tcpip.ErrNoRoute{}
		}

		nicID = e.boundNICID

	case StateInitial:
		// Nothing to do. We'll eventually fill-in the gaps in the ID (if any)
		// when we find a route.

	case StateConnecting, StateSynSent, StateSynRecv:
		// A connection request has already been issued but hasn't completed
		// yet.
		return &tcpip.ErrAlreadyConnecting{}

	case StateError:
		if err := e.hardErrorLocked(); err != nil {
			return err
		}
		return &tcpip.ErrConnectionAborted{}

	default:
		return &tcpip.ErrInvalidEndpointState{}
	}

	// Find a route to the desired destination.
	r, err := e.stack.FindRoute(nicID, e.ID.LocalAddress, addr.Addr, netProto, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer r.Release()

	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	e.ID.LocalAddress = r.LocalAddress
	e.ID.RemoteAddress = r.RemoteAddress
	e.ID.RemotePort = addr.Port

	if e.ID.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice)
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

		var twReuse tcpip.TCPTimeWaitReuseOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &twReuse); err != nil {
			panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %#v) = %s", ProtocolNumber, &twReuse, err))
		}

		reuse := twReuse == tcpip.TCPTimeWaitReuseGlobal
		if twReuse == tcpip.TCPTimeWaitReuseLoopbackOnly {
			switch netProto {
			case header.IPv4ProtocolNumber:
				reuse = header.IsV4LoopbackAddress(e.ID.LocalAddress) && header.IsV4LoopbackAddress(e.ID.RemoteAddress)
			case header.IPv6ProtocolNumber:
				reuse = e.ID.LocalAddress == header.IPv6Loopback && e.ID.RemoteAddress == header.IPv6Loopback
			}
		}

		bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
		if _, err := e.stack.PickEphemeralPortStable(portOffset, func(p uint16) (bool, tcpip.Error) {
			if sameAddr && p == e.ID.RemotePort {
				return false, nil
			}
			if _, err := e.stack.ReservePort(netProtos, ProtocolNumber, e.ID.LocalAddress, p, e.portFlags, bindToDevice, addr, nil /* testPort */); err != nil {
				if _, ok := err.(*tcpip.ErrPortInUse); !ok || !reuse {
					return false, nil
				}
				transEPID := e.ID
				transEPID.LocalPort = p
				// Check if an endpoint is registered with demuxer in TIME-WAIT and if
				// we can reuse it. If we can't find a transport endpoint then we just
				// skip using this port as it's possible that either an endpoint has
				// bound the port but not registered with demuxer yet (no listen/connect
				// done yet) or the reservation was freed between the check above and
				// the FindTransportEndpoint below. But rather than retry the same port
				// we just skip it and move on.
				transEP := e.stack.FindTransportEndpoint(netProto, ProtocolNumber, transEPID, r.NICID())
				if transEP == nil {
					// ReservePort failed but there is no registered endpoint with
					// demuxer. Which indicates there is at least some endpoint that has
					// bound the port.
					return false, nil
				}

				tcpEP := transEP.(*endpoint)
				tcpEP.LockUser()
				// If the endpoint is not in TIME-WAIT or if it is in TIME-WAIT but
				// less than 1 second has elapsed since its recentTS was updated then
				// we cannot reuse the port.
				if tcpEP.EndpointState() != StateTimeWait || time.Since(tcpEP.recentTSTime) < 1*time.Second {
					tcpEP.UnlockUser()
					return false, nil
				}
				// Since the endpoint is in TIME-WAIT it should be safe to acquire its
				// Lock while holding the lock for this endpoint as endpoints in
				// TIME-WAIT do not acquire locks on other endpoints.
				tcpEP.workerCleanup = false
				tcpEP.cleanupLocked()
				tcpEP.notifyProtocolGoroutine(notifyAbort)
				tcpEP.UnlockUser()
				// Now try and Reserve again if it fails then we skip.
				if _, err := e.stack.ReservePort(netProtos, ProtocolNumber, e.ID.LocalAddress, p, e.portFlags, bindToDevice, addr, nil /* testPort */); err != nil {
					return false, nil
				}
			}

			id := e.ID
			id.LocalPort = p
			if err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.portFlags, bindToDevice); err != nil {
				e.stack.ReleasePort(netProtos, ProtocolNumber, e.ID.LocalAddress, p, e.portFlags, bindToDevice, addr)
				if _, ok := err.(*tcpip.ErrPortInUse); ok {
					return false, nil
				}
				return false, err
			}

			// Port picking successful. Save the details of
			// the selected port.
			e.ID = id
			e.isPortReserved = true
			e.boundBindToDevice = bindToDevice
			e.boundPortFlags = e.portFlags
			e.boundDest = addr
			return true, nil
		}); err != nil {
			return err
		}
	}

	e.isRegistered = true
	e.setEndpointState(StateConnecting)
	r.Acquire()
	e.route = r
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
				e.sndWaker.Assert()
			}
		}
		e.segmentQueue.mu.Unlock()
		e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		e.setEndpointState(StateEstablished)
	}

	if run {
		if handshake {
			h := e.newHandshake()
			e.setEndpointState(StateSynSent)
			h.start()
		}
		e.stack.Stats().TCP.ActiveConnectionOpenings.Increment()
		e.workerRunning = true
		go e.protocolMainLoop(handshake, nil) // S/R-SAFE: will be drained before save.
	}

	return &tcpip.ErrConnectStarted{}
}

// ConnectEndpoint is not supported.
func (*endpoint) ConnectEndpoint(tcpip.Endpoint) tcpip.Error {
	return &tcpip.ErrInvalidEndpointState{}
}

// Shutdown closes the read and/or write end of the endpoint connection to its
// peer.
func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()
	return e.shutdownLocked(flags)
}

func (e *endpoint) shutdownLocked(flags tcpip.ShutdownFlags) tcpip.Error {
	e.shutdownFlags |= flags
	switch {
	case e.EndpointState().connected():
		// Close for read.
		if e.shutdownFlags&tcpip.ShutdownRead != 0 {
			// Mark read side as closed.
			e.rcvListMu.Lock()
			e.rcvClosed = true
			rcvBufUsed := e.rcvBufUsed
			e.rcvListMu.Unlock()

			// If we're fully closed and we have unread data we need to abort
			// the connection with a RST.
			if e.shutdownFlags&tcpip.ShutdownWrite != 0 && rcvBufUsed > 0 {
				e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
				// Wake up worker to terminate loop.
				e.notifyProtocolGoroutine(notifyTickleWorker)
				return nil
			}
		}

		// Close for write.
		if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
			e.sndBufMu.Lock()
			if e.sndClosed {
				// Already closed.
				e.sndBufMu.Unlock()
				if e.EndpointState() == StateTimeWait {
					return &tcpip.ErrNotConnected{}
				}
				return nil
			}

			// Queue fin segment.
			s := newOutgoingSegment(e.ID, nil)
			e.sndQueue.PushBack(s)
			e.sndBufInQueue++
			// Mark endpoint as closed.
			e.sndClosed = true
			e.sndBufMu.Unlock()
			e.handleClose()
		}

		return nil
	case e.EndpointState() == StateListen:
		if e.shutdownFlags&tcpip.ShutdownRead != 0 {
			// Reset all connections from the accept queue and keep the
			// worker running so that it can continue handling incoming
			// segments by replying with RST.
			//
			// By not removing this endpoint from the demuxer mapping, we
			// ensure that any other bind to the same port fails, as on Linux.
			e.rcvListMu.Lock()
			e.rcvClosed = true
			e.rcvListMu.Unlock()
			e.closePendingAcceptableConnectionsLocked()
			// Notify waiters that the endpoint is shutdown.
			e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut | waiter.EventHUp | waiter.EventErr)
		}
		return nil
	default:
		return &tcpip.ErrNotConnected{}
	}
}

// Listen puts the endpoint in "listen" mode, which allows it to accept
// new connections.
func (e *endpoint) Listen(backlog int) tcpip.Error {
	err := e.listen(backlog)
	if err != nil {
		if !err.IgnoreStats() {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
		}
	}
	return err
}

func (e *endpoint) listen(backlog int) tcpip.Error {
	e.LockUser()
	defer e.UnlockUser()

	if e.EndpointState() == StateListen && !e.closed {
		e.acceptMu.Lock()
		defer e.acceptMu.Unlock()
		if e.acceptedChan == nil {
			// listen is called after shutdown.
			e.acceptedChan = make(chan *endpoint, backlog)
			e.shutdownFlags = 0
			e.rcvListMu.Lock()
			e.rcvClosed = false
			e.rcvListMu.Unlock()
		} else {
			// Adjust the size of the channel iff we can fix
			// existing pending connections into the new one.
			if len(e.acceptedChan) > backlog {
				return &tcpip.ErrInvalidEndpointState{}
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
		}

		// Notify any blocked goroutines that they can attempt to
		// deliver endpoints again.
		e.acceptCond.Broadcast()

		return nil
	}

	if e.EndpointState() == StateInitial {
		// The listen is called on an unbound socket, the socket is
		// automatically bound to a random free port with the local
		// address set to INADDR_ANY.
		if err := e.bindLocked(tcpip.FullAddress{}); err != nil {
			return err
		}
	}

	// Endpoint must be bound before it can transition to listen mode.
	if e.EndpointState() != StateBound {
		e.stats.ReadErrors.InvalidEndpointState.Increment()
		return &tcpip.ErrInvalidEndpointState{}
	}

	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.ID, e, e.boundPortFlags, e.boundBindToDevice); err != nil {
		return err
	}

	e.isRegistered = true
	e.setEndpointState(StateListen)

	// The channel may be non-nil when we're restoring the endpoint, and it
	// may be pre-populated with some previously accepted (but not Accepted)
	// endpoints.
	e.acceptMu.Lock()
	if e.acceptedChan == nil {
		e.acceptedChan = make(chan *endpoint, backlog)
	}
	e.acceptMu.Unlock()

	e.workerRunning = true
	go e.protocolListenLoop( // S/R-SAFE: drained on save.
		seqnum.Size(e.receiveBufferAvailable()))
	return nil
}

// startAcceptedLoop sets up required state and starts a goroutine with the
// main loop for accepted connections.
func (e *endpoint) startAcceptedLoop() {
	e.workerRunning = true
	e.mu.Unlock()
	wakerInitDone := make(chan struct{})
	go e.protocolMainLoop(false, wakerInitDone) // S/R-SAFE: drained on save.
	<-wakerInitDone
}

// Accept returns a new endpoint if a peer has established a connection
// to an endpoint previously set to listen mode.
//
// addr if not-nil will contain the peer address of the returned endpoint.
func (e *endpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	e.rcvListMu.Lock()
	rcvClosed := e.rcvClosed
	e.rcvListMu.Unlock()
	// Endpoint must be in listen state before it can accept connections.
	if rcvClosed || e.EndpointState() != StateListen {
		return nil, nil, &tcpip.ErrInvalidEndpointState{}
	}

	// Get the new accepted endpoint.
	e.acceptMu.Lock()
	defer e.acceptMu.Unlock()
	var n *endpoint
	select {
	case n = <-e.acceptedChan:
		e.acceptCond.Signal()
	default:
		return nil, nil, &tcpip.ErrWouldBlock{}
	}
	if peerAddr != nil {
		*peerAddr = n.getRemoteAddress()
	}
	return n, n.waiterQueue, nil
}

// Bind binds the endpoint to a specific local port and optionally address.
func (e *endpoint) Bind(addr tcpip.FullAddress) (err tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	return e.bindLocked(addr)
}

func (e *endpoint) bindLocked(addr tcpip.FullAddress) (err tcpip.Error) {
	// Don't allow binding once endpoint is not in the initial state
	// anymore. This is because once the endpoint goes into a connected or
	// listen state, it is already bound.
	if e.EndpointState() != StateInitial {
		return &tcpip.ErrAlreadyBound{}
	}

	e.BindAddr = addr.Addr
	addr, netProto, err := e.checkV4MappedLocked(addr)
	if err != nil {
		return err
	}

	netProtos := []tcpip.NetworkProtocolNumber{netProto}

	// Expand netProtos to include v4 and v6 under dual-stack if the caller is
	// binding to a wildcard (empty) address, and this is an IPv6 endpoint with
	// v6only set to false.
	if netProto == header.IPv6ProtocolNumber {
		stackHasV4 := e.stack.CheckNetworkProtocol(header.IPv4ProtocolNumber)
		alsoBindToV4 := !e.ops.GetV6Only() && addr.Addr == "" && stackHasV4
		if alsoBindToV4 {
			netProtos = append(netProtos, header.IPv4ProtocolNumber)
		}
	}

	var nic tcpip.NICID
	// If an address is specified, we must ensure that it's one of our
	// local addresses.
	if len(addr.Addr) != 0 {
		nic = e.stack.CheckLocalAddress(addr.NIC, netProto, addr.Addr)
		if nic == 0 {
			return &tcpip.ErrBadLocalAddress{}
		}
		e.ID.LocalAddress = addr.Addr
	}

	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	port, err := e.stack.ReservePort(netProtos, ProtocolNumber, addr.Addr, addr.Port, e.portFlags, bindToDevice, tcpip.FullAddress{}, func(p uint16) bool {
		id := e.ID
		id.LocalPort = p
		// CheckRegisterTransportEndpoint should only return an error if there is a
		// listening endpoint bound with the same id and portFlags and bindToDevice
		// options.
		//
		// NOTE: Only listening and connected endpoint register with
		// demuxer. Further connected endpoints always have a remote
		// address/port. Hence this will only return an error if there is a matching
		// listening endpoint.
		if err := e.stack.CheckRegisterTransportEndpoint(netProtos, ProtocolNumber, id, e.portFlags, bindToDevice); err != nil {
			return false
		}
		return true
	})
	if err != nil {
		return err
	}

	e.boundBindToDevice = bindToDevice
	e.boundPortFlags = e.portFlags
	// TODO(gvisor.dev/issue/3691): Add test to verify boundNICID is correct.
	e.boundNICID = nic
	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.ID.LocalPort = port

	// Mark endpoint as bound.
	e.setEndpointState(StateBound)

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	return tcpip.FullAddress{
		Addr: e.ID.LocalAddress,
		Port: e.ID.LocalPort,
		NIC:  e.boundNICID,
	}, nil
}

// GetRemoteAddress returns the address to which the endpoint is connected.
func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	if !e.EndpointState().connected() {
		return tcpip.FullAddress{}, &tcpip.ErrNotConnected{}
	}

	return e.getRemoteAddress(), nil
}

func (e *endpoint) getRemoteAddress() tcpip.FullAddress {
	return tcpip.FullAddress{
		Addr: e.ID.RemoteAddress,
		Port: e.ID.RemotePort,
		NIC:  e.boundNICID,
	}
}

func (*endpoint) HandlePacket(stack.TransportEndpointID, *stack.PacketBuffer) {
	// TCP HandlePacket is not required anymore as inbound packets first
	// land at the Dispatcher which then can either deliver using the
	// worker go routine or directly do the invoke the tcp processing inline
	// based on the state of the endpoint.
}

func (e *endpoint) enqueueSegment(s *segment) bool {
	// Send packet to worker goroutine.
	if !e.segmentQueue.enqueue(s) {
		// The queue is full, so we drop the segment.
		e.stack.Stats().DroppedPackets.Increment()
		e.stats.ReceiveErrors.SegmentQueueDropped.Increment()
		return false
	}
	return true
}

func (e *endpoint) onICMPError(err tcpip.Error, errType byte, errCode byte, extra uint32, pkt *stack.PacketBuffer) {
	// Update last error first.
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()

	// Update the error queue if IP_RECVERR is enabled.
	if e.SocketOptions().GetRecvError() {
		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:       err,
			ErrOrigin: header.ICMPOriginFromNetProto(pkt.NetworkProtocolNumber),
			ErrType:   errType,
			ErrCode:   errCode,
			ErrInfo:   extra,
			// Linux passes the payload with the TCP header. We don't know if the TCP
			// header even exists, it may not for fragmented packets.
			Payload: pkt.Data.ToView(),
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.ID.RemoteAddress,
				Port: e.ID.RemotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.ID.LocalAddress,
				Port: e.ID.LocalPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
	}

	// Notify of the error.
	e.notifyProtocolGoroutine(notifyError)
}

// HandleControlPacket implements stack.TransportEndpoint.HandleControlPacket.
func (e *endpoint) HandleControlPacket(typ stack.ControlType, extra uint32, pkt *stack.PacketBuffer) {
	switch typ {
	case stack.ControlPacketTooBig:
		e.sndBufMu.Lock()
		e.packetTooBigCount++
		if v := int(extra); v < e.sndMTU {
			e.sndMTU = v
		}
		e.sndBufMu.Unlock()

		e.notifyProtocolGoroutine(notifyMTUChanged)

	case stack.ControlNoRoute:
		e.onICMPError(&tcpip.ErrNoRoute{}, byte(header.ICMPv4DstUnreachable), byte(header.ICMPv4HostUnreachable), extra, pkt)

	case stack.ControlAddressUnreachable:
		e.onICMPError(&tcpip.ErrNoRoute{}, byte(header.ICMPv6DstUnreachable), byte(header.ICMPv6AddressUnreachable), extra, pkt)

	case stack.ControlNetworkUnreachable:
		e.onICMPError(&tcpip.ErrNetworkUnreachable{}, byte(header.ICMPv6DstUnreachable), byte(header.ICMPv6NetworkUnreachable), extra, pkt)
	}
}

// updateSndBufferUsage is called by the protocol goroutine when room opens up
// in the send buffer. The number of newly available bytes is v.
func (e *endpoint) updateSndBufferUsage(v int) {
	sendBufferSize := e.getSendBufferSize()
	e.sndBufMu.Lock()
	notify := e.sndBufUsed >= sendBufferSize>>1
	e.sndBufUsed -= v
	// We only notify when there is half the sendBufferSize available after
	// a full buffer event occurs. This ensures that we don't wake up
	// writers to queue just 1-2 segments and go back to sleep.
	notify = notify && e.sndBufUsed < int(sendBufferSize)>>1
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
		e.rcvBufUsed += s.payloadSize()
		s.incRef()
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
	memUsed := e.receiveMemUsed()
	if memUsed >= e.rcvBufSize {
		return 0
	}

	return e.rcvBufSize - memUsed
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer based on the actual memory used by all segments held in
// receive buffer/pending and segment queue.
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvListMu.Lock()
	available := e.receiveBufferAvailableLocked()
	e.rcvListMu.Unlock()
	return available
}

// receiveBufferUsed returns the amount of in-use receive buffer.
func (e *endpoint) receiveBufferUsed() int {
	e.rcvListMu.Lock()
	used := e.rcvBufUsed
	e.rcvListMu.Unlock()
	return used
}

// receiveBufferSize returns the current size of the receive buffer.
func (e *endpoint) receiveBufferSize() int {
	e.rcvListMu.Lock()
	size := e.rcvBufSize
	e.rcvListMu.Unlock()
	return size
}

// receiveMemUsed returns the total memory in use by segments held by this
// endpoint.
func (e *endpoint) receiveMemUsed() int {
	return int(atomic.LoadInt32(&e.rcvMemUsed))
}

// updateReceiveMemUsed adds the provided delta to e.rcvMemUsed.
func (e *endpoint) updateReceiveMemUsed(delta int) {
	atomic.AddInt32(&e.rcvMemUsed, int32(delta))
}

// maxReceiveBufferSize returns the stack wide maximum receive buffer size for
// an endpoint.
func (e *endpoint) maxReceiveBufferSize() int {
	var rs tcpip.TCPReceiveBufferSizeRangeOption
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
	if e.sendTSOk && seqnum.Value(e.recentTimestamp()).LessThan(seqnum.Value(tsVal)) && segSeq.LessThanEq(maxSentAck) {
		e.setRecentTimestamp(tsVal)
	}
}

// maybeEnableTimestamp marks the timestamp option enabled for this endpoint if
// the SYN options indicate that timestamp option was negotiated. It also
// initializes the recentTS with the value provided in synOpts.TSval.
func (e *endpoint) maybeEnableTimestamp(synOpts *header.TCPSynOptions) {
	if synOpts.TS {
		e.sendTSOk = true
		e.setRecentTimestamp(synOpts.TSVal)
	}
}

// timestamp returns the timestamp value to be used in the TSVal field of the
// timestamp option for outgoing TCP segments for a given endpoint.
func (e *endpoint) timestamp() uint32 {
	return tcpTimeStamp(time.Now(), e.tsOffset)
}

// tcpTimeStamp returns a timestamp offset by the provided offset. This is
// not inlined above as it's used when SYN cookies are in use and endpoint
// is not created at the time when the SYN cookie is sent.
func tcpTimeStamp(curTime time.Time, offset uint32) uint32 {
	return uint32(curTime.Unix()*1000+int64(curTime.Nanosecond()/1e6)) + offset
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
	var v tcpip.TCPSACKEnabled
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
	s.ID = stack.TCPEndpointID(e.ID)

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
	s.RecentTS = e.recentTimestamp()
	s.TSOffset = e.tsOffset
	s.SACKPermitted = e.sackPermitted
	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])
	s.SACK.ReceivedBlocks, s.SACK.MaxSACKED = e.scoreboard.Copy()

	// Copy endpoint send state.
	sndBufSize := e.getSendBufferSize()
	e.sndBufMu.Lock()
	s.SndBufSize = sndBufSize
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
		SackedOut:        e.snd.sackedOut,
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

	rc := &e.snd.rc
	s.Sender.RACKState = stack.TCPRACKState{
		XmitTime:      rc.xmitTime,
		EndSequence:   rc.endSequence,
		FACK:          rc.fack,
		RTT:           rc.rtt,
		Reord:         rc.reorderSeen,
		DSACKSeen:     rc.dsackSeen,
		ReoWnd:        rc.reoWnd,
		ReoWndIncr:    rc.reoWndIncr,
		ReoWndPersist: rc.reoWndPersist,
		RTTSeq:        rc.rttSeq,
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
	if e.route.HasHardwareGSOCapability() {
		e.initHardwareGSO()
	} else if e.route.HasSoftwareGSOCapability() {
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
	return uint32(e.EndpointState())
}

// Info returns a copy of the endpoint info.
func (e *endpoint) Info() tcpip.EndpointInfo {
	e.LockUser()
	// Make a copy of the endpoint info.
	ret := e.TransportEndpointInfo
	e.UnlockUser()
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
		e.LockUser()
		running := e.workerRunning
		e.UnlockUser()
		if !running {
			break
		}
		<-notifyCh
	}
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (e *endpoint) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

// GetTCPSendBufferLimits is used to get send buffer size limits for TCP.
func GetTCPSendBufferLimits(s tcpip.StackHandler) tcpip.SendBufferSizeOption {
	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err != nil {
		panic(fmt.Sprintf("s.TransportProtocolOption(%d, %#v) = %s", header.TCPProtocolNumber, ss, err))
	}

	return tcpip.SendBufferSizeOption{
		Min:     ss.Min,
		Default: ss.Default,
		Max:     ss.Max,
	}
}
