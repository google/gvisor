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
	"container/heap"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"runtime"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bufferv2"
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
type EndpointState tcpip.EndpointState

// Endpoint states. Note that are represented in a netstack-specific manner and
// may not be meaningful externally. Specifically, they need to be translated to
// Linux's representation for these states if presented to userspace.
const (
	_ EndpointState = iota
	// TCP protocol states in sync with the definitions in
	// https://github.com/torvalds/linux/blob/7acac4b3196/include/net/tcp_states.h#L13
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

	// Endpoint states internal to netstack.
	StateInitial
	StateBound
	StateConnecting // Connect() called, but the initial SYN hasn't been sent.
	StateError
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

// internal returns true when the state is netstack internal.
func (s EndpointState) internal() bool {
	switch s {
	case StateInitial, StateBound, StateConnecting, StateError:
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

// ReceiveErrors collect segment receive errors within transport layer.
//
// +stateify savable
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
	// a zero receive window when rcvQueue is full.
	ZeroRcvWindowState tcpip.StatCounter

	// WantZeroWindow is the number of times we wanted to advertise a
	// zero receive window but couldn't because it would have caused
	// the receive window's right edge to shrink.
	WantZeroRcvWindow tcpip.StatCounter
}

// SendErrors collect segment send errors within the transport layer.
//
// +stateify savable
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
//
// +stateify savable
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

// sndQueueInfo implements a send queue.
//
// +stateify savable
type sndQueueInfo struct {
	sndQueueMu sync.Mutex `state:"nosave"`
	stack.TCPSndBufState

	// sndWaker is used to signal the protocol goroutine when there may be
	// segments that need to be sent.
	sndWaker sleep.Waker `state:"manual"`
}

// CloneState clones sq into other. It is not thread safe
func (sq *sndQueueInfo) CloneState(other *stack.TCPSndBufState) {
	other.SndBufSize = sq.SndBufSize
	other.SndBufUsed = sq.SndBufUsed
	other.SndClosed = sq.SndClosed
	other.PacketTooBigCount = sq.PacketTooBigCount
	other.SndMTU = sq.SndMTU
	other.AutoTuneSndBufDisabled = atomicbitops.FromUint32(sq.AutoTuneSndBufDisabled.RacyLoad())
}

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
// e.acceptMu -> Protects e.acceptQueue.
// e.rcvQueueMu -> Protects e.rcvQueue's associated fields but not e.rcvQueue
// itself.
// e.sndQueueMu -> Protects the e.sndQueue and associated fields.
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
	stack.TCPEndpointStateInner
	stack.TransportEndpointInfo
	tcpip.DefaultSocketOptionsHandler

	// endpointEntry is used to queue endpoints for processing to the
	// a given tcp processor goroutine.
	//
	// Precondition: epQueue.mu must be held to read/write this field..
	endpointEntry `state:"nosave"`

	// pendingProcessingMu protects pendingProcessing.
	pendingProcessingMu sync.Mutex `state:"nosave"`

	// pendingProcessing is true if this endpoint is queued for processing
	// to a TCP processor.
	// +checklocks:pendingProcessingMu
	pendingProcessing bool `state:"nosave"`

	// The following fields are initialized at creation time and do not
	// change throughout the lifetime of the endpoint.
	stack       *stack.Stack  `state:"manual"`
	protocol    *protocol     `state:"manual"`
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

	rcvQueueMu sync.Mutex `state:"nosave"`

	// +checklocks:rcvQueueMu
	stack.TCPRcvBufState

	// rcvMemUsed tracks the total amount of memory in use by received segments
	// held in rcvQueue, pendingRcvdSegments and the segment queue. This is used to
	// compute the window and the actual available buffer space. This is distinct
	// from rcvBufUsed above which is the actual number of payload bytes held in
	// the buffer not including any segment overheads.
	rcvMemUsed atomicbitops.Int32

	// mu protects all endpoint fields unless documented otherwise. mu must
	// be acquired before interacting with the endpoint fields.
	//
	// During handshake, mu is locked by the protocol listen goroutine and
	// released by the handshake completion goroutine.
	mu          sync.CrossGoroutineMutex `state:"nosave"`
	ownedByUser atomicbitops.Uint32

	// rcvQueue is the queue for ready-for-delivery segments.
	//
	// +checklocks:mu
	rcvQueue segmentList `state:"wait"`

	// state must be read/set using the EndpointState()/setEndpointState()
	// methods.
	state atomicbitops.Uint32 `state:".(EndpointState)"`

	// origEndpointState is only used during a restore phase to save the
	// endpoint state at restore time as the socket is moved to it's correct
	// state.
	origEndpointState uint32 `state:"nosave"`

	isPortReserved    bool `state:"manual"`
	isRegistered      bool `state:"manual"`
	boundNICID        tcpip.NICID
	route             *stack.Route `state:"manual"`
	ipv4TTL           uint8
	ipv6HopLimit      int16
	isConnectNotified bool

	// h stores a reference to the current handshake state if the endpoint is in
	// the SYN-SENT or SYN-RECV states, in which case endpoint == endpoint.h.ep.
	// nil otherwise.
	// +checklocks:mu
	h *handshake

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

	// recentTSTime is the unix time when we last updated
	// TCPEndpointStateInner.RecentTS.
	recentTSTime tcpip.MonotonicTime

	// shutdownFlags represent the current shutdown state of the endpoint.
	shutdownFlags tcpip.ShutdownFlags

	// tcpRecovery is the loss recovery algorithm used by TCP.
	tcpRecovery tcpip.TCPRecovery

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

	// sndQueueInfo contains the implementation of the endpoint's send queue.
	sndQueueInfo sndQueueInfo

	// cc stores the name of the Congestion Control algorithm to use for
	// this endpoint.
	cc tcpip.CongestionControlOption

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

	// acceptMu protects accepQueue
	acceptMu sync.Mutex `state:"nosave"`

	// acceptQueue is used by a listening endpoint to send newly accepted
	// connections to the endpoint so that they can be read by Accept()
	// calls.
	//
	// +checklocks:acceptMu
	acceptQueue acceptQueue

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

	gso stack.GSO

	stats Stats

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

	// lastOutOfWindowAckTime is the time at which the an ACK was sent in response
	// to an out of window segment being received by this endpoint.
	lastOutOfWindowAckTime tcpip.MonotonicTime

	// finWait2Timer is used to reap orphaned sockets in FIN-WAIT-2 where the peer
	// is yet to send a FIN but on our end the socket is fully closed i.e. endpoint.Close()
	// has been called on the socket. This timer is not started for sockets that
	// are waiting for a peer FIN but are not closed.
	finWait2Timer tcpip.Timer `state:"nosave"`

	// timeWaitTimer is used to reap a socket once a socket has been in TIME-WAIT state
	// for tcp.DefaultTCPTimeWaitTimeout seconds.
	timeWaitTimer tcpip.Timer `state:"nosave"`

	// listenCtx is used by listening endpoints to store state used while listening for
	// connections. Nil otherwise.
	listenCtx *listenContext `state:"nosave"`
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

// isOwnedByUser() returns true if the endpoint lock is currently
// held by a user(syscall) goroutine.
func (e *endpoint) isOwnedByUser() bool {
	return e.ownedByUser.Load() == 1
}

// LockUser tries to lock e.mu and if it fails it will check if the lock is held
// by another syscall goroutine. If yes, then it will goto sleep waiting for the
// lock to be released, if not then it will spin till it acquires the lock or
// another syscall goroutine acquires it in which case it will goto sleep as
// described above.
//
// The assumption behind spinning here being that background packet processing
// should not be holding the lock for long and spinning reduces latency as we
// avoid an expensive sleep/wakeup of the syscall goroutine).
// +checklocksacquire:e.mu
func (e *endpoint) LockUser() {
	const iterations = 5
	for i := 0; i < iterations; i++ {
		// Try first if the sock is locked then check if it's owned
		// by another user goroutine if not then we spin, otherwise
		// we just go to sleep on the Lock() and wait.
		if !e.TryLock() {
			// If socket is owned by the user then just go to sleep
			// as the lock could be held for a reasonably long time.
			if e.ownedByUser.Load() == 1 {
				e.mu.Lock()
				e.ownedByUser.Store(1)
				return
			}
			// Spin but don't yield the processor since the lower half
			// should yield the lock soon.
			continue
		}
		e.ownedByUser.Store(1)
		return
	}

	for i := 0; i < iterations; i++ {
		// Try first if the sock is locked then check if it's owned
		// by another user goroutine if not then we spin, otherwise
		// we just go to sleep on the Lock() and wait.
		if !e.TryLock() {
			// If socket is owned by the user then just go to sleep
			// as the lock could be held for a reasonably long time.
			if e.ownedByUser.Load() == 1 {
				e.mu.Lock()
				e.ownedByUser.Store(1)
				return
			}
			// Spin but yield the processor since the lower half
			// should yield the lock soon.
			runtime.Gosched()
			continue
		}
		e.ownedByUser.Store(1)
		return
	}

	// Finally just give up and wait for the Lock.
	e.mu.Lock()
	e.ownedByUser.Store(1)
}

// UnlockUser will check if there are any segments already queued for processing
// and wake up a processor goroutine to process them before unlocking e.mu.
// This is required because we when packets arrive and endpoint lock is already
// held then such packets are queued up to be processed.
//
// Precondition: e.LockUser() must have been called before calling e.UnlockUser()
// +checklocksrelease:e.mu
func (e *endpoint) UnlockUser() {
	// Lock segment queue before checking so that we avoid a race where
	// segments can be queued between the time we check if queue is empty
	// and actually unlock the endpoint mutex.
	e.segmentQueue.mu.Lock()
	if e.segmentQueue.emptyLocked() {
		if e.ownedByUser.Swap(0) != 1 {
			panic("e.UnlockUser() called without calling e.LockUser()")
		}
		e.mu.Unlock()
		e.segmentQueue.mu.Unlock()
		return
	}
	e.segmentQueue.mu.Unlock()

	// Since we are waking the processor goroutine here just unlock
	// and let it process the queued segments.
	if e.ownedByUser.Swap(0) != 1 {
		panic("e.UnlockUser() called without calling e.LockUser()")
	}
	processor := e.protocol.dispatcher.selectProcessor(e.ID)
	e.mu.Unlock()

	// Wake up the processor for this endpoint to process any queued
	// segments after releasing the lock to avoid the case where if the
	// processor goroutine starts running before we release the lock here
	// then it will fail to process as TryLock() will fail.
	processor.queueEndpoint(e)
	return
}

// StopWork halts packet processing. Only to be used in tests.
// +checklocksacquire:e.mu
func (e *endpoint) StopWork() {
	e.mu.Lock()
}

// ResumeWork resumes packet processing. Only to be used in tests.
// +checklocksrelease:e.mu
func (e *endpoint) ResumeWork() {
	e.mu.Unlock()
}

// AssertLockHeld forces the checklocks analyzer to consider e.mu held. This is
// used in places where we know that e.mu is held, but checklocks does not,
// which can happen when creating new locked objects. You must pass the known
// locked endpoint to this function and it must be the same as the caller
// endpoint.
// TODO(b/226403629): Remove this function once checklocks understands local
// variable locks.
// +checklocks:locked.mu
// +checklocksacquire:e.mu
func (e *endpoint) AssertLockHeld(locked *endpoint) {
	if e != locked {
		panic("AssertLockHeld failed: locked endpoint != asserting endpoint")
	}
}

// TryLock is a helper that calls TryLock on the endpoint's mutex and
// adds the necessary checklocks annotations.
// TODO(b/226403629): Remove this once checklocks understands TryLock.
// +checklocksacquire:e.mu
func (e *endpoint) TryLock() bool {
	if e.mu.TryLock() {
		return true // +checklocksforce
	}
	return false // +checklocksignore
}

// setEndpointState updates the state of the endpoint to state atomically. This
// method is unexported as the only place we should update the state is in this
// package but we allow the state to be read freely without holding e.mu.
//
// +checklocks:e.mu
func (e *endpoint) setEndpointState(state EndpointState) {
	oldstate := EndpointState(e.state.Swap(uint32(state)))
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
		if oldstate.connected() {
			e.stack.Stats().TCP.CurrentConnected.Decrement()
		}
		fallthrough
	default:
		if oldstate == StateEstablished {
			e.stack.Stats().TCP.CurrentEstablished.Decrement()
		}
	}
}

// EndpointState returns the current state of the endpoint.
func (e *endpoint) EndpointState() EndpointState {
	return EndpointState(e.state.Load())
}

// setRecentTimestamp sets the recentTS field to the provided value.
func (e *endpoint) setRecentTimestamp(recentTS uint32) {
	e.RecentTS = recentTS
	e.recentTSTime = e.stack.Clock().NowMonotonic()
}

// recentTimestamp returns the value of the recentTS field.
func (e *endpoint) recentTimestamp() uint32 {
	return e.RecentTS
}

// TODO(gvisor.dev/issue/6974): Remove once tcp endpoints are composed with a
// network.Endpoint, which also defines this function.
func calculateTTL(route *stack.Route, ipv4TTL uint8, ipv6HopLimit int16) uint8 {
	switch netProto := route.NetProto(); netProto {
	case header.IPv4ProtocolNumber:
		if ipv4TTL == tcpip.UseDefaultIPv4TTL {
			return route.DefaultTTL()
		}
		return ipv4TTL
	case header.IPv6ProtocolNumber:
		if ipv6HopLimit == tcpip.UseDefaultIPv6HopLimit {
			return route.DefaultTTL()
		}
		return uint8(ipv6HopLimit)
	default:
		panic(fmt.Sprintf("invalid protocol number = %d", netProto))
	}
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
	// should never be a zero timer if the endpoint is not closed.
	timer timer       `state:"nosave"`
	waker sleep.Waker `state:"nosave"`
}

func newEndpoint(s *stack.Stack, protocol *protocol, netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) *endpoint {
	e := &endpoint{
		stack:    s,
		protocol: protocol,
		TransportEndpointInfo: stack.TransportEndpointInfo{
			NetProto:   netProto,
			TransProto: header.TCPProtocolNumber,
		},
		sndQueueInfo: sndQueueInfo{
			TCPSndBufState: stack.TCPSndBufState{
				SndMTU: math.MaxInt32,
			},
		},
		waiterQueue: waiterQueue,
		state:       atomicbitops.FromUint32(uint32(StateInitial)),
		keepalive: keepalive{
			idle:     DefaultKeepaliveIdle,
			interval: DefaultKeepaliveInterval,
			count:    DefaultKeepaliveCount,
		},
		uniqueID:      s.UniqueID(),
		ipv4TTL:       tcpip.UseDefaultIPv4TTL,
		ipv6HopLimit:  tcpip.UseDefaultIPv6HopLimit,
		txHash:        s.Rand().Uint32(),
		windowClamp:   DefaultReceiveBufferSize,
		maxSynRetries: DefaultSynRetries,
	}
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits, GetTCPReceiveBufferLimits)
	e.ops.SetMulticastLoop(true)
	e.ops.SetQuickAck(true)
	e.ops.SetSendBufferSize(DefaultSendBufferSize, false /* notify */)
	e.ops.SetReceiveBufferSize(DefaultReceiveBufferSize, false /* notify */)

	var ss tcpip.TCPSendBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
		e.ops.SetSendBufferSize(int64(ss.Default), false /* notify */)
	}

	var rs tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
		e.ops.SetReceiveBufferSize(int64(rs.Default), false /* notify */)
	}

	var cs tcpip.CongestionControlOption
	if err := s.TransportProtocolOption(ProtocolNumber, &cs); err == nil {
		e.cc = cs
	}

	var mrb tcpip.TCPModerateReceiveBufferOption
	if err := s.TransportProtocolOption(ProtocolNumber, &mrb); err == nil {
		e.RcvAutoParams.Disabled = !bool(mrb)
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

	if p := s.GetTCPProbe(); p != nil {
		e.probe = p
	}

	e.segmentQueue.ep = e

	// TODO(https://gvisor.dev/issues/7493): Defer creating the timer until TCP connection becomes
	// established.
	e.keepalive.timer.init(e.stack.Clock(), maybeFailTimerHandler(e, e.keepaliveTimerExpired))

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
		// Check if there's anything in the accepted queue.
		if (mask & waiter.ReadableEvents) != 0 {
			e.acceptMu.Lock()
			if e.acceptQueue.endpoints.Len() != 0 {
				result |= waiter.ReadableEvents
			}
			e.acceptMu.Unlock()
		}
	}
	if e.EndpointState().connected() {
		// Determine if the endpoint is writable if requested.
		if (mask & waiter.WritableEvents) != 0 {
			e.sndQueueInfo.sndQueueMu.Lock()
			sndBufSize := e.getSendBufferSize()
			if e.sndQueueInfo.SndClosed || e.sndQueueInfo.SndBufUsed < sndBufSize {
				result |= waiter.WritableEvents
			}
			e.sndQueueInfo.sndQueueMu.Unlock()
		}

		// Determine if the endpoint is readable if requested.
		if (mask & waiter.ReadableEvents) != 0 {
			e.rcvQueueMu.Lock()
			if e.RcvBufUsed > 0 || e.RcvClosed {
				result |= waiter.ReadableEvents
			}
			e.rcvQueueMu.Unlock()
		}
	}

	return result
}

// Purging pending rcv segments is only necessary on RST.
func (e *endpoint) purgePendingRcvQueue() {
	if e.rcv != nil {
		for e.rcv.pendingRcvdSegments.Len() > 0 {
			s := heap.Pop(&e.rcv.pendingRcvdSegments).(*segment)
			s.DecRef()
		}
	}
}

// +checklocks:e.mu
func (e *endpoint) purgeReadQueue() {
	if e.rcv != nil {
		e.rcvQueueMu.Lock()
		defer e.rcvQueueMu.Unlock()
		for {
			s := e.rcvQueue.Front()
			if s == nil {
				break
			}
			e.rcvQueue.Remove(s)
			s.DecRef()
		}
		e.RcvBufUsed = 0
	}
}

// +checklocks:e.mu
func (e *endpoint) purgeWriteQueue() {
	if e.snd != nil {
		e.sndQueueInfo.sndQueueMu.Lock()
		defer e.sndQueueInfo.sndQueueMu.Unlock()
		e.snd.updateWriteNext(nil)
		for {
			s := e.snd.writeList.Front()
			if s == nil {
				break
			}
			e.snd.writeList.Remove(s)
			s.DecRef()
		}
		e.sndQueueInfo.SndBufUsed = 0
		e.sndQueueInfo.SndClosed = true
	}
}

// Abort implements stack.TransportEndpoint.Abort.
func (e *endpoint) Abort() {
	defer e.drainClosingSegmentQueue()
	e.LockUser()
	defer e.UnlockUser()
	defer e.purgeReadQueue()
	// Reset all connected endpoints.
	switch state := e.EndpointState(); {
	case state.connected():
		e.resetConnectionLocked(&tcpip.ErrAborted{})
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	}
	e.closeLocked()
}

// Close puts the endpoint in a closed state and frees all resources associated
// with it. It must be called only once and with no other concurrent calls to
// the endpoint.
func (e *endpoint) Close() {
	e.LockUser()
	if e.closed {
		e.UnlockUser()
		return
	}

	// We always want to purge the read queue, but do so after the checks in
	// shutdownLocked.
	e.closeLocked()
	e.purgeReadQueue()
	if e.EndpointState() == StateClose || e.EndpointState() == StateError {
		// It should be safe to purge the read queue now as the endpoint
		// is now closed or in an error state and further reads are not
		// permitted.
		e.UnlockUser()
		e.drainClosingSegmentQueue()
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
		return
	}
	e.UnlockUser()
}

// +checklocks:e.mu
func (e *endpoint) closeLocked() {
	linger := e.SocketOptions().GetLinger()
	if linger.Enabled && linger.Timeout == 0 {
		s := e.EndpointState()
		isResetState := s == StateEstablished || s == StateCloseWait || s == StateFinWait1 || s == StateFinWait2 || s == StateSynRecv
		if isResetState {
			// Close the endpoint without doing full shutdown and
			// send a RST.
			e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			return
		}
	}

	// Issue a shutdown so that the peer knows we won't send any more data
	// if we're connected, or stop accepting if we're listening.
	e.shutdownLocked(tcpip.ShutdownWrite | tcpip.ShutdownRead)
	e.closeNoShutdownLocked()
}

// closeNoShutdown closes the endpoint without doing a full shutdown.
// +checklocks:e.mu
func (e *endpoint) closeNoShutdownLocked() {
	// For listening sockets, we always release ports inline so that they
	// are immediately available for reuse after Close() is called. If also
	// registered, we unregister as well otherwise the next user would fail
	// in Listen() when trying to register.
	if e.EndpointState() == StateListen && e.isPortReserved {
		if e.isRegistered {
			e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
			e.isRegistered = false
		}

		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         e.TransportEndpointInfo.ID.LocalAddress,
			Port:         e.TransportEndpointInfo.ID.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		e.stack.ReleasePort(portRes)
		e.isPortReserved = false
		e.boundBindToDevice = 0
		e.boundPortFlags = ports.Flags{}
		e.boundDest = tcpip.FullAddress{}
	}

	// Mark endpoint as closed.
	e.closed = true
	tcpip.AddDanglingEndpoint(e)

	eventMask := waiter.ReadableEvents | waiter.WritableEvents

	switch e.EndpointState() {
	case StateInitial, StateBound, StateListen:
		e.setEndpointState(StateClose)
		fallthrough
	case StateClose, StateError:
		eventMask |= waiter.EventHUp
		e.cleanupLocked()
	case StateConnecting, StateSynSent, StateSynRecv:
		// Abort the handshake and set the error.
		// Notify that the endpoint is closed.
		eventMask |= waiter.EventHUp
		e.handshakeFailed(&tcpip.ErrAborted{})
		// Notify that the endpoint is closed.
		eventMask |= waiter.EventHUp
	case StateFinWait2:
		// The socket has been closed and we are in FIN-WAIT-2 so start
		// the FIN-WAIT-2 timer.
		if e.finWait2Timer == nil {
			e.finWait2Timer = e.stack.Clock().AfterFunc(e.tcpLingerTimeout, e.finWait2TimerExpired)
		}
	}

	e.waiterQueue.Notify(eventMask)
}

// closePendingAcceptableConnections closes all connections that have completed
// handshake but not yet been delivered to the application.
func (e *endpoint) closePendingAcceptableConnectionsLocked() {
	e.acceptMu.Lock()

	pendingEndpoints := e.acceptQueue.pendingEndpoints
	e.acceptQueue.pendingEndpoints = nil

	completedEndpoints := make([]*endpoint, 0, e.acceptQueue.endpoints.Len())
	for n := e.acceptQueue.endpoints.Front(); n != nil; n = n.Next() {
		completedEndpoints = append(completedEndpoints, n.Value.(*endpoint))
	}
	e.acceptQueue.endpoints.Init()
	e.acceptQueue.capacity = 0
	e.acceptMu.Unlock()

	// Close any endpoints in SYN-RCVD state.
	for n := range pendingEndpoints {
		n.Abort()
	}

	// Reset all connections that are waiting to be accepted.
	for _, n := range completedEndpoints {
		n.Abort()
	}
}

// cleanupLocked frees all resources associated with the endpoint.
// +checklocks:e.mu
func (e *endpoint) cleanupLocked() {
	if e.snd != nil {
		e.snd.resendTimer.cleanup()
		e.snd.probeTimer.cleanup()
		e.snd.reorderTimer.cleanup()
	}

	if e.finWait2Timer != nil {
		e.finWait2Timer.Stop()
	}

	if e.timeWaitTimer != nil {
		e.timeWaitTimer.Stop()
	}

	// Close all endpoints that might have been accepted by TCP but not by
	// the client.
	e.closePendingAcceptableConnectionsLocked()
	e.keepalive.timer.cleanup()

	if e.isRegistered {
		e.stack.StartTransportEndpointCleanup(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
		e.isRegistered = false
	}

	if e.isPortReserved {
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         e.TransportEndpointInfo.ID.LocalAddress,
			Port:         e.TransportEndpointInfo.ID.LocalPort,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		e.stack.ReleasePort(portRes)
		e.isPortReserved = false
	}
	e.boundBindToDevice = 0
	e.boundPortFlags = ports.Flags{}
	e.boundDest = tcpip.FullAddress{}

	if e.route != nil {
		e.route.Release()
		e.route = nil
	}

	e.purgeWriteQueue()
	// Only purge the read queue here if the socket is fully closed by the
	// user.
	if e.closed {
		e.purgeReadQueue()
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

	sendNonZeroWindowUpdate := false

	e.rcvQueueMu.Lock()
	if e.RcvAutoParams.Disabled {
		e.rcvQueueMu.Unlock()
		return
	}
	now := e.stack.Clock().NowMonotonic()
	if rtt := e.RcvAutoParams.RTT; rtt == 0 || now.Sub(e.RcvAutoParams.MeasureTime) < rtt {
		e.RcvAutoParams.CopiedBytes += copied
		e.rcvQueueMu.Unlock()
		return
	}
	prevRTTCopied := e.RcvAutoParams.CopiedBytes + copied
	prevCopied := e.RcvAutoParams.PrevCopiedBytes
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
		rcvBufSize := int(e.ops.GetReceiveBufferSize())
		if rcvWnd > rcvBufSize {
			availBefore := wndFromSpace(e.receiveBufferAvailableLocked(rcvBufSize))
			e.ops.SetReceiveBufferSize(int64(rcvWnd), false /* notify */)
			availAfter := wndFromSpace(e.receiveBufferAvailableLocked(rcvWnd))
			if crossed, above := e.windowCrossedACKThresholdLocked(availAfter-availBefore, rcvBufSize); crossed && above {
				sendNonZeroWindowUpdate = true
			}
		}

		// We only update PrevCopiedBytes when we grow the buffer because in cases
		// where PrevCopiedBytes > prevRTTCopied the existing buffer is already big
		// enough to handle the current rate and we don't need to do any
		// adjustments.
		e.RcvAutoParams.PrevCopiedBytes = prevRTTCopied
	}
	e.RcvAutoParams.MeasureTime = now
	e.RcvAutoParams.CopiedBytes = 0
	e.rcvQueueMu.Unlock()

	// Send the update after unlocking rcvQueueMu as sending a segment acquires
	// the lock to calculate the window to be sent.
	if e.EndpointState().connected() && sendNonZeroWindowUpdate {
		e.rcv.nonZeroWindow() // +checklocksforce:e.rcv.ep.mu
	}
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.owner = owner
}

// +checklocks:e.mu
func (e *endpoint) hardErrorLocked() tcpip.Error {
	err := e.hardError
	e.hardError = nil
	return err
}

// +checklocks:e.mu
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

// LastErrorLocked reads and clears lastError.
// Only to be used in tests.
// +checklocks:e.mu
func (e *endpoint) LastErrorLocked() tcpip.Error {
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
	e.LockUser()
	defer e.UnlockUser()

	if err := e.checkReadLocked(); err != nil {
		if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
			e.stats.ReadErrors.ReadClosed.Increment()
		}
		return tcpip.ReadResult{}, err
	}

	var err error
	done := 0
	// N.B. Here we get the first segment to be processed. It is safe to not
	// hold rcvQueueMu when processing, since we hold e.mu to ensure we only
	// remove segments from the list through Read() and that new segments
	// cannot be appended.
	s := e.rcvQueue.Front()
	for s != nil {
		var n int
		n, err = s.ReadTo(dst, opts.Peek)
		// Book keeping first then error handling.
		done += n

		if opts.Peek {
			s = s.Next()
		} else {
			sendNonZeroWindowUpdate := false
			memDelta := 0
			for {
				seg := e.rcvQueue.Front()
				if seg == nil || seg.payloadSize() != 0 {
					break
				}
				e.rcvQueue.Remove(seg)
				// Memory is only considered released when the whole segment has been
				// read.
				memDelta += seg.segMemSize()
				seg.DecRef()
			}
			e.rcvQueueMu.Lock()
			e.RcvBufUsed -= n
			s = e.rcvQueue.Front()

			if memDelta > 0 {
				// If the window was small before this read and if the read freed up
				// enough buffer space, to either fit an aMSS or half a receive buffer
				// (whichever smaller), then notify the protocol goroutine to send a
				// window update.
				if crossed, above := e.windowCrossedACKThresholdLocked(memDelta, int(e.ops.GetReceiveBufferSize())); crossed && above {
					sendNonZeroWindowUpdate = true
				}
			}
			e.rcvQueueMu.Unlock()

			if e.EndpointState().connected() && sendNonZeroWindowUpdate {
				e.rcv.nonZeroWindow() // +checklocksforce:e.rcv.ep.mu
			}
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

// checkRead checks that endpoint is in a readable state.
//
// +checklocks:e.mu
func (e *endpoint) checkReadLocked() tcpip.Error {
	e.rcvQueueMu.Lock()
	defer e.rcvQueueMu.Unlock()
	// When in SYN-SENT state, let the caller block on the receive.
	// An application can initiate a non-blocking connect and then block
	// on a receive. It can expect to read any data after the handshake
	// is complete. RFC793, section 3.9, p58.
	if e.EndpointState() == StateSynSent {
		return &tcpip.ErrWouldBlock{}
	}

	// The endpoint can be read if it's connected, or if it's already closed
	// but has some pending unread data. Also note that a RST being received
	// would cause the state to become StateError so we should allow the
	// reads to proceed before returning a ECONNRESET.
	bufUsed := e.RcvBufUsed
	if s := e.EndpointState(); !s.connected() && s != StateClose && bufUsed == 0 {
		if s == StateError {
			if err := e.hardErrorLocked(); err != nil {
				return err
			}
			return &tcpip.ErrClosedForReceive{}
		}
		e.stats.ReadErrors.NotConnected.Increment()
		return &tcpip.ErrNotConnected{}
	}

	if e.RcvBufUsed == 0 {
		if e.RcvClosed || !e.EndpointState().connected() {
			return &tcpip.ErrClosedForReceive{}
		}
		return &tcpip.ErrWouldBlock{}
	}

	return nil
}

// isEndpointWritableLocked checks if a given endpoint is writable
// and also returns the number of bytes that can be written at this
// moment. If the endpoint is not writable then it returns an error
// indicating the reason why it's not writable.
// +checklocks:e.mu
// +checklocks:e.sndQueueInfo.sndQueueMu
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
	if e.sndQueueInfo.SndClosed {
		return 0, &tcpip.ErrClosedForSend{}
	}

	sndBufSize := e.getSendBufferSize()
	avail := sndBufSize - e.sndQueueInfo.SndBufUsed
	if avail <= 0 {
		return 0, &tcpip.ErrWouldBlock{}
	}
	return avail, nil
}

// readFromPayloader reads a slice from the Payloader.
// +checklocks:e.mu
// +checklocks:e.sndQueueInfo.sndQueueMu
func (e *endpoint) readFromPayloader(p tcpip.Payloader, opts tcpip.WriteOptions, avail int) (bufferv2.Buffer, tcpip.Error) {
	// We can release locks while copying data.
	//
	// This is not possible if atomic is set, because we can't allow the
	// available buffer space to be consumed by some other caller while we
	// are copying data in.
	if !opts.Atomic {
		e.sndQueueInfo.sndQueueMu.Unlock()
		defer e.sndQueueInfo.sndQueueMu.Lock()

		e.UnlockUser()
		defer e.LockUser()
	}

	// Fetch data.
	var payload bufferv2.Buffer
	if l := p.Len(); l < avail {
		avail = l
	}
	if avail == 0 {
		return payload, nil
	}
	if _, err := payload.WriteFromReader(p, int64(avail)); err != nil {
		payload.Release()
		return bufferv2.Buffer{}, &tcpip.ErrBadBuffer{}
	}
	return payload, nil
}

// queueSegment reads data from the payloader and returns a segment to be sent.
// +checklocks:e.mu
func (e *endpoint) queueSegment(p tcpip.Payloader, opts tcpip.WriteOptions) (*segment, int, tcpip.Error) {
	e.sndQueueInfo.sndQueueMu.Lock()
	defer e.sndQueueInfo.sndQueueMu.Unlock()

	avail, err := e.isEndpointWritableLocked()
	if err != nil {
		e.stats.WriteErrors.WriteClosed.Increment()
		return nil, 0, err
	}

	buf, err := e.readFromPayloader(p, opts, avail)
	if err != nil {
		return nil, 0, err
	}

	// Do not queue zero length segments.
	if buf.Size() == 0 {
		return nil, 0, nil
	}

	if !opts.Atomic {
		// Since we released locks in between it's possible that the
		// endpoint transitioned to a CLOSED/ERROR states so make
		// sure endpoint is still writable before trying to write.
		avail, err := e.isEndpointWritableLocked()
		if err != nil {
			e.stats.WriteErrors.WriteClosed.Increment()
			buf.Release()
			return nil, 0, err
		}

		// A simultaneous call to write on the socket can reduce avail. Discard
		// excess data copied if this is the case.
		if int64(avail) < buf.Size() {
			buf.Truncate(int64(avail))
		}
	}

	// Add data to the send queue.
	size := int(buf.Size())
	s := newOutgoingSegment(e.TransportEndpointInfo.ID, e.stack.Clock(), buf)
	e.sndQueueInfo.SndBufUsed += size
	s.IncRef()
	e.snd.writeList.PushBack(s)

	return s, size, nil
}

// Write writes data to the endpoint's peer.
func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	// Linux completely ignores any address passed to sendto(2) for TCP sockets
	// (without the MSG_FASTOPEN flag). Corking is unimplemented, so opts.More
	// and opts.EndOfRecord are also ignored.

	e.LockUser()
	defer e.UnlockUser()

	// Return if either we didn't queue anything or if an error occurred while
	// attempting to queue data.
	nextSeg, n, err := e.queueSegment(p, opts)
	if nextSeg != nil {
		defer nextSeg.DecRef()
	}
	if n == 0 || err != nil {
		return 0, err
	}

	e.sendData(nextSeg)
	return int64(n), nil
}

// selectWindowLocked returns the new window without checking for shrinking or scaling
// applied.
// +checklocks:e.mu
// +checklocks:e.rcvQueueMu
func (e *endpoint) selectWindowLocked(rcvBufSize int) (wnd seqnum.Size) {
	wndFromAvailable := wndFromSpace(e.receiveBufferAvailableLocked(rcvBufSize))
	maxWindow := wndFromSpace(rcvBufSize)
	wndFromUsedBytes := maxWindow - e.RcvBufUsed

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

// selectWindow invokes selectWindowLocked after acquiring e.rcvQueueMu.
// +checklocks:e.mu
func (e *endpoint) selectWindow() (wnd seqnum.Size) {
	e.rcvQueueMu.Lock()
	wnd = e.selectWindowLocked(int(e.ops.GetReceiveBufferSize()))
	e.rcvQueueMu.Unlock()
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
// receive buffer size. This is chosen arbitrarily.
// crossed will be true if the window size crossed the ACK threshold.
// above will be true if the new window is >= ACK threshold and false
// otherwise.
//
// +checklocks:e.mu
// +checklocks:e.rcvQueueMu
func (e *endpoint) windowCrossedACKThresholdLocked(deltaBefore int, rcvBufSize int) (crossed bool, above bool) {
	newAvail := int(e.selectWindowLocked(rcvBufSize))
	oldAvail := newAvail - deltaBefore
	if oldAvail < 0 {
		oldAvail = 0
	}
	threshold := int(e.amss)
	// rcvBufFraction is the inverse of the fraction of receive buffer size that
	// is used to decide if the available buffer space is now above it.
	const rcvBufFraction = 2
	if wndThreshold := wndFromSpace(rcvBufSize / rcvBufFraction); threshold > wndThreshold {
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
func (e *endpoint) OnKeepAliveSet(bool) {
	e.LockUser()
	e.resetKeepaliveTimer(true /* receivedData */)
	e.UnlockUser()
}

// OnDelayOptionSet implements tcpip.SocketOptionsHandler.OnDelayOptionSet.
func (e *endpoint) OnDelayOptionSet(v bool) {
	if !v {
		e.LockUser()
		defer e.UnlockUser()
		// Handle delayed data.
		if e.EndpointState().connected() {
			e.sendData(nil /* next */)
		}
	}
}

// OnCorkOptionSet implements tcpip.SocketOptionsHandler.OnCorkOptionSet.
func (e *endpoint) OnCorkOptionSet(v bool) {
	if !v {
		e.LockUser()
		defer e.UnlockUser()
		// Handle the corked data.
		if e.EndpointState().connected() {
			e.sendData(nil /* next */)
		}
	}
}

func (e *endpoint) getSendBufferSize() int {
	return int(e.ops.GetSendBufferSize())
}

// OnSetReceiveBufferSize implements tcpip.SocketOptionsHandler.OnSetReceiveBufferSize.
func (e *endpoint) OnSetReceiveBufferSize(rcvBufSz, oldSz int64) (newSz int64, postSet func()) {
	e.LockUser()

	sendNonZeroWindowUpdate := false
	e.rcvQueueMu.Lock()

	// Make sure the receive buffer size allows us to send a
	// non-zero window size.
	scale := uint8(0)
	if e.rcv != nil {
		scale = e.rcv.RcvWndScale
	}
	if rcvBufSz>>scale == 0 {
		rcvBufSz = 1 << scale
	}

	availBefore := wndFromSpace(e.receiveBufferAvailableLocked(int(oldSz)))
	availAfter := wndFromSpace(e.receiveBufferAvailableLocked(int(rcvBufSz)))
	e.RcvAutoParams.Disabled = true

	// Immediately send an ACK to uncork the sender silly window
	// syndrome prevetion, when our available space grows above aMSS
	// or half receive buffer, whichever smaller.
	if crossed, above := e.windowCrossedACKThresholdLocked(availAfter-availBefore, int(rcvBufSz)); crossed && above {
		sendNonZeroWindowUpdate = true
	}

	e.rcvQueueMu.Unlock()

	postSet = func() {
		e.LockUser()
		defer e.UnlockUser()
		if e.EndpointState().connected() && sendNonZeroWindowUpdate {
			e.rcv.nonZeroWindow() // +checklocksforce:e.rcv.ep.mu
		}

	}
	e.UnlockUser()
	return rcvBufSz, postSet
}

// OnSetSendBufferSize implements tcpip.SocketOptionsHandler.OnSetSendBufferSize.
func (e *endpoint) OnSetSendBufferSize(sz int64) int64 {
	e.sndQueueInfo.TCPSndBufState.AutoTuneSndBufDisabled.Store(1)
	return sz
}

// WakeupWriters implements tcpip.SocketOptionsHandler.WakeupWriters.
func (e *endpoint) WakeupWriters() {
	e.LockUser()
	defer e.UnlockUser()

	sendBufferSize := e.getSendBufferSize()
	e.sndQueueInfo.sndQueueMu.Lock()
	notify := (sendBufferSize - e.sndQueueInfo.SndBufUsed) >= e.sndQueueInfo.SndBufUsed>>1
	e.sndQueueInfo.sndQueueMu.Unlock()

	if notify {
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

// SetSockOptInt sets a socket option.
func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	// Lower 2 bits represents ECN bits. RFC 3168, section 23.1
	const inetECNMask = 3

	switch opt {
	case tcpip.KeepaliveCountOption:
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.count = v
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true /* receivedData */)
		e.UnlockUser()

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

	case tcpip.MTUDiscoverOption:
		// Return not supported if attempting to set this option to
		// anything other than path MTU discovery disabled.
		if v != tcpip.PMTUDiscoveryDont {
			return &tcpip.ErrNotSupported{}
		}

	case tcpip.IPv4TTLOption:
		e.LockUser()
		e.ipv4TTL = uint8(v)
		e.UnlockUser()

	case tcpip.IPv6HopLimitOption:
		e.LockUser()
		e.ipv6HopLimit = int16(v)
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
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.idle = time.Duration(*v)
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true /* receivedData */)
		e.UnlockUser()

	case *tcpip.KeepaliveIntervalOption:
		e.LockUser()
		e.keepalive.Lock()
		e.keepalive.interval = time.Duration(*v)
		e.keepalive.Unlock()
		e.resetKeepaliveTimer(true /* receivedData */)
		e.UnlockUser()

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

	e.rcvQueueMu.Lock()
	defer e.rcvQueueMu.Unlock()

	return e.RcvBufUsed, nil
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

	case tcpip.IPv4TTLOption:
		e.LockUser()
		v := int(e.ipv4TTL)
		e.UnlockUser()
		return v, nil

	case tcpip.IPv6HopLimitOption:
		e.LockUser()
		v := int(e.ipv6HopLimit)
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
	if state := e.EndpointState(); state.internal() {
		info.State = tcpip.EndpointState(StateClose)
	} else {
		info.State = tcpip.EndpointState(state)
	}
	snd := e.snd
	if snd != nil {
		// We do not calculate RTT before sending the data packets. If
		// the connection did not send and receive data, then RTT will
		// be zero.
		snd.rtt.Lock()
		info.RTT = snd.rtt.TCPRTTState.SRTT
		info.RTTVar = snd.rtt.TCPRTTState.RTTVar
		snd.rtt.Unlock()

		info.RTO = snd.RTO
		info.CcState = snd.state
		info.SndSsthresh = uint32(snd.Ssthresh)
		info.SndCwnd = uint32(snd.SndCwnd)
		info.ReorderSeen = snd.rc.Reord
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
		addr, port, err := ipt.OriginalDst(e.TransportEndpointInfo.ID, e.NetProto, ProtocolNumber)
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
// +checklocks:e.mu
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
	e.LockUser()
	defer e.UnlockUser()
	err := e.connect(addr, true)
	if err != nil {
		if !err.IgnoreStats() {
			// Connect failed. Let's wake up any waiters.
			e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			e.stats.FailedConnectionAttempts.Increment()
		}
	}
	return err
}

// registerEndpoint registers the endpoint with the provided address.
//
// +checklocks:e.mu
func (e *endpoint) registerEndpoint(addr tcpip.FullAddress, netProto tcpip.NetworkProtocolNumber, nicID tcpip.NICID) tcpip.Error {
	netProtos := []tcpip.NetworkProtocolNumber{netProto}
	if e.TransportEndpointInfo.ID.LocalPort != 0 {
		// The endpoint is bound to a port, attempt to register it.
		err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice)
		if err != nil {
			return err
		}
	} else {
		// The endpoint doesn't have a local port yet, so try to get
		// one. Make sure that it isn't one that will result in the same
		// address/port for both local and remote (otherwise this
		// endpoint would be trying to connect to itself).
		sameAddr := e.TransportEndpointInfo.ID.LocalAddress == e.TransportEndpointInfo.ID.RemoteAddress

		// Calculate a port offset based on the destination IP/port and
		// src IP to ensure that for a given tuple (srcIP, destIP,
		// destPort) the offset used as a starting point is the same to
		// ensure that we can cycle through the port space effectively.
		portBuf := make([]byte, 2)
		binary.LittleEndian.PutUint16(portBuf, e.ID.RemotePort)

		h := jenkins.Sum32(e.protocol.portOffsetSecret)
		for _, s := range [][]byte{
			[]byte(e.ID.LocalAddress),
			[]byte(e.ID.RemoteAddress),
			portBuf,
		} {
			// Per io.Writer.Write:
			//
			// Write must return a non-nil error if it returns n < len(p).
			if _, err := h.Write(s); err != nil {
				panic(err)
			}
		}
		portOffset := h.Sum32()

		var twReuse tcpip.TCPTimeWaitReuseOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &twReuse); err != nil {
			panic(fmt.Sprintf("e.stack.TransportProtocolOption(%d, %#v) = %s", ProtocolNumber, &twReuse, err))
		}

		reuse := twReuse == tcpip.TCPTimeWaitReuseGlobal
		if twReuse == tcpip.TCPTimeWaitReuseLoopbackOnly {
			switch netProto {
			case header.IPv4ProtocolNumber:
				reuse = header.IsV4LoopbackAddress(e.TransportEndpointInfo.ID.LocalAddress) && header.IsV4LoopbackAddress(e.TransportEndpointInfo.ID.RemoteAddress)
			case header.IPv6ProtocolNumber:
				reuse = e.TransportEndpointInfo.ID.LocalAddress == header.IPv6Loopback && e.TransportEndpointInfo.ID.RemoteAddress == header.IPv6Loopback
			}
		}

		bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
		if _, err := e.stack.PickEphemeralPortStable(portOffset, func(p uint16) (bool, tcpip.Error) {
			if sameAddr && p == e.TransportEndpointInfo.ID.RemotePort {
				return false, nil
			}
			portRes := ports.Reservation{
				Networks:     netProtos,
				Transport:    ProtocolNumber,
				Addr:         e.TransportEndpointInfo.ID.LocalAddress,
				Port:         p,
				Flags:        e.portFlags,
				BindToDevice: bindToDevice,
				Dest:         addr,
			}
			if _, err := e.stack.ReservePort(e.stack.Rand(), portRes, nil /* testPort */); err != nil {
				if _, ok := err.(*tcpip.ErrPortInUse); !ok || !reuse {
					return false, nil
				}
				transEPID := e.TransportEndpointInfo.ID
				transEPID.LocalPort = p
				// Check if an endpoint is registered with demuxer in TIME-WAIT and if
				// we can reuse it. If we can't find a transport endpoint then we just
				// skip using this port as it's possible that either an endpoint has
				// bound the port but not registered with demuxer yet (no listen/connect
				// done yet) or the reservation was freed between the check above and
				// the FindTransportEndpoint below. But rather than retry the same port
				// we just skip it and move on.
				transEP := e.stack.FindTransportEndpoint(netProto, ProtocolNumber, transEPID, nicID)
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
				if tcpEP.EndpointState() != StateTimeWait || e.stack.Clock().NowMonotonic().Sub(tcpEP.recentTSTime) < 1*time.Second {
					tcpEP.UnlockUser()
					return false, nil
				}
				// Since the endpoint is in TIME-WAIT it should be safe to acquire its
				// Lock while holding the lock for this endpoint as endpoints in
				// TIME-WAIT do not acquire locks on other endpoints.
				tcpEP.transitionToStateCloseLocked()
				tcpEP.drainClosingSegmentQueue()
				tcpEP.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
				tcpEP.UnlockUser()
				// Now try and Reserve again if it fails then we skip.
				portRes := ports.Reservation{
					Networks:     netProtos,
					Transport:    ProtocolNumber,
					Addr:         e.TransportEndpointInfo.ID.LocalAddress,
					Port:         p,
					Flags:        e.portFlags,
					BindToDevice: bindToDevice,
					Dest:         addr,
				}
				if _, err := e.stack.ReservePort(e.stack.Rand(), portRes, nil /* testPort */); err != nil {
					return false, nil
				}
			}

			id := e.TransportEndpointInfo.ID
			id.LocalPort = p
			if err := e.stack.RegisterTransportEndpoint(netProtos, ProtocolNumber, id, e, e.portFlags, bindToDevice); err != nil {
				portRes := ports.Reservation{
					Networks:     netProtos,
					Transport:    ProtocolNumber,
					Addr:         e.TransportEndpointInfo.ID.LocalAddress,
					Port:         p,
					Flags:        e.portFlags,
					BindToDevice: bindToDevice,
					Dest:         addr,
				}
				e.stack.ReleasePort(portRes)
				if _, ok := err.(*tcpip.ErrPortInUse); ok {
					return false, nil
				}
				return false, err
			}

			// Port picking successful. Save the details of
			// the selected port.
			e.TransportEndpointInfo.ID = id
			e.isPortReserved = true
			e.boundBindToDevice = bindToDevice
			e.boundPortFlags = e.portFlags
			e.boundDest = addr
			return true, nil
		}); err != nil {
			e.stack.Stats().TCP.FailedPortReservations.Increment()
			return err
		}
	}
	return nil
}

// connect connects the endpoint to its peer.
// +checklocks:e.mu
func (e *endpoint) connect(addr tcpip.FullAddress, handshake bool) tcpip.Error {
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
			return &tcpip.ErrHostUnreachable{}
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
	r, err := e.stack.FindRoute(nicID, e.TransportEndpointInfo.ID.LocalAddress, addr.Addr, netProto, false /* multicastLoop */)
	if err != nil {
		return err
	}
	defer r.Release()

	e.TransportEndpointInfo.ID.LocalAddress = r.LocalAddress()
	e.TransportEndpointInfo.ID.RemoteAddress = r.RemoteAddress()
	e.TransportEndpointInfo.ID.RemotePort = addr.Port

	oldState := e.EndpointState()
	e.setEndpointState(StateConnecting)
	if err := e.registerEndpoint(addr, netProto, r.NICID()); err != nil {
		e.setEndpointState(oldState)
		return err
	}

	e.isRegistered = true
	r.Acquire()
	e.route = r
	e.boundNICID = nicID
	e.effectiveNetProtos = []tcpip.NetworkProtocolNumber{netProto}
	e.connectingAddress = connectingAddr

	e.initGSO()

	// Connect in the restore phase does not perform handshake. Restore its
	// connection setting here.
	if !handshake {
		e.segmentQueue.mu.Lock()
		for _, l := range []segmentList{e.segmentQueue.list, e.snd.writeList} {
			for s := l.Front(); s != nil; s = s.Next() {
				s.id = e.TransportEndpointInfo.ID
				e.sndQueueInfo.sndWaker.Assert()
			}
		}
		e.segmentQueue.mu.Unlock()
		e.snd.ep.AssertLockHeld(e)
		e.snd.updateMaxPayloadSize(int(e.route.MTU()), 0)
		e.setEndpointState(StateEstablished)
		// Set the new auto tuned send buffer size after entering
		// established state.
		e.ops.SetSendBufferSize(e.computeTCPSendBufferSize(), false /* notify */)
		return &tcpip.ErrConnectStarted{}
	}

	// Start a new handshake.
	h := e.newHandshake()
	e.setEndpointState(StateSynSent)
	h.start()
	e.stack.Stats().TCP.ActiveConnectionOpenings.Increment()

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

	if e.EndpointState().connecting() {
		// When calling shutdown(2) on a connecting socket, the endpoint must
		// enter the error state. But this logic cannot belong to the shutdownLocked
		// method because that method is called during a close(2) (and closing a
		// connecting socket is not an error).
		e.handshakeFailed(&tcpip.ErrConnectionReset{})
		e.waiterQueue.Notify(waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
		return nil
	}

	return e.shutdownLocked(flags)
}

// +checklocks:e.mu
func (e *endpoint) shutdownLocked(flags tcpip.ShutdownFlags) tcpip.Error {
	e.shutdownFlags |= flags
	switch {
	case e.EndpointState().connected():
		// Close for read.
		if e.shutdownFlags&tcpip.ShutdownRead != 0 {
			// Mark read side as closed.
			e.rcvQueueMu.Lock()
			e.RcvClosed = true
			rcvBufUsed := e.RcvBufUsed
			e.rcvQueueMu.Unlock()
			// If we're fully closed and we have unread data we need to abort
			// the connection with a RST.
			if e.shutdownFlags&tcpip.ShutdownWrite != 0 && rcvBufUsed > 0 {
				e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
				return nil
			}
			// Wake up any readers that maybe waiting for the stream to become
			// readable.
			e.waiterQueue.Notify(waiter.ReadableEvents)
		}

		// Close for write.
		if e.shutdownFlags&tcpip.ShutdownWrite != 0 {
			e.sndQueueInfo.sndQueueMu.Lock()
			if e.sndQueueInfo.SndClosed {
				// Already closed.
				e.sndQueueInfo.sndQueueMu.Unlock()
				if e.EndpointState() == StateTimeWait {
					return &tcpip.ErrNotConnected{}
				}
				return nil
			}

			// Queue fin segment.
			s := newOutgoingSegment(e.TransportEndpointInfo.ID, e.stack.Clock(), bufferv2.Buffer{})
			e.snd.writeList.PushBack(s)
			// Mark endpoint as closed.
			e.sndQueueInfo.SndClosed = true
			e.sndQueueInfo.sndQueueMu.Unlock()

			// Drain the send queue.
			e.sendData(s)

			// Mark send side as closed.
			e.snd.Closed = true

			// Wake up any writers that maybe waiting for the stream to become
			// writable.
			e.waiterQueue.Notify(waiter.WritableEvents)
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
			e.rcvQueueMu.Lock()
			e.RcvClosed = true
			e.rcvQueueMu.Unlock()
			e.closePendingAcceptableConnectionsLocked()
			// Notify waiters that the endpoint is shutdown.
			e.waiterQueue.Notify(waiter.ReadableEvents | waiter.WritableEvents | waiter.EventHUp | waiter.EventErr)
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

		// Adjust the size of the backlog iff we can fit
		// existing pending connections into the new one.
		if e.acceptQueue.endpoints.Len() > backlog {
			return &tcpip.ErrInvalidEndpointState{}
		}
		e.acceptQueue.capacity = backlog

		if e.acceptQueue.pendingEndpoints == nil {
			e.acceptQueue.pendingEndpoints = make(map[*endpoint]struct{})
		}

		e.shutdownFlags = 0
		e.rcvQueueMu.Lock()
		e.RcvClosed = false
		e.rcvQueueMu.Unlock()

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

	// Setting this state after RegisterTransportEndpoint will result in a
	// race where the endpoint is in Bound but reachable via the demuxer. Instead
	// we set it to listen so that incoming packets will just be queued to the
	// inbound segment queue by the TCP processor.
	e.setEndpointState(StateListen)
	// Register the endpoint.
	if err := e.stack.RegisterTransportEndpoint(e.effectiveNetProtos, ProtocolNumber, e.TransportEndpointInfo.ID, e, e.boundPortFlags, e.boundBindToDevice); err != nil {
		e.transitionToStateCloseLocked()
		return err
	}

	e.isRegistered = true

	// The queue may be non-zero when we're restoring the endpoint, and it
	// may be pre-populated with some previously accepted (but not Accepted)
	// endpoints.
	e.acceptMu.Lock()
	if e.acceptQueue.pendingEndpoints == nil {
		e.acceptQueue.pendingEndpoints = make(map[*endpoint]struct{})
	}
	if e.acceptQueue.capacity == 0 {
		e.acceptQueue.capacity = backlog
	}
	e.acceptMu.Unlock()

	// Initialize the listening context.
	rcvWnd := seqnum.Size(e.receiveBufferAvailable())
	e.listenCtx = newListenContext(e.stack, e.protocol, e, rcvWnd, e.ops.GetV6Only(), e.NetProto)

	return nil
}

// Accept returns a new endpoint if a peer has established a connection
// to an endpoint previously set to listen mode.
//
// addr if not-nil will contain the peer address of the returned endpoint.
func (e *endpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	e.rcvQueueMu.Lock()
	rcvClosed := e.RcvClosed
	e.rcvQueueMu.Unlock()
	// Endpoint must be in listen state before it can accept connections.
	if rcvClosed || e.EndpointState() != StateListen {
		return nil, nil, &tcpip.ErrInvalidEndpointState{}
	}

	// Get the new accepted endpoint.
	var n *endpoint
	e.acceptMu.Lock()
	if element := e.acceptQueue.endpoints.Front(); element != nil {
		n = e.acceptQueue.endpoints.Remove(element).(*endpoint)
	}
	e.acceptMu.Unlock()
	if n == nil {
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

// +checklocks:e.mu
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
		e.TransportEndpointInfo.ID.LocalAddress = addr.Addr
	}

	bindToDevice := tcpip.NICID(e.ops.GetBindToDevice())
	portRes := ports.Reservation{
		Networks:     netProtos,
		Transport:    ProtocolNumber,
		Addr:         addr.Addr,
		Port:         addr.Port,
		Flags:        e.portFlags,
		BindToDevice: bindToDevice,
		Dest:         tcpip.FullAddress{},
	}
	port, err := e.stack.ReservePort(e.stack.Rand(), portRes, func(p uint16) (bool, tcpip.Error) {
		id := e.TransportEndpointInfo.ID
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
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		e.stack.Stats().TCP.FailedPortReservations.Increment()
		return err
	}

	e.boundBindToDevice = bindToDevice
	e.boundPortFlags = e.portFlags
	// TODO(gvisor.dev/issue/3691): Add test to verify boundNICID is correct.
	e.boundNICID = nic
	e.isPortReserved = true
	e.effectiveNetProtos = netProtos
	e.TransportEndpointInfo.ID.LocalPort = port

	// Mark endpoint as bound.
	e.setEndpointState(StateBound)

	return nil
}

// GetLocalAddress returns the address to which the endpoint is bound.
func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	e.LockUser()
	defer e.UnlockUser()

	return tcpip.FullAddress{
		Addr: e.TransportEndpointInfo.ID.LocalAddress,
		Port: e.TransportEndpointInfo.ID.LocalPort,
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
		Addr: e.TransportEndpointInfo.ID.RemoteAddress,
		Port: e.TransportEndpointInfo.ID.RemotePort,
		NIC:  e.boundNICID,
	}
}

func (*endpoint) HandlePacket(stack.TransportEndpointID, stack.PacketBufferPtr) {
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

func (e *endpoint) onICMPError(err tcpip.Error, transErr stack.TransportError, pkt stack.PacketBufferPtr) {
	// Update last error first.
	e.lastErrorMu.Lock()
	e.lastError = err
	e.lastErrorMu.Unlock()

	var recvErr bool
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		recvErr = e.SocketOptions().GetIPv4RecvError()
	case header.IPv6ProtocolNumber:
		recvErr = e.SocketOptions().GetIPv6RecvError()
	default:
		panic(fmt.Sprintf("unhandled network protocol number = %d", pkt.NetworkProtocolNumber))
	}

	if recvErr {
		e.SocketOptions().QueueErr(&tcpip.SockError{
			Err:   err,
			Cause: transErr,
			// Linux passes the payload with the TCP header. We don't know if the TCP
			// header even exists, it may not for fragmented packets.
			Payload: pkt.Data().AsRange().ToView(),
			Dst: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.TransportEndpointInfo.ID.RemoteAddress,
				Port: e.TransportEndpointInfo.ID.RemotePort,
			},
			Offender: tcpip.FullAddress{
				NIC:  pkt.NICID,
				Addr: e.TransportEndpointInfo.ID.LocalAddress,
				Port: e.TransportEndpointInfo.ID.LocalPort,
			},
			NetProto: pkt.NetworkProtocolNumber,
		})
	}

	if e.EndpointState().connecting() {
		e.mu.Lock()
		if lEP := e.h.listenEP; lEP != nil {
			// Remove from listening endpoints pending list.
			lEP.acceptMu.Lock()
			delete(lEP.acceptQueue.pendingEndpoints, e)
			lEP.acceptMu.Unlock()
			lEP.stats.FailedConnectionAttempts.Increment()
		}
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		e.cleanupLocked()
		e.hardError = err
		e.setEndpointState(StateError)
		e.mu.Unlock()
		e.drainClosingSegmentQueue()
		e.waiterQueue.Notify(waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents)
	}
}

// HandleError implements stack.TransportEndpoint.
func (e *endpoint) HandleError(transErr stack.TransportError, pkt stack.PacketBufferPtr) {
	handlePacketTooBig := func(mtu uint32) {
		e.sndQueueInfo.sndQueueMu.Lock()
		update := false
		if v := int(mtu); v < e.sndQueueInfo.SndMTU {
			e.sndQueueInfo.SndMTU = v
			update = true
		}
		newMTU := e.sndQueueInfo.SndMTU
		e.sndQueueInfo.sndQueueMu.Unlock()
		if update {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.snd != nil {
				e.snd.updateMaxPayloadSize(newMTU, 1 /* count */) // +checklocksforce:e.snd.ep.mu
			}
		}
	}

	// TODO(gvisor.dev/issues/5270): Handle all transport errors.
	switch transErr.Kind() {
	case stack.PacketTooBigTransportError:
		handlePacketTooBig(transErr.Info())
	case stack.DestinationHostUnreachableTransportError:
		e.onICMPError(&tcpip.ErrHostUnreachable{}, transErr, pkt)
	case stack.DestinationNetworkUnreachableTransportError:
		e.onICMPError(&tcpip.ErrNetworkUnreachable{}, transErr, pkt)
	case stack.DestinationPortUnreachableTransportError:
		e.onICMPError(&tcpip.ErrConnectionRefused{}, transErr, pkt)
	case stack.DestinationProtoUnreachableTransportError:
		e.onICMPError(&tcpip.ErrUnknownProtocolOption{}, transErr, pkt)
	case stack.SourceRouteFailedTransportError:
		e.onICMPError(&tcpip.ErrNotSupported{}, transErr, pkt)
	case stack.SourceHostIsolatedTransportError:
		e.onICMPError(&tcpip.ErrNoNet{}, transErr, pkt)
	case stack.DestinationHostDownTransportError:
		e.onICMPError(&tcpip.ErrHostDown{}, transErr, pkt)
	}
}

// updateSndBufferUsage is called by the protocol goroutine when room opens up
// in the send buffer. The number of newly available bytes is v.
func (e *endpoint) updateSndBufferUsage(v int) {
	sendBufferSize := e.getSendBufferSize()
	e.sndQueueInfo.sndQueueMu.Lock()
	notify := e.sndQueueInfo.SndBufUsed >= sendBufferSize>>1
	e.sndQueueInfo.SndBufUsed -= v

	// Get the new send buffer size with auto tuning, but do not set it
	// unless we decide to notify the writers.
	newSndBufSz := e.computeTCPSendBufferSize()

	// We only notify when there is half the sendBufferSize available after
	// a full buffer event occurs. This ensures that we don't wake up
	// writers to queue just 1-2 segments and go back to sleep.
	notify = notify && e.sndQueueInfo.SndBufUsed < int(newSndBufSz)>>1
	e.sndQueueInfo.sndQueueMu.Unlock()

	if notify {
		// Set the new send buffer size calculated from auto tuning.
		e.ops.SetSendBufferSize(newSndBufSz, false /* notify */)
		e.waiterQueue.Notify(waiter.WritableEvents)
	}
}

// readyToRead is called by the protocol goroutine when a new segment is ready
// to be read, or when the connection is closed for receiving (in which case
// s will be nil).
//
// +checklocks:e.mu
func (e *endpoint) readyToRead(s *segment) {
	e.rcvQueueMu.Lock()
	if s != nil {
		e.RcvBufUsed += s.payloadSize()
		s.IncRef()
		e.rcvQueue.PushBack(s)
	} else {
		e.RcvClosed = true
	}
	e.rcvQueueMu.Unlock()
	e.waiterQueue.Notify(waiter.ReadableEvents)
}

// receiveBufferAvailableLocked calculates how many bytes are still available
// in the receive buffer.
// +checklocks:e.rcvQueueMu
func (e *endpoint) receiveBufferAvailableLocked(rcvBufSize int) int {
	// We may use more bytes than the buffer size when the receive buffer
	// shrinks.
	memUsed := e.receiveMemUsed()
	if memUsed >= rcvBufSize {
		return 0
	}

	return rcvBufSize - memUsed
}

// receiveBufferAvailable calculates how many bytes are still available in the
// receive buffer based on the actual memory used by all segments held in
// receive buffer/pending and segment queue.
func (e *endpoint) receiveBufferAvailable() int {
	e.rcvQueueMu.Lock()
	available := e.receiveBufferAvailableLocked(int(e.ops.GetReceiveBufferSize()))
	e.rcvQueueMu.Unlock()
	return available
}

// receiveBufferUsed returns the amount of in-use receive buffer.
func (e *endpoint) receiveBufferUsed() int {
	e.rcvQueueMu.Lock()
	used := e.RcvBufUsed
	e.rcvQueueMu.Unlock()
	return used
}

// receiveMemUsed returns the total memory in use by segments held by this
// endpoint.
func (e *endpoint) receiveMemUsed() int {
	return int(e.rcvMemUsed.Load())
}

// updateReceiveMemUsed adds the provided delta to e.rcvMemUsed.
func (e *endpoint) updateReceiveMemUsed(delta int) {
	e.rcvMemUsed.Add(int32(delta))
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
	bufSizeForScale := e.ops.GetReceiveBufferSize()

	e.rcvQueueMu.Lock()
	autoTuningDisabled := e.RcvAutoParams.Disabled
	e.rcvQueueMu.Unlock()
	if autoTuningDisabled {
		return FindWndScale(seqnum.Size(bufSizeForScale))
	}

	return FindWndScale(seqnum.Size(e.maxReceiveBufferSize()))
}

// updateRecentTimestamp updates the recent timestamp using the algorithm
// described in https://tools.ietf.org/html/rfc7323#section-4.3
func (e *endpoint) updateRecentTimestamp(tsVal uint32, maxSentAck seqnum.Value, segSeq seqnum.Value) {
	if e.SendTSOk && seqnum.Value(e.recentTimestamp()).LessThan(seqnum.Value(tsVal)) && segSeq.LessThanEq(maxSentAck) {
		e.setRecentTimestamp(tsVal)
	}
}

// maybeEnableTimestamp marks the timestamp option enabled for this endpoint if
// the SYN options indicate that timestamp option was negotiated. It also
// initializes the recentTS with the value provided in synOpts.TSval.
func (e *endpoint) maybeEnableTimestamp(synOpts header.TCPSynOptions) {
	if synOpts.TS {
		e.SendTSOk = true
		e.setRecentTimestamp(synOpts.TSVal)
	}
}

func (e *endpoint) tsVal(now tcpip.MonotonicTime) uint32 {
	return e.TSOffset.TSVal(now)
}

func (e *endpoint) tsValNow() uint32 {
	return e.tsVal(e.stack.Clock().NowMonotonic())
}

func (e *endpoint) elapsed(now tcpip.MonotonicTime, tsEcr uint32) time.Duration {
	return e.TSOffset.Elapsed(now, tsEcr)
}

// maybeEnableSACKPermitted marks the SACKPermitted option enabled for this endpoint
// if the SYN options indicate that the SACK option was negotiated and the TCP
// stack is configured to enable TCP SACK option.
func (e *endpoint) maybeEnableSACKPermitted(synOpts header.TCPSynOptions) {
	var v tcpip.TCPSACKEnabled
	if err := e.stack.TransportProtocolOption(ProtocolNumber, &v); err != nil {
		// Stack doesn't support SACK. So just return.
		return
	}
	if bool(v) && synOpts.SACKPermitted {
		e.SACKPermitted = true
		e.stack.TransportProtocolOption(ProtocolNumber, &e.tcpRecovery)
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

// completeStateLocked makes a full copy of the endpoint and returns it. This is
// used before invoking the probe.
//
// +checklocks:e.mu
func (e *endpoint) completeStateLocked(s *stack.TCPEndpointState) {
	s.TCPEndpointStateInner = e.TCPEndpointStateInner
	s.ID = stack.TCPEndpointID(e.TransportEndpointInfo.ID)
	s.SegTime = e.stack.Clock().NowMonotonic()
	s.Receiver = e.rcv.TCPReceiverState
	s.Sender = e.snd.TCPSenderState

	sndBufSize := e.getSendBufferSize()
	// Copy the send buffer atomically.
	e.sndQueueInfo.sndQueueMu.Lock()
	e.sndQueueInfo.CloneState(&s.SndBufState)
	s.SndBufState.SndBufSize = sndBufSize
	e.sndQueueInfo.sndQueueMu.Unlock()

	// Copy the receive buffer atomically.
	e.rcvQueueMu.Lock()
	s.RcvBufState = e.TCPRcvBufState
	e.rcvQueueMu.Unlock()

	// Copy the endpoint TCP Option state.
	s.SACK.Blocks = make([]header.SACKBlock, e.sack.NumBlocks)
	copy(s.SACK.Blocks, e.sack.Blocks[:e.sack.NumBlocks])
	s.SACK.ReceivedBlocks, s.SACK.MaxSACKED = e.scoreboard.Copy()

	e.snd.rtt.Lock()
	s.Sender.RTTState = e.snd.rtt.TCPRTTState
	e.snd.rtt.Unlock()

	if cubic, ok := e.snd.cc.(*cubicState); ok {
		s.Sender.Cubic = cubic.TCPCubicState
		s.Sender.Cubic.TimeSinceLastCongestion = e.stack.Clock().NowMonotonic().Sub(s.Sender.Cubic.T)
	}

	s.Sender.RACKState = e.snd.rc.TCPRACKState
	s.Sender.RetransmitTS = e.snd.retransmitTS
	s.Sender.SpuriousRecovery = e.snd.spuriousRecovery
}

func (e *endpoint) initHostGSO() {
	switch e.route.NetProto() {
	case header.IPv4ProtocolNumber:
		e.gso.Type = stack.GSOTCPv4
		e.gso.L3HdrLen = header.IPv4MinimumSize
	case header.IPv6ProtocolNumber:
		e.gso.Type = stack.GSOTCPv6
		e.gso.L3HdrLen = header.IPv6MinimumSize
	default:
		panic(fmt.Sprintf("Unknown netProto: %v", e.NetProto))
	}
	e.gso.NeedsCsum = true
	e.gso.CsumOffset = header.TCPChecksumOffset
	e.gso.MaxSize = e.route.GSOMaxSize()
}

func (e *endpoint) initGSO() {
	if e.route.HasHostGSOCapability() {
		e.initHostGSO()
	} else if e.route.HasGvisorGSOCapability() {
		e.gso = stack.GSO{
			MaxSize:   e.route.GSOMaxSize(),
			Type:      stack.GSOGvisor,
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
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp)
	e.waiterQueue.EventRegister(&waitEntry)
	defer e.waiterQueue.EventUnregister(&waitEntry)
	switch e.EndpointState() {
	case StateClose, StateError:
		return
	}
	<-notifyCh
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

// allowOutOfWindowAck returns true if an out-of-window ACK can be sent now.
func (e *endpoint) allowOutOfWindowAck() bool {
	now := e.stack.Clock().NowMonotonic()

	if e.lastOutOfWindowAckTime != (tcpip.MonotonicTime{}) {
		var limit stack.TCPInvalidRateLimitOption
		if err := e.stack.Option(&limit); err != nil {
			panic(fmt.Sprintf("e.stack.Option(%+v) failed with error: %s", limit, err))
		}
		if now.Sub(e.lastOutOfWindowAckTime) < time.Duration(limit) {
			return false
		}
	}

	e.lastOutOfWindowAckTime = now
	return true
}

// GetTCPReceiveBufferLimits is used to get send buffer size limits for TCP.
func GetTCPReceiveBufferLimits(s tcpip.StackHandler) tcpip.ReceiveBufferSizeOption {
	var ss tcpip.TCPReceiveBufferSizeRangeOption
	if err := s.TransportProtocolOption(header.TCPProtocolNumber, &ss); err != nil {
		panic(fmt.Sprintf("s.TransportProtocolOption(%d, %#v) = %s", header.TCPProtocolNumber, ss, err))
	}

	return tcpip.ReceiveBufferSizeOption{
		Min:     ss.Min,
		Default: ss.Default,
		Max:     ss.Max,
	}
}

// computeTCPSendBufferSize implements auto tuning of send buffer size and
// returns the new send buffer size.
func (e *endpoint) computeTCPSendBufferSize() int64 {
	curSndBufSz := int64(e.getSendBufferSize())

	// Auto tuning is disabled when the user explicitly sets the send
	// buffer size with SO_SNDBUF option.
	if disabled := e.sndQueueInfo.TCPSndBufState.AutoTuneSndBufDisabled.Load(); disabled == 1 {
		return curSndBufSz
	}

	const packetOverheadFactor = 2
	curMSS := e.snd.MaxPayloadSize
	numSeg := InitialCwnd
	if numSeg < e.snd.SndCwnd {
		numSeg = e.snd.SndCwnd
	}

	// SndCwnd indicates the number of segments that can be sent. This means
	// that the sender can send upto #SndCwnd segments and the send buffer
	// size should be set to SndCwnd*MSS to accommodate sending of all the
	// segments.
	newSndBufSz := int64(numSeg * curMSS * packetOverheadFactor)
	if newSndBufSz < curSndBufSz {
		return curSndBufSz
	}
	if ss := GetTCPSendBufferLimits(e.stack); int64(ss.Max) < newSndBufSz {
		newSndBufSz = int64(ss.Max)
	}

	return newSndBufSz
}
