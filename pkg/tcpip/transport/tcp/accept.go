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
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// tsLen is the length, in bits, of the timestamp in the SYN cookie.
	tsLen = 8

	// tsMask is a mask for timestamp values (i.e., tsLen bits).
	tsMask = (1 << tsLen) - 1

	// tsOffset is the offset, in bits, of the timestamp in the SYN cookie.
	tsOffset = 24

	// hashMask is the mask for hash values (i.e., tsOffset bits).
	hashMask = (1 << tsOffset) - 1

	// maxTSDiff is the maximum allowed difference between a received cookie
	// timestamp and the current timestamp. If the difference is greater
	// than maxTSDiff, the cookie is expired.
	maxTSDiff = 2
)

var (
	// SynRcvdCountThreshold is the global maximum number of connections
	// that are allowed to be in SYN-RCVD state before TCP starts using SYN
	// cookies to accept connections.
	//
	// It is an exported variable only for testing, and should not otherwise
	// be used by importers of this package.
	SynRcvdCountThreshold uint64 = 1000

	// mssTable is a slice containing the possible MSS values that we
	// encode in the SYN cookie with two bits.
	mssTable = []uint16{536, 1300, 1440, 1460}
)

func encodeMSS(mss uint16) uint32 {
	for i := len(mssTable) - 1; i > 0; i-- {
		if mss >= mssTable[i] {
			return uint32(i)
		}
	}
	return 0
}

// syncRcvdCount is the number of endpoints in the SYN-RCVD state. The value is
// protected by a mutex so that we can increment only when it's guaranteed not
// to go above a threshold.
var synRcvdCount struct {
	sync.Mutex
	value   uint64
	pending sync.WaitGroup
}

// listenContext is used by a listening endpoint to store state used while
// listening for connections. This struct is allocated by the listen goroutine
// and must not be accessed or have its methods called concurrently as they
// may mutate the stored objects.
type listenContext struct {
	stack    *stack.Stack
	rcvWnd   seqnum.Size
	nonce    [2][sha1.BlockSize]byte
	listenEP *endpoint

	hasherMu sync.Mutex
	hasher   hash.Hash
	v6only   bool
	netProto tcpip.NetworkProtocolNumber
}

// timeStamp returns an 8-bit timestamp with a granularity of 64 seconds.
func timeStamp() uint32 {
	return uint32(time.Now().Unix()>>6) & tsMask
}

// incSynRcvdCount tries to increment the global number of endpoints in SYN-RCVD
// state. It succeeds if the increment doesn't make the count go beyond the
// threshold, and fails otherwise.
func incSynRcvdCount() bool {
	synRcvdCount.Lock()

	if synRcvdCount.value >= SynRcvdCountThreshold {
		synRcvdCount.Unlock()
		return false
	}

	synRcvdCount.pending.Add(1)
	synRcvdCount.value++

	synRcvdCount.Unlock()
	return true
}

// decSynRcvdCount atomically decrements the global number of endpoints in
// SYN-RCVD state. It must only be called if a previous call to incSynRcvdCount
// succeeded.
func decSynRcvdCount() {
	synRcvdCount.Lock()

	synRcvdCount.value--
	synRcvdCount.pending.Done()
	synRcvdCount.Unlock()
}

// newListenContext creates a new listen context.
func newListenContext(stack *stack.Stack, listenEP *endpoint, rcvWnd seqnum.Size, v6only bool, netProto tcpip.NetworkProtocolNumber) *listenContext {
	l := &listenContext{
		stack:    stack,
		rcvWnd:   rcvWnd,
		hasher:   sha1.New(),
		v6only:   v6only,
		netProto: netProto,
		listenEP: listenEP,
	}

	rand.Read(l.nonce[0][:])
	rand.Read(l.nonce[1][:])

	return l
}

// cookieHash calculates the cookieHash for the given id, timestamp and nonce
// index. The hash is used to create and validate cookies.
func (l *listenContext) cookieHash(id stack.TransportEndpointID, ts uint32, nonceIndex int) uint32 {

	// Initialize block with fixed-size data: local ports and v.
	var payload [8]byte
	binary.BigEndian.PutUint16(payload[0:], id.LocalPort)
	binary.BigEndian.PutUint16(payload[2:], id.RemotePort)
	binary.BigEndian.PutUint32(payload[4:], ts)

	// Feed everything to the hasher.
	l.hasherMu.Lock()
	l.hasher.Reset()
	l.hasher.Write(payload[:])
	l.hasher.Write(l.nonce[nonceIndex][:])
	io.WriteString(l.hasher, string(id.LocalAddress))
	io.WriteString(l.hasher, string(id.RemoteAddress))

	// Finalize the calculation of the hash and return the first 4 bytes.
	h := make([]byte, 0, sha1.Size)
	h = l.hasher.Sum(h)
	l.hasherMu.Unlock()

	return binary.BigEndian.Uint32(h[:])
}

// createCookie creates a SYN cookie for the given id and incoming sequence
// number.
func (l *listenContext) createCookie(id stack.TransportEndpointID, seq seqnum.Value, data uint32) seqnum.Value {
	ts := timeStamp()
	v := l.cookieHash(id, 0, 0) + uint32(seq) + (ts << tsOffset)
	v += (l.cookieHash(id, ts, 1) + data) & hashMask
	return seqnum.Value(v)
}

// isCookieValid checks if the supplied cookie is valid for the given id and
// sequence number. If it is, it also returns the data originally encoded in the
// cookie when createCookie was called.
func (l *listenContext) isCookieValid(id stack.TransportEndpointID, cookie seqnum.Value, seq seqnum.Value) (uint32, bool) {
	ts := timeStamp()
	v := uint32(cookie) - l.cookieHash(id, 0, 0) - uint32(seq)
	cookieTS := v >> tsOffset
	if ((ts - cookieTS) & tsMask) > maxTSDiff {
		return 0, false
	}

	return (v - l.cookieHash(id, cookieTS, 1)) & hashMask, true
}

// createConnectingEndpoint creates a new endpoint in a connecting state, with
// the connection parameters given by the arguments.
func (l *listenContext) createConnectingEndpoint(s *segment, iss seqnum.Value, irs seqnum.Value, rcvdSynOpts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {
	// Create a new endpoint.
	netProto := l.netProto
	if netProto == 0 {
		netProto = s.route.NetProto
	}
	n := newEndpoint(l.stack, netProto, nil)
	n.v6only = l.v6only
	n.id = s.id
	n.boundNICID = s.route.NICID()
	n.route = s.route.Clone()
	n.effectiveNetProtos = []tcpip.NetworkProtocolNumber{s.route.NetProto}
	n.rcvBufSize = int(l.rcvWnd)

	n.maybeEnableTimestamp(rcvdSynOpts)
	n.maybeEnableSACKPermitted(rcvdSynOpts)

	n.initGSO()

	// Register new endpoint so that packets are routed to it.
	if err := n.stack.RegisterTransportEndpoint(n.boundNICID, n.effectiveNetProtos, ProtocolNumber, n.id, n, n.reusePort); err != nil {
		n.Close()
		return nil, err
	}

	n.isRegistered = true

	// Create sender and receiver.
	//
	// The receiver at least temporarily has a zero receive window scale,
	// but the caller may change it (before starting the protocol loop).
	n.snd = newSender(n, iss, irs, s.window, rcvdSynOpts.MSS, rcvdSynOpts.WS)
	n.rcv = newReceiver(n, irs, l.rcvWnd, 0)

	return n, nil
}

// createEndpoint creates a new endpoint in connected state and then performs
// the TCP 3-way handshake.
func (l *listenContext) createEndpointAndPerformHandshake(s *segment, opts *header.TCPSynOptions) (*endpoint, *tcpip.Error) {
	// Create new endpoint.
	irs := s.sequenceNumber
	cookie := l.createCookie(s.id, irs, encodeMSS(opts.MSS))
	ep, err := l.createConnectingEndpoint(s, cookie, irs, opts)
	if err != nil {
		return nil, err
	}

	// Perform the 3-way handshake.
	h := newHandshake(ep, l.rcvWnd)

	h.resetToSynRcvd(cookie, irs, opts)
	if err := h.execute(); err != nil {
		ep.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		ep.Close()
		return nil, err
	}
	ep.mu.Lock()
	ep.state = StateEstablished
	ep.mu.Unlock()

	// Update the receive window scaling. We can't do it before the
	// handshake because it's possible that the peer doesn't support window
	// scaling.
	ep.rcv.rcvWndScale = h.effectiveRcvWndScale()

	return ep, nil
}

// deliverAccepted delivers the newly-accepted endpoint to the listener. If the
// endpoint has transitioned out of the listen state, the new endpoint is closed
// instead.
func (e *endpoint) deliverAccepted(n *endpoint) {
	e.mu.RLock()
	state := e.state
	e.mu.RUnlock()
	if state == StateListen {
		e.acceptedChan <- n
		e.waiterQueue.Notify(waiter.EventIn)
	} else {
		n.Close()
	}
}

// handleSynSegment is called in its own goroutine once the listening endpoint
// receives a SYN segment. It is responsible for completing the handshake and
// queueing the new endpoint for acceptance.
//
// A limited number of these goroutines are allowed before TCP starts using SYN
// cookies to accept connections.
func (e *endpoint) handleSynSegment(ctx *listenContext, s *segment, opts *header.TCPSynOptions) {
	defer decSynRcvdCount()
	defer e.decSynRcvdCount()
	defer s.decRef()
	n, err := ctx.createEndpointAndPerformHandshake(s, opts)
	if err != nil {
		e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
		return
	}

	e.deliverAccepted(n)
}

func (e *endpoint) incSynRcvdCount() bool {
	e.mu.Lock()
	if e.synRcvdCount >= cap(e.acceptedChan) {
		e.mu.Unlock()
		return false
	}
	e.synRcvdCount++
	e.mu.Unlock()
	return true
}

func (e *endpoint) decSynRcvdCount() {
	e.mu.Lock()
	e.synRcvdCount--
	e.mu.Unlock()
}

func (e *endpoint) acceptQueueIsFull() bool {
	e.mu.Lock()
	if l, c := len(e.acceptedChan)+e.synRcvdCount, cap(e.acceptedChan); l >= c {
		e.mu.Unlock()
		return true
	}
	e.mu.Unlock()
	return false
}

// handleListenSegment is called when a listening endpoint receives a segment
// and needs to handle it.
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) {
	switch s.flags {
	case header.TCPFlagSyn:
		opts := parseSynSegmentOptions(s)
		if incSynRcvdCount() {
			// Only handle the syn if the following conditions hold
			//   - accept queue is not full.
			//   - number of connections in synRcvd state is less than the
			//     backlog.
			if !e.acceptQueueIsFull() && e.incSynRcvdCount() {
				s.incRef()
				go e.handleSynSegment(ctx, s, &opts) // S/R-SAFE: synRcvdCount is the barrier.
				return
			}
			decSynRcvdCount()
			e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return
		} else {
			// If cookies are in use but the endpoint accept queue
			// is full then drop the syn.
			if e.acceptQueueIsFull() {
				e.stack.Stats().TCP.ListenOverflowSynDrop.Increment()
				e.stack.Stats().DroppedPackets.Increment()
				return
			}
			cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
			// Send SYN with window scaling because we currently
			// dont't encode this information in the cookie.
			//
			// Enable Timestamp option if the original syn did have
			// the timestamp option specified.
			synOpts := header.TCPSynOptions{
				WS:    -1,
				TS:    opts.TS,
				TSVal: tcpTimeStamp(timeStampOffset()),
				TSEcr: opts.TSVal,
			}
			sendSynTCP(&s.route, s.id, header.TCPFlagSyn|header.TCPFlagAck, cookie, s.sequenceNumber+1, ctx.rcvWnd, synOpts)
			e.stack.Stats().TCP.ListenOverflowSynCookieSent.Increment()
		}

	case header.TCPFlagAck:
		if e.acceptQueueIsFull() {
			// Silently drop the ack as the application can't accept
			// the connection at this point. The ack will be
			// retransmitted by the sender anyway and we can
			// complete the connection at the time of retransmit if
			// the backlog has space.
			e.stack.Stats().TCP.ListenOverflowAckDrop.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return
		}

		// Validate the cookie.
		data, ok := ctx.isCookieValid(s.id, s.ackNumber-1, s.sequenceNumber-1)
		if !ok || int(data) >= len(mssTable) {
			e.stack.Stats().TCP.ListenOverflowInvalidSynCookieRcvd.Increment()
			e.stack.Stats().DroppedPackets.Increment()
			return
		}
		e.stack.Stats().TCP.ListenOverflowSynCookieRcvd.Increment()
		// Create newly accepted endpoint and deliver it.
		rcvdSynOptions := &header.TCPSynOptions{
			MSS: mssTable[data],
			// Disable Window scaling as original SYN is
			// lost.
			WS: -1,
		}

		// When syn cookies are in use we enable timestamp only
		// if the ack specifies the timestamp option assuming
		// that the other end did in fact negotiate the
		// timestamp option in the original SYN.
		if s.parsedOptions.TS {
			rcvdSynOptions.TS = true
			rcvdSynOptions.TSVal = s.parsedOptions.TSVal
			rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
		}

		n, err := ctx.createConnectingEndpoint(s, s.ackNumber-1, s.sequenceNumber-1, rcvdSynOptions)
		if err != nil {
			e.stack.Stats().TCP.FailedConnectionAttempts.Increment()
			return
		}

		// clear the tsOffset for the newly created
		// endpoint as the Timestamp was already
		// randomly offset when the original SYN-ACK was
		// sent above.
		n.tsOffset = 0

		// Switch state to connected.
		n.state = StateEstablished

		// Do the delivery in a separate goroutine so
		// that we don't block the listen loop in case
		// the application is slow to accept or stops
		// accepting.
		//
		// NOTE: This won't result in an unbounded
		// number of goroutines as we do check before
		// entering here that there was at least some
		// space available in the backlog.
		go e.deliverAccepted(n)
	}
}

// protocolListenLoop is the main loop of a listening TCP endpoint. It runs in
// its own goroutine and is responsible for handling connection requests.
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) *tcpip.Error {
	defer func() {
		// Mark endpoint as closed. This will prevent goroutines running
		// handleSynSegment() from attempting to queue new connections
		// to the endpoint.
		e.mu.Lock()
		e.state = StateClose

		// Do cleanup if needed.
		e.completeWorkerLocked()

		if e.drainDone != nil {
			close(e.drainDone)
		}
		e.mu.Unlock()

		// Notify waiters that the endpoint is shutdown.
		e.waiterQueue.Notify(waiter.EventIn | waiter.EventOut)
	}()

	e.mu.Lock()
	v6only := e.v6only
	e.mu.Unlock()

	ctx := newListenContext(e.stack, e, rcvWnd, v6only, e.netProto)

	s := sleep.Sleeper{}
	s.AddWaker(&e.notificationWaker, wakerForNotification)
	s.AddWaker(&e.newSegmentWaker, wakerForNewSegment)
	for {
		switch index, _ := s.Fetch(true); index {
		case wakerForNotification:
			n := e.fetchNotifications()
			if n&notifyClose != 0 {
				return nil
			}
			if n&notifyDrain != 0 {
				for !e.segmentQueue.empty() {
					s := e.segmentQueue.dequeue()
					e.handleListenSegment(ctx, s)
					s.decRef()
				}
				synRcvdCount.pending.Wait()
				close(e.drainDone)
				<-e.undrain
			}

		case wakerForNewSegment:
			// Process at most maxSegmentsPerWake segments.
			mayRequeue := true
			for i := 0; i < maxSegmentsPerWake; i++ {
				s := e.segmentQueue.dequeue()
				if s == nil {
					mayRequeue = false
					break
				}

				e.handleListenSegment(ctx, s)
				s.decRef()
			}

			// If the queue is not empty, make sure we'll wake up
			// in the next iteration.
			if mayRequeue && !e.segmentQueue.empty() {
				e.newSegmentWaker.Assert()
			}
		}
	}
}
