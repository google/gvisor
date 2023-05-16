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

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets.
	e.segmentQueue.freeze()

	e.mu.Lock()
	defer e.mu.Unlock()

	epState := e.EndpointState()
	switch {
	case epState == StateInitial || epState == StateBound:
	case epState.connected() || epState.handshake():
		if !e.route.HasSaveRestoreCapability() {
			if !e.route.HasDisconnectOkCapability() {
				panic(&tcpip.ErrSaveRejection{
					Err: fmt.Errorf("endpoint cannot be saved in connected state: local %s:%d, remote %s:%d", e.TransportEndpointInfo.ID.LocalAddress, e.TransportEndpointInfo.ID.LocalPort, e.TransportEndpointInfo.ID.RemoteAddress, e.TransportEndpointInfo.ID.RemotePort),
				})
			}
			e.resetConnectionLocked(&tcpip.ErrConnectionAborted{})
			e.mu.Unlock()
			e.Close()
			e.mu.Lock()
		}
		fallthrough
	case epState == StateListen:
		// Nothing to do.
	case epState.closed():
		// Nothing to do.
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.EndpointState()))
	}
}

// saveEndpoints is invoked by stateify.
func (a *acceptQueue) saveEndpoints() []*endpoint {
	acceptedEndpoints := make([]*endpoint, a.endpoints.Len())
	for i, e := 0, a.endpoints.Front(); e != nil; i, e = i+1, e.Next() {
		acceptedEndpoints[i] = e.Value.(*endpoint)
	}
	return acceptedEndpoints
}

// loadEndpoints is invoked by stateify.
func (a *acceptQueue) loadEndpoints(acceptedEndpoints []*endpoint) {
	for _, ep := range acceptedEndpoints {
		a.endpoints.PushBack(ep)
	}
}

// saveState is invoked by stateify.
func (e *endpoint) saveState() EndpointState {
	return e.EndpointState()
}

// Endpoint loading must be done in the following ordering by their state, to
// avoid dangling connecting w/o listening peer, and to avoid conflicts in port
// reservation.
var connectedLoading sync.WaitGroup
var listenLoading sync.WaitGroup
var connectingLoading sync.WaitGroup

// Bound endpoint loading happens last.

// loadState is invoked by stateify.
func (e *endpoint) loadState(epState EndpointState) {
	// This is to ensure that the loading wait groups include all applicable
	// endpoints before any asynchronous calls to the Wait() methods.
	// For restore purposes we treat TimeWait like a connected endpoint.
	if epState.connected() || epState == StateTimeWait {
		connectedLoading.Add(1)
	}
	switch {
	case epState == StateListen:
		listenLoading.Add(1)
	case epState.connecting():
		connectingLoading.Add(1)
	}
	// Directly update the state here rather than using e.setEndpointState
	// as the endpoint is still being loaded and the stack reference is not
	// yet initialized.
	e.state.Store(uint32(epState))
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	// RacyLoad() can be used because we are initializing e.
	e.origEndpointState = e.state.RacyLoad()
	// Restore the endpoint to InitialState as it will be moved to
	// its origEndpointState during Resume.
	e.state = atomicbitops.FromUint32(uint32(StateInitial))
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	if !e.EndpointState().closed() {
		e.keepalive.timer.init(s.Clock(), maybeFailTimerHandler(e, e.keepaliveTimerExpired))
	}
	if snd := e.snd; snd != nil {
		snd.resendTimer.init(s.Clock(), maybeFailTimerHandler(e, e.snd.retransmitTimerExpired))
		snd.reorderTimer.init(s.Clock(), timerHandler(e, e.snd.rc.reorderTimerExpired))
		snd.probeTimer.init(s.Clock(), timerHandler(e, e.snd.probeTimerExpired))
	}
	e.stack = s
	e.protocol = protocolFromStack(s)
	e.ops.InitHandler(e, e.stack, GetTCPSendBufferLimits, GetTCPReceiveBufferLimits)
	e.segmentQueue.thaw()

	bind := func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		addr, _, err := e.checkV4MappedLocked(tcpip.FullAddress{Addr: e.BindAddr, Port: e.TransportEndpointInfo.ID.LocalPort})
		if err != nil {
			panic("unable to parse BindAddr: " + err.String())
		}
		portRes := ports.Reservation{
			Networks:     e.effectiveNetProtos,
			Transport:    ProtocolNumber,
			Addr:         addr.Addr,
			Port:         addr.Port,
			Flags:        e.boundPortFlags,
			BindToDevice: e.boundBindToDevice,
			Dest:         e.boundDest,
		}
		if ok := e.stack.ReserveTuple(portRes); !ok {
			panic(fmt.Sprintf("unable to re-reserve tuple (%v, %q, %d, %+v, %d, %v)", e.effectiveNetProtos, addr.Addr, addr.Port, e.boundPortFlags, e.boundBindToDevice, e.boundDest))
		}
		e.isPortReserved = true

		// Mark endpoint as bound.
		e.setEndpointState(StateBound)
	}

	epState := EndpointState(e.origEndpointState)
	switch {
	case epState.connected():
		bind()
		if e.connectingAddress.BitLen() == 0 {
			e.connectingAddress = e.TransportEndpointInfo.ID.RemoteAddress
			// This endpoint is accepted by netstack but not yet by
			// the app. If the endpoint is IPv6 but the remote
			// address is IPv4, we need to connect as IPv6 so that
			// dual-stack mode can be properly activated.
			if e.NetProto == header.IPv6ProtocolNumber && e.TransportEndpointInfo.ID.RemoteAddress.BitLen() != header.IPv6AddressSizeBits {
				e.connectingAddress = tcpip.AddrFrom16Slice(append(
					[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff},
					e.TransportEndpointInfo.ID.RemoteAddress.AsSlice()...,
				))
			}
		}
		// Reset the scoreboard to reinitialize the sack information as
		// we do not restore SACK information.
		e.scoreboard.Reset()
		e.mu.Lock()
		err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort}, false /* handshake */)
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			panic("endpoint connecting failed: " + err.String())
		}
		e.state.Store(e.origEndpointState)
		// For FIN-WAIT-2 and TIME-WAIT we need to start the appropriate timers so
		// that the socket is closed correctly.
		switch epState {
		case StateFinWait2:
			e.finWait2Timer = e.stack.Clock().AfterFunc(e.tcpLingerTimeout, e.finWait2TimerExpired)
		case StateTimeWait:
			e.timeWaitTimer = e.stack.Clock().AfterFunc(e.getTimeWaitDuration(), e.timeWaitTimerExpired)
		}

		e.mu.Unlock()
		connectedLoading.Done()
	case epState == StateListen:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			bind()
			e.acceptMu.Lock()
			backlog := e.acceptQueue.capacity
			e.acceptMu.Unlock()
			if err := e.Listen(backlog); err != nil {
				panic("endpoint listening failed: " + err.String())
			}
			e.LockUser()
			if e.shutdownFlags != 0 {
				e.shutdownLocked(e.shutdownFlags)
			}
			e.UnlockUser()
			listenLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateConnecting:
		// Initial SYN hasn't been sent yet so initiate a connect.
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			bind()
			err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.TransportEndpointInfo.ID.RemotePort})
			if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
				panic("endpoint connecting failed: " + err.String())
			}
			connectingLoading.Done()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateSynSent || epState == StateSynRecv:
		connectedLoading.Wait()
		listenLoading.Wait()
		// Initial SYN has been sent/received so we should bind the
		// ports start the retransmit timer for the SYNs and let it
		// naturally complete the connection.
		bind()
		e.mu.Lock()
		defer e.mu.Unlock()
		e.setEndpointState(epState)
		r, err := e.stack.FindRoute(e.boundNICID, e.TransportEndpointInfo.ID.LocalAddress, e.TransportEndpointInfo.ID.RemoteAddress, e.effectiveNetProtos[0], false /* multicastLoop */)
		if err != nil {
			panic(fmt.Sprintf("FindRoute failed when restoring endpoint w/ ID: %+v", e.ID))
		}
		e.route = r
		timer, err := newBackoffTimer(e.stack.Clock(), InitialRTO, MaxRTO, maybeFailTimerHandler(e, e.h.retransmitHandlerLocked))
		if err != nil {
			panic(fmt.Sprintf("newBackOffTimer(_, %s, %s, _) failed: %s", InitialRTO, MaxRTO, err))
		}
		e.h.retransmitTimer = timer
		connectingLoading.Done()
	case epState == StateBound:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			connectingLoading.Wait()
			bind()
			tcpip.AsyncLoading.Done()
		}()
	case epState == StateClose:
		e.isPortReserved = false
		e.state.Store(uint32(StateClose))
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	case epState == StateError:
		e.state.Store(uint32(StateError))
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	}
}
