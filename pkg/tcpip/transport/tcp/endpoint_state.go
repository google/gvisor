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
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func (e *endpoint) drainSegmentLocked() {
	// Drain only up to once.
	if e.drainDone != nil {
		return
	}

	e.drainDone = make(chan struct{})
	e.undrain = make(chan struct{})
	e.mu.Unlock()

	e.notifyProtocolGoroutine(notifyDrain)
	<-e.drainDone

	e.mu.Lock()
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets.
	e.segmentQueue.setLimit(0)

	e.mu.Lock()
	defer e.mu.Unlock()

	switch e.state {
	case StateInitial, StateBound:
		// TODO(b/138137272): this enumeration duplicates
		// EndpointState.connected. remove it.
	case StateEstablished, StateSynSent, StateSynRecv, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		if e.route.Capabilities()&stack.CapabilitySaveRestore == 0 {
			if e.route.Capabilities()&stack.CapabilityDisconnectOk == 0 {
				panic(tcpip.ErrSaveRejection{fmt.Errorf("endpoint cannot be saved in connected state: local %v:%d, remote %v:%d", e.ID.LocalAddress, e.ID.LocalPort, e.ID.RemoteAddress, e.ID.RemotePort)})
			}
			e.resetConnectionLocked(tcpip.ErrConnectionAborted)
			e.mu.Unlock()
			e.Close()
			e.mu.Lock()
		}
		if !e.workerRunning {
			// The endpoint must be in acceptedChan or has been just
			// disconnected and closed.
			break
		}
		fallthrough
	case StateListen, StateConnecting:
		e.drainSegmentLocked()
		if e.state != StateClose && e.state != StateError {
			if !e.workerRunning {
				panic("endpoint has no worker running in listen, connecting, or connected state")
			}
			break
		}
		fallthrough
	case StateError, StateClose:
		for e.state == StateError && e.workerRunning {
			e.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			e.mu.Lock()
		}
		if e.workerRunning {
			panic("endpoint still has worker running in closed or error state")
		}
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.state))
	}

	if e.waiterQueue != nil && !e.waiterQueue.IsEmpty() {
		panic("endpoint still has waiters upon save")
	}

	if e.state != StateClose && !((e.state == StateBound || e.state == StateListen) == e.isPortReserved) {
		panic("endpoints which are not in the closed state must have a reserved port IFF they are in bound or listen state")
	}
}

// saveAcceptedChan is invoked by stateify.
func (e *endpoint) saveAcceptedChan() []*endpoint {
	if e.acceptedChan == nil {
		return nil
	}
	acceptedEndpoints := make([]*endpoint, len(e.acceptedChan), cap(e.acceptedChan))
	for i := 0; i < len(acceptedEndpoints); i++ {
		select {
		case ep := <-e.acceptedChan:
			acceptedEndpoints[i] = ep
		default:
			panic("endpoint acceptedChan buffer got consumed by background context")
		}
	}
	for i := 0; i < len(acceptedEndpoints); i++ {
		select {
		case e.acceptedChan <- acceptedEndpoints[i]:
		default:
			panic("endpoint acceptedChan buffer got populated by background context")
		}
	}
	return acceptedEndpoints
}

// loadAcceptedChan is invoked by stateify.
func (e *endpoint) loadAcceptedChan(acceptedEndpoints []*endpoint) {
	if cap(acceptedEndpoints) > 0 {
		e.acceptedChan = make(chan *endpoint, cap(acceptedEndpoints))
		for _, ep := range acceptedEndpoints {
			e.acceptedChan <- ep
		}
	}
}

// saveState is invoked by stateify.
func (e *endpoint) saveState() EndpointState {
	return e.state
}

// Endpoint loading must be done in the following ordering by their state, to
// avoid dangling connecting w/o listening peer, and to avoid conflicts in port
// reservation.
var connectedLoading sync.WaitGroup
var listenLoading sync.WaitGroup
var connectingLoading sync.WaitGroup

// Bound endpoint loading happens last.

// loadState is invoked by stateify.
func (e *endpoint) loadState(state EndpointState) {
	// This is to ensure that the loading wait groups include all applicable
	// endpoints before any asynchronous calls to the Wait() methods.
	if state.connected() {
		connectedLoading.Add(1)
	}
	switch state {
	case StateListen:
		listenLoading.Add(1)
	case StateConnecting, StateSynSent, StateSynRecv:
		connectingLoading.Add(1)
	}
	e.state = state
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
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
		if len(e.BindAddr) == 0 {
			e.BindAddr = e.ID.LocalAddress
		}
		addr := e.BindAddr
		port := e.ID.LocalPort
		if err := e.Bind(tcpip.FullAddress{Addr: addr, Port: port}); err != nil {
			panic(fmt.Sprintf("endpoint binding [%v]:%d failed: %v", addr, port, err))
		}
	}

	switch state {
	case StateEstablished, StateFinWait1, StateFinWait2, StateTimeWait, StateCloseWait, StateLastAck, StateClosing:
		bind()
		if len(e.connectingAddress) == 0 {
			e.connectingAddress = e.ID.RemoteAddress
			// This endpoint is accepted by netstack but not yet by
			// the app. If the endpoint is IPv6 but the remote
			// address is IPv4, we need to connect as IPv6 so that
			// dual-stack mode can be properly activated.
			if e.NetProto == header.IPv6ProtocolNumber && len(e.ID.RemoteAddress) != header.IPv6AddressSize {
				e.connectingAddress = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + e.ID.RemoteAddress
			}
		}
		// Reset the scoreboard to reinitialize the sack information as
		// we do not restore SACK information.
		e.scoreboard.Reset()
		if err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.ID.RemotePort}, false, e.workerRunning); err != tcpip.ErrConnectStarted {
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
			if err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.ID.RemotePort}); err != tcpip.ErrConnectStarted {
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
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	}
}

// saveLastError is invoked by stateify.
func (e *endpoint) saveLastError() string {
	if e.lastError == nil {
		return ""
	}

	return e.lastError.String()
}

// loadLastError is invoked by stateify.
func (e *endpoint) loadLastError(s string) {
	if s == "" {
		return
	}

	e.lastError = loadError(s)
}

// saveHardError is invoked by stateify.
func (e *EndpointInfo) saveHardError() string {
	if e.HardError == nil {
		return ""
	}

	return e.HardError.String()
}

// loadHardError is invoked by stateify.
func (e *EndpointInfo) loadHardError(s string) {
	if s == "" {
		return
	}

	e.HardError = loadError(s)
}

var messageToError map[string]*tcpip.Error

var populate sync.Once

func loadError(s string) *tcpip.Error {
	populate.Do(func() {
		var errors = []*tcpip.Error{
			tcpip.ErrUnknownProtocol,
			tcpip.ErrUnknownNICID,
			tcpip.ErrUnknownDevice,
			tcpip.ErrUnknownProtocolOption,
			tcpip.ErrDuplicateNICID,
			tcpip.ErrDuplicateAddress,
			tcpip.ErrNoRoute,
			tcpip.ErrBadLinkEndpoint,
			tcpip.ErrAlreadyBound,
			tcpip.ErrInvalidEndpointState,
			tcpip.ErrAlreadyConnecting,
			tcpip.ErrAlreadyConnected,
			tcpip.ErrNoPortAvailable,
			tcpip.ErrPortInUse,
			tcpip.ErrBadLocalAddress,
			tcpip.ErrClosedForSend,
			tcpip.ErrClosedForReceive,
			tcpip.ErrWouldBlock,
			tcpip.ErrConnectionRefused,
			tcpip.ErrTimeout,
			tcpip.ErrAborted,
			tcpip.ErrConnectStarted,
			tcpip.ErrDestinationRequired,
			tcpip.ErrNotSupported,
			tcpip.ErrQueueSizeNotSupported,
			tcpip.ErrNotConnected,
			tcpip.ErrConnectionReset,
			tcpip.ErrConnectionAborted,
			tcpip.ErrNoSuchFile,
			tcpip.ErrInvalidOptionValue,
			tcpip.ErrNoLinkAddress,
			tcpip.ErrBadAddress,
			tcpip.ErrNetworkUnreachable,
			tcpip.ErrMessageTooLong,
			tcpip.ErrNoBufferSpace,
			tcpip.ErrBroadcastDisabled,
			tcpip.ErrNotPermitted,
			tcpip.ErrAddressFamilyNotSupported,
		}

		messageToError = make(map[string]*tcpip.Error)
		for _, e := range errors {
			if messageToError[e.String()] != nil {
				panic("tcpip errors with duplicated message: " + e.String())
			}
			messageToError[e.String()] = e
		}
	})

	e, ok := messageToError[s]
	if !ok {
		panic("unknown error message: " + s)
	}

	return e
}

// saveMeasureTime is invoked by stateify.
func (r *rcvBufAutoTuneParams) saveMeasureTime() unixTime {
	return unixTime{r.measureTime.Unix(), r.measureTime.UnixNano()}
}

// loadMeasureTime is invoked by stateify.
func (r *rcvBufAutoTuneParams) loadMeasureTime(unix unixTime) {
	r.measureTime = time.Unix(unix.second, unix.nano)
}

// saveRttMeasureTime is invoked by stateify.
func (r *rcvBufAutoTuneParams) saveRttMeasureTime() unixTime {
	return unixTime{r.rttMeasureTime.Unix(), r.rttMeasureTime.UnixNano()}
}

// loadRttMeasureTime is invoked by stateify.
func (r *rcvBufAutoTuneParams) loadRttMeasureTime(unix unixTime) {
	r.rttMeasureTime = time.Unix(unix.second, unix.nano)
}
