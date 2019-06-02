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

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
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
	case stateInitial, stateBound:
	case stateConnected:
		if e.route.Capabilities()&stack.CapabilitySaveRestore == 0 {
			if e.route.Capabilities()&stack.CapabilityDisconnectOk == 0 {
				panic(tcpip.ErrSaveRejection{fmt.Errorf("endpoint cannot be saved in connected state: local %v:%d, remote %v:%d", e.id.LocalAddress, e.id.LocalPort, e.id.RemoteAddress, e.id.RemotePort)})
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
	case stateListen, stateConnecting:
		e.drainSegmentLocked()
		if e.state != stateClosed && e.state != stateError {
			if !e.workerRunning {
				panic("endpoint has no worker running in listen, connecting, or connected state")
			}
			break
		}
		fallthrough
	case stateError, stateClosed:
		for e.state == stateError && e.workerRunning {
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

	if e.state != stateClosed && !((e.state == stateBound || e.state == stateListen) == e.isPortReserved) {
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
func (e *endpoint) saveState() endpointState {
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
func (e *endpoint) loadState(state endpointState) {
	// This is to ensure that the loading wait groups include all applicable
	// endpoints before any asynchronous calls to the Wait() methods.
	switch state {
	case stateConnected:
		connectedLoading.Add(1)
	case stateListen:
		listenLoading.Add(1)
	case stateConnecting:
		connectingLoading.Add(1)
	}
	e.state = state
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.stack = stack.StackFromEnv
	e.segmentQueue.setLimit(MaxUnprocessedSegments)
	e.workMu.Init()

	state := e.state
	switch state {
	case stateInitial, stateBound, stateListen, stateConnecting, stateConnected:
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
		e.state = stateInitial
		if len(e.bindAddress) == 0 {
			e.bindAddress = e.id.LocalAddress
		}
		if err := e.Bind(tcpip.FullAddress{Addr: e.bindAddress, Port: e.id.LocalPort}); err != nil {
			panic("endpoint binding failed: " + err.String())
		}
	}

	switch state {
	case stateConnected:
		bind()
		if len(e.connectingAddress) == 0 {
			// This endpoint is accepted by netstack but not yet by
			// the app. If the endpoint is IPv6 but the remote
			// address is IPv4, we need to connect as IPv6 so that
			// dual-stack mode can be properly activated.
			if e.netProto == header.IPv6ProtocolNumber && len(e.id.RemoteAddress) != header.IPv6AddressSize {
				e.connectingAddress = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff" + e.id.RemoteAddress
			} else {
				e.connectingAddress = e.id.RemoteAddress
			}
		}
		// Reset the scoreboard to reinitialize the sack information as
		// we do not restore SACK information.
		e.scoreboard.Reset()
		if err := e.connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.id.RemotePort}, false, e.workerRunning); err != tcpip.ErrConnectStarted {
			panic("endpoint connecting failed: " + err.String())
		}
		connectedLoading.Done()
	case stateListen:
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
	case stateConnecting:
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
	case stateBound:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			listenLoading.Wait()
			connectingLoading.Wait()
			bind()
			tcpip.AsyncLoading.Done()
		}()
	case stateClosed:
		if e.isPortReserved {
			tcpip.AsyncLoading.Add(1)
			go func() {
				connectedLoading.Wait()
				listenLoading.Wait()
				connectingLoading.Wait()
				bind()
				e.state = stateClosed
				tcpip.AsyncLoading.Done()
			}()
		}
		fallthrough
	case stateError:
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
func (e *endpoint) saveHardError() string {
	if e.hardError == nil {
		return ""
	}

	return e.hardError.String()
}

// loadHardError is invoked by stateify.
func (e *endpoint) loadHardError(s string) {
	if s == "" {
		return
	}

	e.hardError = loadError(s)
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
