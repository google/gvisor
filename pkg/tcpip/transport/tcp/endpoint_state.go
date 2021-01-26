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
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
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
	e.segmentQueue.freeze()

	e.mu.Lock()
	defer e.mu.Unlock()

	epState := e.EndpointState()
	switch {
	case epState == StateInitial || epState == StateBound:
	case epState.connected() || epState.handshake():
		if !e.route.HasSaveRestoreCapability() {
			if !e.route.HasDisconncetOkCapability() {
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
	case epState == StateListen || epState == StateConnecting:
		e.drainSegmentLocked()
		// Refresh epState, since drainSegmentLocked may have changed it.
		epState = e.EndpointState()
		if !epState.closed() {
			if !e.workerRunning {
				panic("endpoint has no worker running in listen, connecting, or connected state")
			}
		}
	case epState.closed():
		for e.workerRunning {
			e.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
			e.mu.Lock()
		}
		if e.workerRunning {
			panic(fmt.Sprintf("endpoint: %+v still has worker running in closed or error state", e.ID))
		}
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.EndpointState()))
	}

	if e.waiterQueue != nil && !e.waiterQueue.IsEmpty() {
		panic("endpoint still has waiters upon save")
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
	atomic.StoreUint32((*uint32)(&e.state), uint32(epState))
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.origEndpointState = e.state
	// Restore the endpoint to InitialState as it will be moved to
	// its origEndpointState during Resume.
	e.state = StateInitial
	// Condition variables and mutexs are not S/R'ed so reinitialize
	// acceptCond with e.acceptMu.
	e.acceptCond = sync.NewCond(&e.acceptMu)
	e.keepalive.timer.init(&e.keepalive.waker)
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.stack = s
	e.ops.InitHandler(e, e.stack)
	e.segmentQueue.thaw()
	epState := e.origEndpointState
	switch epState {
	case StateInitial, StateBound, StateListen, StateConnecting, StateEstablished:
		var ss tcpip.TCPSendBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &ss); err == nil {
			sendBufferSize := e.getSendBufferSize()
			if sendBufferSize < ss.Min || sendBufferSize > ss.Max {
				panic(fmt.Sprintf("endpoint sendBufferSize %d is outside the min and max allowed [%d, %d]", sendBufferSize, ss.Min, ss.Max))
			}
		}

		var rs tcpip.TCPReceiveBufferSizeRangeOption
		if err := e.stack.TransportProtocolOption(ProtocolNumber, &rs); err == nil {
			if e.rcvBufSize < rs.Min || e.rcvBufSize > rs.Max {
				panic(fmt.Sprintf("endpoint.rcvBufSize %d is outside the min and max allowed [%d, %d]", e.rcvBufSize, rs.Min, rs.Max))
			}
		}
	}

	bind := func() {
		addr, _, err := e.checkV4MappedLocked(tcpip.FullAddress{Addr: e.BindAddr, Port: e.ID.LocalPort})
		if err != nil {
			panic("unable to parse BindAddr: " + err.String())
		}
		if ok := e.stack.ReserveTuple(e.effectiveNetProtos, ProtocolNumber, addr.Addr, addr.Port, e.boundPortFlags, e.boundBindToDevice, e.boundDest); !ok {
			panic(fmt.Sprintf("unable to re-reserve tuple (%v, %q, %d, %+v, %d, %v)", e.effectiveNetProtos, addr.Addr, addr.Port, e.boundPortFlags, e.boundBindToDevice, e.boundDest))
		}
		e.isPortReserved = true

		// Mark endpoint as bound.
		e.setEndpointState(StateBound)
	}

	switch {
	case epState.connected():
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
		e.mu.Lock()
		e.state = e.origEndpointState
		closed := e.closed
		e.mu.Unlock()
		e.notifyProtocolGoroutine(notifyTickleWorker)
		if epState == StateFinWait2 && closed {
			// If the endpoint has been closed then make sure we notify so
			// that the FIN_WAIT2 timer is started after a restore.
			e.notifyProtocolGoroutine(notifyClose)
		}
		connectedLoading.Done()
	case epState == StateListen:
		tcpip.AsyncLoading.Add(1)
		go func() {
			connectedLoading.Wait()
			bind()
			backlog := cap(e.acceptedChan)
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
	case epState.connecting():
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
		e.state = StateClose
		e.stack.CompleteTransportEndpointCleanup(e)
		tcpip.DeleteDanglingEndpoint(e)
	case epState == StateError:
		e.state = StateError
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

	e.lastError = tcpip.StringToError(s)
}

// saveRecentTSTime is invoked by stateify.
func (e *endpoint) saveRecentTSTime() unixTime {
	return unixTime{e.recentTSTime.Unix(), e.recentTSTime.UnixNano()}
}

// loadRecentTSTime is invoked by stateify.
func (e *endpoint) loadRecentTSTime(unix unixTime) {
	e.recentTSTime = time.Unix(unix.second, unix.nano)
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

	e.hardError = tcpip.StringToError(s)
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
