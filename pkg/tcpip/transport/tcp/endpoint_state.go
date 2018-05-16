// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"fmt"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
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

	e.notificationWaker.Assert()
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
	case stateListen:
		if !e.segmentQueue.empty() {
			e.drainSegmentLocked()
		}
	case stateConnecting:
		e.drainSegmentLocked()
		if e.state != stateConnected {
			break
		}
		fallthrough
	case stateConnected:
		// FIXME
		panic(tcpip.ErrSaveRejection{fmt.Errorf("endpoint cannot be saved in connected state: local %v:%v, remote %v:%v", e.id.LocalAddress, e.id.LocalPort, e.id.RemoteAddress, e.id.RemotePort)})
	case stateClosed, stateError:
		if e.workerRunning {
			panic(fmt.Sprintf("endpoint still has worker running in closed or error state"))
		}
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.state))
	}
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.stack = stack.StackFromEnv
	e.segmentQueue.setLimit(2 * e.rcvBufSize)
	e.workMu.Init()

	state := e.state
	switch state {
	case stateInitial, stateBound, stateListen, stateConnecting:
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

	switch state {
	case stateBound, stateListen, stateConnecting:
		e.state = stateInitial
		if err := e.Bind(tcpip.FullAddress{Addr: e.id.LocalAddress, Port: e.id.LocalPort}, nil); err != nil {
			panic("endpoint binding failed: " + err.String())
		}
	}

	switch state {
	case stateListen:
		backlog := cap(e.acceptedChan)
		e.acceptedChan = nil
		if err := e.Listen(backlog); err != nil {
			panic("endpoint listening failed: " + err.String())
		}
	}

	switch state {
	case stateConnecting:
		if err := e.Connect(tcpip.FullAddress{NIC: e.boundNICID, Addr: e.connectingAddress, Port: e.id.RemotePort}); err != tcpip.ErrConnectStarted {
			panic("endpoint connecting failed: " + err.String())
		}
	}
}

// saveAcceptedChan is invoked by stateify.
func (e *endpoint) saveAcceptedChan() endpointChan {
	if e.acceptedChan == nil {
		return endpointChan{}
	}
	close(e.acceptedChan)
	buffer := make([]*endpoint, 0, len(e.acceptedChan))
	for ep := range e.acceptedChan {
		buffer = append(buffer, ep)
	}
	if len(buffer) != cap(buffer) {
		panic("endpoint.acceptedChan buffer got consumed by background context")
	}
	c := cap(e.acceptedChan)
	e.acceptedChan = nil
	return endpointChan{buffer: buffer, cap: c}
}

// loadAcceptedChan is invoked by stateify.
func (e *endpoint) loadAcceptedChan(c endpointChan) {
	if c.cap == 0 {
		return
	}
	e.acceptedChan = make(chan *endpoint, c.cap)
	for _, ep := range c.buffer {
		e.acceptedChan <- ep
	}
}

type endpointChan struct {
	buffer []*endpoint
	cap    int
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
