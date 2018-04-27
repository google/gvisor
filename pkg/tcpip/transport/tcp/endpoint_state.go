// Copyright 2017 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tcp

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// ErrSaveRejection indicates a failed save due to unsupported tcp endpoint
// state.
type ErrSaveRejection struct {
	Err error
}

// Error returns a sensible description of the save rejection error.
func (e ErrSaveRejection) Error() string {
	return "save rejected due to unsupported endpoint state: " + e.Err.Error()
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets.
	e.segmentQueue.setLimit(0)

	e.mu.RLock()
	defer e.mu.RUnlock()

	switch e.state {
	case stateInitial:
	case stateBound:
	case stateListen:
		if !e.segmentQueue.empty() {
			e.mu.RUnlock()
			e.drainDone = make(chan struct{}, 1)
			e.notificationWaker.Assert()
			<-e.drainDone
			e.mu.RLock()
		}
	case stateConnecting:
		panic(ErrSaveRejection{fmt.Errorf("endpoint in connecting state upon save: local %v:%v, remote %v:%v", e.id.LocalAddress, e.id.LocalPort, e.id.RemoteAddress, e.id.RemotePort)})
	case stateConnected:
		// FIXME
		panic(ErrSaveRejection{fmt.Errorf("endpoint cannot be saved in connected state: local %v:%v, remote %v:%v", e.id.LocalAddress, e.id.LocalPort, e.id.RemoteAddress, e.id.RemotePort)})
	case stateClosed:
	case stateError:
	default:
		panic(fmt.Sprintf("endpoint in unknown state %v", e.state))
	}
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.stack = stack.StackFromEnv

	if e.state == stateListen {
		e.state = stateBound
		backlog := cap(e.acceptedChan)
		e.acceptedChan = nil
		defer func() {
			if err := e.Listen(backlog); err != nil {
				panic("endpoint listening failed: " + err.String())
			}
		}()
	}

	if e.state == stateBound {
		e.state = stateInitial
		defer func() {
			if err := e.Bind(tcpip.FullAddress{Addr: e.id.LocalAddress, Port: e.id.LocalPort}, nil); err != nil {
				panic("endpoint binding failed: " + err.String())
			}
		}()
	}

	if e.state == stateInitial {
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

	e.segmentQueue.setLimit(2 * e.rcvBufSize)
	e.workMu.Init()
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
