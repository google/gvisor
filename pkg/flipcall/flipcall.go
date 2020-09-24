// Copyright 2019 The gVisor Authors.
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

// Package flipcall implements a protocol providing Fast Local Interprocess
// Procedure Calls between mutually-distrusting processes.
package flipcall

import (
	"fmt"
	"math"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// An Endpoint provides the ability to synchronously transfer data and control
// to a connected peer Endpoint, which may be in another process.
//
// Since the Endpoint control transfer model is synchronous, at any given time
// one Endpoint "has control" (designated the active Endpoint), and the other
// is "waiting for control" (designated the inactive Endpoint). Users of the
// flipcall package designate one Endpoint as the client, which is initially
// active, and the other as the server, which is initially inactive. See
// flipcall_example_test.go for usage.
type Endpoint struct {
	// packet is a pointer to the beginning of the packet window. (Since this
	// is a raw OS memory mapping and not a Go object, it does not need to be
	// represented as an unsafe.Pointer.) packet is immutable.
	packet uintptr

	// dataCap is the size of the datagram part of the packet window in bytes.
	// dataCap is immutable.
	dataCap uint32

	// activeState is csClientActive if this is a client Endpoint and
	// csServerActive if this is a server Endpoint.
	activeState uint32

	// inactiveState is csServerActive if this is a client Endpoint and
	// csClientActive if this is a server Endpoint.
	inactiveState uint32

	// shutdown is non-zero if Endpoint.Shutdown() has been called, or if the
	// Endpoint has acknowledged shutdown initiated by the peer. shutdown is
	// accessed using atomic memory operations.
	//
	// +checkatomic
	shutdown uint32

	ctrl endpointControlImpl
}

// EndpointSide indicates which side of a connection an Endpoint belongs to.
type EndpointSide int

const (
	// ClientSide indicates that an Endpoint is a client (initially-active;
	// first method call should be Connect).
	ClientSide EndpointSide = iota

	// ServerSide indicates that an Endpoint is a server (initially-inactive;
	// first method call should be RecvFirst.)
	ServerSide
)

// Init must be called on zero-value Endpoints before first use. If it
// succeeds, ep.Destroy() must be called once the Endpoint is no longer in use.
//
// pwd represents the packet window used to exchange data with the peer
// Endpoint. FD may differ between Endpoints if they are in different
// processes, but must represent the same file. The packet window must
// initially be filled with zero bytes.
func (ep *Endpoint) Init(side EndpointSide, pwd PacketWindowDescriptor, opts ...EndpointOption) error {
	switch side {
	case ClientSide:
		ep.activeState = csClientActive
		ep.inactiveState = csServerActive
	case ServerSide:
		ep.activeState = csServerActive
		ep.inactiveState = csClientActive
	default:
		return fmt.Errorf("invalid EndpointSide: %v", side)
	}
	if pwd.Length < pageSize {
		return fmt.Errorf("packet window size (%d) less than minimum (%d)", pwd.Length, pageSize)
	}
	if pwd.Length > math.MaxUint32 {
		return fmt.Errorf("packet window size (%d) exceeds maximum (%d)", pwd.Length, math.MaxUint32)
	}
	m, e := packetWindowMmap(pwd)
	if e != 0 {
		return fmt.Errorf("failed to mmap packet window: %v", e)
	}
	ep.packet = m
	ep.dataCap = uint32(pwd.Length) - uint32(PacketHeaderBytes)
	if err := ep.ctrlInit(opts...); err != nil {
		ep.unmapPacket()
		return err
	}
	return nil
}

// NewEndpoint is a convenience function that returns an initialized Endpoint
// allocated on the heap.
func NewEndpoint(side EndpointSide, pwd PacketWindowDescriptor, opts ...EndpointOption) (*Endpoint, error) {
	var ep Endpoint
	if err := ep.Init(side, pwd, opts...); err != nil {
		return nil, err
	}
	return &ep, nil
}

// An EndpointOption configures an Endpoint.
type EndpointOption interface {
	isEndpointOption()
}

// Destroy releases resources owned by ep. No other Endpoint methods may be
// called after Destroy.
func (ep *Endpoint) Destroy() {
	ep.unmapPacket()
}

func (ep *Endpoint) unmapPacket() {
	unix.RawSyscall(unix.SYS_MUNMAP, ep.packet, uintptr(ep.dataCap)+PacketHeaderBytes, 0)
	ep.packet = 0
}

// Shutdown causes concurrent and future calls to ep.Connect(), ep.SendRecv(),
// ep.RecvFirst(), and ep.SendLast(), as well as the same calls in the peer
// Endpoint, to unblock and return ShutdownErrors. It does not wait for
// concurrent calls to return. Successive calls to Shutdown have no effect.
//
// Shutdown is the only Endpoint method that may be called concurrently with
// other methods on the same Endpoint.
func (ep *Endpoint) Shutdown() {
	if atomic.SwapUint32(&ep.shutdown, 1) != 0 {
		// ep.Shutdown() has previously been called.
		return
	}
	ep.ctrlShutdown()
}

// isShutdownLocally returns true if ep.Shutdown() has been called.
func (ep *Endpoint) isShutdownLocally() bool {
	return atomic.LoadUint32(&ep.shutdown) != 0
}

// ShutdownError is returned by most Endpoint methods after Endpoint.Shutdown()
// has been called.
type ShutdownError struct{}

// Error implements error.Error.
func (ShutdownError) Error() string {
	return "flipcall connection shutdown"
}

// DataCap returns the maximum datagram size supported by ep. Equivalently,
// DataCap returns len(ep.Data()).
func (ep *Endpoint) DataCap() uint32 {
	return ep.dataCap
}

// Connection state.
const (
	// The client is, by definition, initially active, so this must be 0.
	csClientActive = 0
	csServerActive = 1
	csShutdown     = 2
)

// Connect blocks until the peer Endpoint has called Endpoint.RecvFirst().
//
// Preconditions:
// * ep is a client Endpoint.
// * ep.Connect(), ep.RecvFirst(), ep.SendRecv(), and ep.SendLast() have never
//   been called.
func (ep *Endpoint) Connect() error {
	err := ep.ctrlConnect()
	if err == nil {
		raceBecomeActive()
	}
	return err
}

// RecvFirst blocks until the peer Endpoint calls Endpoint.SendRecv(), then
// returns the datagram length specified by that call.
//
// Preconditions:
// * ep is a server Endpoint.
// * ep.SendRecv(), ep.RecvFirst(), and ep.SendLast() have never been called.
func (ep *Endpoint) RecvFirst() (uint32, error) {
	if err := ep.ctrlWaitFirst(); err != nil {
		return 0, err
	}
	raceBecomeActive()
	recvDataLen := atomic.LoadUint32(ep.dataLen())
	if recvDataLen > ep.dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, ep.dataCap)
	}
	return recvDataLen, nil
}

// SendRecv transfers control to the peer Endpoint, causing its call to
// Endpoint.SendRecv() or Endpoint.RecvFirst() to return with the given
// datagram length, then blocks until the peer Endpoint calls
// Endpoint.SendRecv() or Endpoint.SendLast().
//
// Preconditions:
// * dataLen <= ep.DataCap().
// * No previous call to ep.SendRecv() or ep.RecvFirst() has returned an error.
// * ep.SendLast() has never been called.
// * If ep is a client Endpoint, ep.Connect() has previously been called and
//   returned nil.
func (ep *Endpoint) SendRecv(dataLen uint32) (uint32, error) {
	if dataLen > ep.dataCap {
		panic(fmt.Sprintf("attempting to send packet with datagram length %d (maximum %d)", dataLen, ep.dataCap))
	}
	// This store can safely be non-atomic: Under correct operation we should
	// be the only thread writing ep.dataLen(), and ep.ctrlRoundTrip() will
	// synchronize with the receiver. We will not read from ep.dataLen() until
	// after ep.ctrlRoundTrip(), so if the peer is mutating it concurrently then
	// they can only shoot themselves in the foot.
	*ep.dataLen() = dataLen
	raceBecomeInactive()
	if err := ep.ctrlRoundTrip(); err != nil {
		return 0, err
	}
	raceBecomeActive()
	recvDataLen := atomic.LoadUint32(ep.dataLen())
	if recvDataLen > ep.dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, ep.dataCap)
	}
	return recvDataLen, nil
}

// SendLast causes the peer Endpoint's call to Endpoint.SendRecv() or
// Endpoint.RecvFirst() to return with the given datagram length.
//
// Preconditions:
// * dataLen <= ep.DataCap().
// * No previous call to ep.SendRecv() or ep.RecvFirst() has returned an error.
// * ep.SendLast() has never been called.
// * If ep is a client Endpoint, ep.Connect() has previously been called and
//   returned nil.
func (ep *Endpoint) SendLast(dataLen uint32) error {
	if dataLen > ep.dataCap {
		panic(fmt.Sprintf("attempting to send packet with datagram length %d (maximum %d)", dataLen, ep.dataCap))
	}
	*ep.dataLen() = dataLen
	raceBecomeInactive()
	if err := ep.ctrlWakeLast(); err != nil {
		return err
	}
	return nil
}
