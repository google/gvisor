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

package flipcall

import (
	"fmt"
	"math"
	"reflect"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// An Endpoint provides the ability to synchronously transfer data and control
// to a connected peer Endpoint, which may be in another process.
//
// Since the Endpoint control transfer model is synchronous, at any given time
// one Endpoint "has control" (designated the *active* Endpoint), and the other
// is "waiting for control" (designated the *inactive* Endpoint). Users of the
// flipcall package arbitrarily designate one Endpoint as initially-active, and
// the other as initially-inactive; in a client/server protocol, the client
// Endpoint is usually initially-active (able to send a request) and the server
// Endpoint is usually initially-inactive (waiting for a request). The
// initially-active Endpoint writes data to be sent to Endpoint.Data(), and
// then synchronously transfers control to the inactive Endpoint by calling
// Endpoint.SendRecv(), becoming the inactive Endpoint in the process. The
// initially-inactive Endpoint waits for control by calling
// Endpoint.RecvFirst(); receiving control causes it to become the active
// Endpoint. After this, the protocol is symmetric: the active Endpoint reads
// data sent by the peer by reading from Endpoint.Data(), writes data to be
// sent to the peer into Endpoint.Data(), and then calls Endpoint.SendRecv() to
// exchange roles with the peer, which blocks until the peer has done the same.
type Endpoint struct {
	// shutdown is non-zero if Endpoint.Shutdown() has been called. shutdown is
	// accessed using atomic memory operations.
	shutdown uint32

	// dataCap is the size of the datagram part of the packet window in bytes.
	// dataCap is immutable.
	dataCap uint32

	// packet is the beginning of the packet window. packet is immutable.
	packet unsafe.Pointer

	ctrl endpointControlState
}

// Init must be called on zero-value Endpoints before first use. If it
// succeeds, Destroy() must be called once the Endpoint is no longer in use.
//
// ctrlMode specifies how connected Endpoints will exchange control. Both
// connected Endpoints must specify the same value for ctrlMode.
//
// pwd represents the packet window used to exchange data with the peer
// Endpoint. FD may differ between Endpoints if they are in different
// processes, but must represent the same file. The packet window must
// initially be filled with zero bytes.
func (ep *Endpoint) Init(ctrlMode ControlMode, pwd PacketWindowDescriptor) error {
	if pwd.Length < pageSize {
		return fmt.Errorf("packet window size (%d) less than minimum (%d)", pwd.Length, pageSize)
	}
	if pwd.Length > math.MaxUint32 {
		return fmt.Errorf("packet window size (%d) exceeds maximum (%d)", pwd.Length, math.MaxUint32)
	}
	m, _, e := syscall.Syscall6(syscall.SYS_MMAP, 0, uintptr(pwd.Length), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED, uintptr(pwd.FD), uintptr(pwd.Offset))
	if e != 0 {
		return fmt.Errorf("failed to mmap packet window: %v", e)
	}
	ep.dataCap = uint32(pwd.Length) - uint32(packetHeaderBytes)
	ep.packet = (unsafe.Pointer)(m)
	if err := ep.initControlState(ctrlMode); err != nil {
		ep.unmapPacket()
		return err
	}
	return nil
}

// NewEndpoint is a convenience function that returns an initialized Endpoint
// allocated on the heap.
func NewEndpoint(ctrlMode ControlMode, pwd PacketWindowDescriptor) (*Endpoint, error) {
	var ep Endpoint
	if err := ep.Init(ctrlMode, pwd); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (ep *Endpoint) unmapPacket() {
	syscall.Syscall(syscall.SYS_MUNMAP, uintptr(ep.packet), uintptr(ep.dataCap)+packetHeaderBytes, 0)
	ep.dataCap = 0
	ep.packet = nil
}

// Destroy releases resources owned by ep. No other Endpoint methods may be
// called after Destroy.
func (ep *Endpoint) Destroy() {
	ep.unmapPacket()
}

// Packets consist of an 8-byte header followed by an arbitrarily-sized
// datagram. The header consists of:
//
// - A 4-byte native-endian sequence number, which is incremented by the active
// Endpoint after it finishes writing to the packet window. The sequence number
// is needed to handle spurious wakeups.
//
// - A 4-byte native-endian datagram length in bytes.
const (
	sizeofUint32      = unsafe.Sizeof(uint32(0))
	packetHeaderBytes = 2 * sizeofUint32
)

func (ep *Endpoint) seq() *uint32 {
	return (*uint32)(ep.packet)
}

func (ep *Endpoint) dataLen() *uint32 {
	return (*uint32)((unsafe.Pointer)(uintptr(ep.packet) + sizeofUint32))
}

// DataCap returns the maximum datagram size supported by ep in bytes.
func (ep *Endpoint) DataCap() uint32 {
	return ep.dataCap
}

func (ep *Endpoint) data() unsafe.Pointer {
	return unsafe.Pointer(uintptr(ep.packet) + packetHeaderBytes)
}

// Data returns the datagram part of ep's packet window as a byte slice.
//
// Note that the packet window is shared with the potentially-untrusted peer
// Endpoint, which may concurrently mutate the contents of the packet window.
// Thus:
//
// - Readers must not assume that two reads of the same byte in Data() will
// return the same result. In other words, readers should read any given byte
// in Data() at most once.
//
// - Writers must not assume that they will read back the same data that they
// have written. In other words, writers should avoid reading from Data() at
// all.
func (ep *Endpoint) Data() []byte {
	var bs []byte
	bsReflect := (*reflect.SliceHeader)((unsafe.Pointer)(&bs))
	bsReflect.Data = uintptr(ep.data())
	bsReflect.Len = int(ep.DataCap())
	bsReflect.Cap = bsReflect.Len
	return bs
}

// SendRecv transfers control to the peer Endpoint, causing its call to
// Endpoint.SendRecv() or Endpoint.RecvFirst() to return with the given
// datagram length, then blocks until the peer Endpoint calls
// Endpoint.SendRecv() or Endpoint.SendLast().
//
// Preconditions: No previous call to ep.SendRecv() or ep.RecvFirst() has
// returned an error. ep.SendLast() has never been called.
func (ep *Endpoint) SendRecv(dataLen uint32) (uint32, error) {
	dataCap := ep.DataCap()
	if dataLen > dataCap {
		return 0, fmt.Errorf("can't send packet with datagram length %d (maximum %d)", dataLen, dataCap)
	}
	atomic.StoreUint32(ep.dataLen(), dataLen)
	if err := ep.doRoundTrip(); err != nil {
		return 0, err
	}
	recvDataLen := atomic.LoadUint32(ep.dataLen())
	if recvDataLen > dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, dataCap)
	}
	return recvDataLen, nil
}

// RecvFirst blocks until the peer Endpoint calls Endpoint.SendRecv(), then
// returns the datagram length specified by that call.
//
// Preconditions: ep.SendRecv(), ep.RecvFirst(), and ep.SendLast() have never
// been called.
func (ep *Endpoint) RecvFirst() (uint32, error) {
	if err := ep.doWaitFirst(); err != nil {
		return 0, err
	}
	recvDataLen := atomic.LoadUint32(ep.dataLen())
	if dataCap := ep.DataCap(); recvDataLen > dataCap {
		return 0, fmt.Errorf("received packet with invalid datagram length %d (maximum %d)", recvDataLen, dataCap)
	}
	return recvDataLen, nil
}

// SendLast causes the peer Endpoint's call to Endpoint.SendRecv() or
// Endpoint.RecvFirst() to return with the given datagram length.
//
// Preconditions: No previous call to ep.SendRecv() or ep.RecvFirst() has
// returned an error. ep.SendLast() has never been called.
func (ep *Endpoint) SendLast(dataLen uint32) error {
	dataCap := ep.DataCap()
	if dataLen > dataCap {
		return fmt.Errorf("can't send packet with datagram length %d (maximum %d)", dataLen, dataCap)
	}
	atomic.StoreUint32(ep.dataLen(), dataLen)
	if err := ep.doNotifyLast(); err != nil {
		return err
	}
	return nil
}

// Shutdown causes concurrent and future calls to ep.SendRecv(),
// ep.RecvFirst(), and ep.SendLast() to unblock and return errors. It does not
// wait for concurrent calls to return.
func (ep *Endpoint) Shutdown() {
	if atomic.SwapUint32(&ep.shutdown, 1) == 0 {
		ep.interruptForShutdown()
	}
}

func (ep *Endpoint) isShutdown() bool {
	return atomic.LoadUint32(&ep.shutdown) != 0
}

type endpointShutdownError struct{}

// Error implements error.Error.
func (endpointShutdownError) Error() string {
	return "Endpoint.Shutdown() has been called"
}
