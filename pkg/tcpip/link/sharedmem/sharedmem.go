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

// +build linux

// Package sharedmem provides the implemention of data-link layer endpoints
// backed by shared memory.
//
// Shared memory endpoints can be used in the networking stack by calling New()
// to create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package sharedmem

import (
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sharedmem/queue"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// QueueConfig holds all the file descriptors needed to describe a tx or rx
// queue over shared memory. It is used when creating new shared memory
// endpoints to describe tx and rx queues.
type QueueConfig struct {
	// DataFD is a file descriptor for the file that contains the data to
	// be transmitted via this queue. Descriptors contain offsets within
	// this file.
	DataFD int

	// EventFD is a file descriptor for the event that is signaled when
	// data is becomes available in this queue.
	EventFD int

	// TxPipeFD is a file descriptor for the tx pipe associated with the
	// queue.
	TxPipeFD int

	// RxPipeFD is a file descriptor for the rx pipe associated with the
	// queue.
	RxPipeFD int

	// SharedDataFD is a file descriptor for the file that contains shared
	// state between the two ends of the queue. This data specifies, for
	// example, whether EventFD signaling is enabled or disabled.
	SharedDataFD int
}

type endpoint struct {
	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// bufferSize is the size of each individual buffer.
	bufferSize uint32

	// addr is the local address of this endpoint.
	addr tcpip.LinkAddress

	// rx is the receive queue.
	rx rx

	// stopRequested is to be accessed atomically only, and determines if
	// the worker goroutines should stop.
	stopRequested uint32

	// Wait group used to indicate that all workers have stopped.
	completed sync.WaitGroup

	// mu protects the following fields.
	mu sync.Mutex

	// tx is the transmit queue.
	tx tx

	// workerStarted specifies whether the worker goroutine was started.
	workerStarted bool
}

// New creates a new shared-memory-based endpoint. Buffers will be broken up
// into buffers of "bufferSize" bytes.
func New(mtu, bufferSize uint32, addr tcpip.LinkAddress, tx, rx QueueConfig) (stack.LinkEndpoint, error) {
	e := &endpoint{
		mtu:        mtu,
		bufferSize: bufferSize,
		addr:       addr,
	}

	if err := e.tx.init(bufferSize, &tx); err != nil {
		return nil, err
	}

	if err := e.rx.init(bufferSize, &rx); err != nil {
		e.tx.cleanup()
		return nil, err
	}

	return e, nil
}

// Close frees all resources associated with the endpoint.
func (e *endpoint) Close() {
	// Tell dispatch goroutine to stop, then write to the eventfd so that
	// it wakes up in case it's sleeping.
	atomic.StoreUint32(&e.stopRequested, 1)
	syscall.Write(e.rx.eventFD, []byte{1, 0, 0, 0, 0, 0, 0, 0})

	// Cleanup the queues inline if the worker hasn't started yet; we also
	// know it won't start from now on because stopRequested is set to 1.
	e.mu.Lock()
	workerPresent := e.workerStarted
	e.mu.Unlock()

	if !workerPresent {
		e.tx.cleanup()
		e.rx.cleanup()
	}
}

// Wait implements stack.LinkEndpoint.Wait. It waits until all workers have
// stopped after a Close() call.
func (e *endpoint) Wait() {
	e.completed.Wait()
}

// Attach implements stack.LinkEndpoint.Attach. It launches the goroutine that
// reads packets from the rx queue.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	if !e.workerStarted && atomic.LoadUint32(&e.stopRequested) == 0 {
		e.workerStarted = true
		e.completed.Add(1)
		// Link endpoints are not savable. When transportation endpoints
		// are saved, they stop sending outgoing packets and all
		// incoming packets are rejected.
		go e.dispatchLoop(dispatcher) // S/R-SAFE: see above.
	}
	e.mu.Unlock()
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.workerStarted
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu - header.EthernetMinimumSize
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (*endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return 0
}

// MaxHeaderLength implements stack.LinkEndpoint.MaxHeaderLength. It returns the
// ethernet frame header size.
func (*endpoint) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

// LinkAddress implements stack.LinkEndpoint.LinkAddress. It returns the local
// link address.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(r *stack.Route, _ *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBuffer) *tcpip.Error {
	// Add the ethernet header here.
	eth := header.Ethernet(pkt.Header.Prepend(header.EthernetMinimumSize))
	pkt.LinkHeader = buffer.View(eth)
	ethHdr := &header.EthernetFields{
		DstAddr: r.RemoteLinkAddress,
		Type:    protocol,
	}
	if r.LocalLinkAddress != "" {
		ethHdr.SrcAddr = r.LocalLinkAddress
	} else {
		ethHdr.SrcAddr = e.addr
	}
	eth.Encode(ethHdr)

	v := pkt.Data.ToView()
	// Transmit the packet.
	e.mu.Lock()
	ok := e.tx.transmit(pkt.Header.View(), v)
	e.mu.Unlock()

	if !ok {
		return tcpip.ErrWouldBlock
	}

	return nil
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e *endpoint) WritePackets(r *stack.Route, _ *stack.GSO, pkts stack.PacketBufferList, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	panic("not implemented")
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	v := vv.ToView()
	// Transmit the packet.
	e.mu.Lock()
	ok := e.tx.transmit(v, buffer.View{})
	e.mu.Unlock()

	if !ok {
		return tcpip.ErrWouldBlock
	}

	return nil
}

// dispatchLoop reads packets from the rx queue in a loop and dispatches them
// to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) {
	// Post initial set of buffers.
	limit := e.rx.q.PostedBuffersLimit()
	if l := uint64(len(e.rx.data)) / uint64(e.bufferSize); limit > l {
		limit = l
	}
	for i := uint64(0); i < limit; i++ {
		b := queue.RxBuffer{
			Offset: i * uint64(e.bufferSize),
			Size:   e.bufferSize,
			ID:     i,
		}
		if !e.rx.q.PostBuffers([]queue.RxBuffer{b}) {
			log.Warningf("Unable to post %v-th buffer", i)
		}
	}

	// Read in a loop until a stop is requested.
	var rxb []queue.RxBuffer
	for atomic.LoadUint32(&e.stopRequested) == 0 {
		var n uint32
		rxb, n = e.rx.postAndReceive(rxb, &e.stopRequested)

		// Copy data from the shared area to its own buffer, then
		// prepare to repost the buffer.
		b := make([]byte, n)
		offset := uint32(0)
		for i := range rxb {
			copy(b[offset:], e.rx.data[rxb[i].Offset:][:rxb[i].Size])
			offset += rxb[i].Size

			rxb[i].Size = e.bufferSize
		}

		if n < header.EthernetMinimumSize {
			continue
		}

		// Send packet up the stack.
		eth := header.Ethernet(b[:header.EthernetMinimumSize])
		d.DeliverNetworkPacket(e, eth.SourceAddress(), eth.DestinationAddress(), eth.Type(), stack.PacketBuffer{
			Data:       buffer.View(b[header.EthernetMinimumSize:]).ToVectorisedView(),
			LinkHeader: buffer.View(eth),
		})
	}

	// Clean state.
	e.tx.cleanup()
	e.rx.cleanup()

	e.completed.Done()
}
