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

//go:build linux
// +build linux

// Package xdp provides link layer endpoints backed by AF_XDP sockets.
package xdp

import (
	"fmt"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/qdisc/fifo"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/xdp"
)

// TODO(b/240191988): Turn off GSO, GRO, and LRO. Limit veth MTU to 1500.

// MTU is sized to ensure packets fit inside a 2048 byte XDP frame.
const MTU = 1500

var _ stack.LinkEndpoint = (*endpoint)(nil)

type endpoint struct {
	// fd is the underlying AF_XDP socket.
	fd int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(tcpip.Error)

	networkDispatcher stack.NetworkDispatcher

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// control is used to control the AF_XDP socket.
	control *xdp.ControlBlock

	// stopFD is used to stop the dispatch loop.
	stopFD stopfd.StopFD
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FD is used to read/write packets.
	FD int

	// ClosedFunc is a function to be called when an endpoint's peer (if
	// any) closes its end of the communication pipe.
	ClosedFunc func(tcpip.Error)

	// Address is the link address for this endpoint.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool

	// InterfaceIndex is the interface index of the underlying device.
	InterfaceIndex int
}

// New creates a new endpoint from an AF_XDP socket.
func New(opts *Options) (stack.LinkEndpoint, error) {
	caps := stack.CapabilityResolutionRequired
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	if err := unix.SetNonblock(opts.FD, true); err != nil {
		return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", opts.FD, err)
	}

	ep := &endpoint{
		fd:     opts.FD,
		caps:   caps,
		closed: opts.ClosedFunc,
		addr:   opts.Address,
	}

	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}
	ep.stopFD = stopFD

	// Use a 2MB UMEM to match the PACKET_MMAP dispatcher. There will be
	// 1024 UMEM frames, and each queue will have 512 descriptors. Having
	// fewer descriptors than frames prevents RX and TX from starving each
	// other.
	// TODO(b/240191988): Consider different numbers of descriptors for
	// different queues.
	const (
		frameSize = 2048
		umemSize  = 1 << 21
		nFrames   = umemSize / frameSize
	)
	xdpOpts := xdp.ReadOnlySocketOpts{
		NFrames:      nFrames,
		FrameSize:    frameSize,
		NDescriptors: nFrames / 2,
	}
	ep.control, err = xdp.ReadOnlyFromSocket(opts.FD, uint32(opts.InterfaceIndex), 0 /* queueID */, xdpOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP dispatcher: %v", err)
	}

	ep.control.UMEM.Lock()
	defer ep.control.UMEM.Unlock()

	ep.control.Fill.FillAll(&ep.control.UMEM)

	return ep, nil
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher. If one is already attached,
// then nothing happens.
//
// Attach implements stack.LinkEndpoint.Attach.
func (ep *endpoint) Attach(networkDispatcher stack.NetworkDispatcher) {
	// nil means the NIC is being removed.
	if networkDispatcher == nil && ep.IsAttached() {
		ep.stopFD.Stop()
		ep.Wait()
		ep.networkDispatcher = nil
		return
	}
	if networkDispatcher != nil && ep.networkDispatcher == nil {
		ep.networkDispatcher = networkDispatcher
		// Link endpoints are not savable. When transportation endpoints are
		// saved, they stop sending outgoing packets and all incoming packets
		// are rejected.
		ep.wg.Add(1)
		go func() { // S/R-SAFE: See above.
			defer ep.wg.Done()
			for {
				cont, err := ep.dispatch()
				if err != nil || !cont {
					if ep.closed != nil {
						ep.closed(err)
					}
					return
				}
			}
		}()
	}
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (ep *endpoint) IsAttached() bool {
	return ep.networkDispatcher != nil
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (ep *endpoint) MTU() uint32 {
	return MTU
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (ep *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return ep.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (ep *endpoint) MaxHeaderLength() uint16 {
	return uint16(header.EthernetMinimumSize)
}

// LinkAddress returns the link address of this endpoint.
func (ep *endpoint) LinkAddress() tcpip.LinkAddress {
	return ep.addr
}

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (ep *endpoint) Wait() {
	ep.wg.Wait()
}

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (ep *endpoint) AddHeader(pkt stack.PacketBufferPtr) {
	// Add ethernet header if needed.
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (ep *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// WritePackets writes outbound packets to the underlying file descriptors. If
// one is not currently writable, the packet is dropped.
//
// Each packet in pkts should have the following fields populated:
//   - pkt.EgressRoute
//   - pkt.NetworkProtocolNumber
//
// The following should not be populated, as GSO is not supported with XDP.
//   - pkt.GSOOptions
func (ep *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// We expect to be called via fifo, which imposes a limit of
	// fifo.BatchSize.
	var preallocatedBatch [fifo.BatchSize]unix.XDPDesc
	batch := preallocatedBatch[:0]

	ep.control.UMEM.Lock()

	ep.control.Completion.FreeAll(&ep.control.UMEM)

	// Reserve TX queue descriptors and umem buffers
	nReserved, index := ep.control.TX.Reserve(&ep.control.UMEM, uint32(pkts.Len()))
	if nReserved == 0 {
		ep.control.UMEM.Unlock()
		return 0, &tcpip.ErrNoBufferSpace{}
	}

	// Allocate UMEM space. In order to release the UMEM lock as soon as
	// possible, we allocate up-front and copy data in after releasing.
	for _, pkt := range pkts.AsSlice() {
		batch = append(batch, unix.XDPDesc{
			Addr: ep.control.UMEM.AllocFrame(),
			Len:  uint32(pkt.Size()),
		})
	}
	ep.control.UMEM.Unlock()

	for i, pkt := range pkts.AsSlice() {
		// Copy packets into UMEM frame.
		frame := ep.control.UMEM.Get(batch[i])
		offset := 0
		for _, buf := range pkt.AsSlices() {
			offset += copy(frame[offset:], buf)
		}
		ep.control.TX.Set(index+uint32(i), batch[i])
	}

	// Notify the kernel that there're packets to write.
	ep.control.TX.Notify()

	return pkts.Len(), nil
}

func (ep *endpoint) dispatch() (bool, tcpip.Error) {
	var views []*bufferv2.View

	for {
		stopped, errno := rawfile.BlockingPollUntilStopped(ep.stopFD.EFD, ep.fd, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return !stopped, rawfile.TranslateErrno(errno)
		}
		if stopped {
			return true, nil
		}

		// Avoid the cost of the poll syscall if possible by peeking
		// until there are no packets left.
		for {
			// We can receive multiple packets at once.
			nReceived, rxIndex := ep.control.RX.Peek()

			if nReceived == 0 {
				break
			}

			// Reuse views to avoid allocating.
			views = views[:0]

			// Populate views quickly so that we can release frames
			// back to the kernel.
			ep.control.UMEM.Lock()
			for i := uint32(0); i < nReceived; i++ {
				// Copy packet bytes into a view and free up the
				// buffer.
				descriptor := ep.control.RX.Get(rxIndex + i)
				data := ep.control.UMEM.Get(descriptor)
				view := bufferv2.NewViewWithData(data)
				views = append(views, view)
				ep.control.UMEM.FreeFrame(descriptor.Addr)
			}
			ep.control.Fill.FillAll(&ep.control.UMEM)
			ep.control.UMEM.Unlock()

			// Process each packet.
			for i := uint32(0); i < nReceived; i++ {
				view := views[i]
				data := view.AsSlice()

				netProto := header.Ethernet(data).Type()

				// Wrap the packet in a PacketBuffer and send it up the stack.
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: bufferv2.MakeWithView(view),
				})
				// AF_XDP packets always have a link header.
				if _, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
					panic(fmt.Sprintf("LinkHeader().Consume(%d) must succeed", header.EthernetMinimumSize))
				}
				ep.networkDispatcher.DeliverNetworkPacket(netProto, pkt)
				pkt.DecRef()
			}
			// Tell the kernel that we're done with these
			// descriptors in the RX queue.
			ep.control.RX.Release(nReceived)
		}

		return true, nil
	}
}
