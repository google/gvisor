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
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*endpoint)(nil)

type endpoint struct {
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(tcpip.Error)

	inboundDispatcher dispatcher
	networkDispatcher stack.NetworkDispatcher

	// wg keeps track of running goroutines.
	wg sync.WaitGroup
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FD is used to read/write packets.
	FD int

	// MTU is the mtu to use for this endpoint.
	MTU uint32

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
		mtu:    opts.MTU,
		caps:   caps,
		closed: opts.ClosedFunc,
		addr:   opts.Address,
	}

	if err := ep.inboundDispatcher.init(opts.FD, ep, opts.InterfaceIndex); err != nil {
		return nil, fmt.Errorf("ep.inboundDispatcher.init(%d, %+v) = %v", opts.FD, ep, err)
	}

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
		ep.inboundDispatcher.Stop()
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
				cont, err := ep.inboundDispatcher.dispatch()
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
	return ep.mtu
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
	return 0, &tcpip.ErrNotSupported{}
}
