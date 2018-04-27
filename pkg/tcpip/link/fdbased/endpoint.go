// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fdbased provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// FD based endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package fdbased

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

type endpoint struct {
	// fd is the file descriptor used to send and receive packets.
	fd int

	// mtu (maximum transmission unit) is the maximum size of a packet.
	mtu uint32

	// hdrSize specifies the link-layer header size. If set to 0, no header
	// is added/removed; otherwise an ethernet header is used.
	hdrSize int

	// addr is the address of the endpoint.
	addr tcpip.LinkAddress

	// caps holds the endpoint capabilities.
	caps stack.LinkEndpointCapabilities

	// closed is a function to be called when the FD's peer (if any) closes
	// its end of the communication pipe.
	closed func(*tcpip.Error)

	vv     *buffer.VectorisedView
	iovecs []syscall.Iovec
	views  []buffer.View
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	FD              int
	MTU             uint32
	EthernetHeader  bool
	ChecksumOffload bool
	ClosedFunc      func(*tcpip.Error)
	Address         tcpip.LinkAddress
}

// New creates a new fd-based endpoint.
//
// Makes fd non-blocking, but does not take ownership of fd, which must remain
// open for the lifetime of the returned endpoint.
func New(opts *Options) tcpip.LinkEndpointID {
	syscall.SetNonblock(opts.FD, true)

	caps := stack.LinkEndpointCapabilities(0)
	if opts.ChecksumOffload {
		caps |= stack.CapabilityChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	e := &endpoint{
		fd:      opts.FD,
		mtu:     opts.MTU,
		caps:    caps,
		closed:  opts.ClosedFunc,
		addr:    opts.Address,
		hdrSize: hdrSize,
		views:   make([]buffer.View, len(BufConfig)),
		iovecs:  make([]syscall.Iovec, len(BufConfig)),
	}
	vv := buffer.NewVectorisedView(0, e.views)
	e.vv = &vv
	return stack.RegisterLinkEndpoint(e)
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	go e.dispatchLoop(dispatcher) // S/R-FIXME
}

// MTU implements stack.LinkEndpoint.MTU. It returns the value initialized
// during construction.
func (e *endpoint) MTU() uint32 {
	return e.mtu
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.caps
}

// MaxHeaderLength returns the maximum size of the link-layer header.
func (e *endpoint) MaxHeaderLength() uint16 {
	return uint16(e.hdrSize)
}

// LinkAddress returns the link address of this endpoint.
func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return e.addr
}

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(r *stack.Route, hdr *buffer.Prependable, payload buffer.View, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			DstAddr: r.RemoteLinkAddress,
			SrcAddr: e.addr,
			Type:    protocol,
		})
	}

	if len(payload) == 0 {
		return rawfile.NonBlockingWrite(e.fd, hdr.UsedBytes())

	}

	return rawfile.NonBlockingWrite2(e.fd, hdr.UsedBytes(), payload)
}

func (e *endpoint) capViews(n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			e.views[i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func (e *endpoint) allocateViews(bufConfig []int) {
	for i, v := range e.views {
		if v != nil {
			break
		}
		b := buffer.NewView(bufConfig[i])
		e.views[i] = b
		e.iovecs[i] = syscall.Iovec{
			Base: &b[0],
			Len:  uint64(len(b)),
		}
	}
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) dispatch(d stack.NetworkDispatcher, largeV buffer.View) (bool, *tcpip.Error) {
	e.allocateViews(BufConfig)

	n, err := rawfile.BlockingReadv(e.fd, e.iovecs)
	if err != nil {
		return false, err
	}

	if n <= e.hdrSize {
		return false, nil
	}

	var p tcpip.NetworkProtocolNumber
	var addr tcpip.LinkAddress
	if e.hdrSize > 0 {
		eth := header.Ethernet(e.views[0])
		p = eth.Type()
		addr = eth.SourceAddress()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		switch header.IPVersion(e.views[0]) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	used := e.capViews(n, BufConfig)
	e.vv.SetViews(e.views[:used])
	e.vv.SetSize(n)
	e.vv.TrimFront(e.hdrSize)

	d.DeliverNetworkPacket(e, addr, p, e.vv)

	// Prepare e.views for another packet: release used views.
	for i := 0; i < used; i++ {
		e.views[i] = nil
	}

	return true, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(d stack.NetworkDispatcher) *tcpip.Error {
	v := buffer.NewView(header.MaxIPPacketSize)
	for {
		cont, err := e.dispatch(d, v)
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}

// InjectableEndpoint is an injectable fd-based endpoint. The endpoint writes
// to the FD, but does not read from it. All reads come from injected packets.
type InjectableEndpoint struct {
	endpoint

	dispatcher stack.NetworkDispatcher
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

// Inject injects an inbound packet.
func (e *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv *buffer.VectorisedView) {
	e.dispatcher.DeliverNetworkPacket(e, "", protocol, vv)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32) (tcpip.LinkEndpointID, *InjectableEndpoint) {
	syscall.SetNonblock(fd, true)

	e := &InjectableEndpoint{endpoint: endpoint{
		fd:  fd,
		mtu: mtu,
	}}

	return stack.RegisterLinkEndpoint(e), e
}
