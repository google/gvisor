// Copyright 2018 Google LLC
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

// Package fdbased provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// FD based endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
package fdbased

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

const (
	// MaxMsgsPerRecv is the maximum number of packets we want to retrieve
	// in a single RecvMMsg call.
	MaxMsgsPerRecv = 8
)

// BufConfig defines the shape of the vectorised view used to read packets from the NIC.
var BufConfig = []int{128, 256, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768}

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher func() (bool, *tcpip.Error)

// PacketDispatchMode are the various supported methods of receiving and
// dispatching packets from the underlying FD.
type PacketDispatchMode int

const (
	// Readv is the default dispatch mode and is the least performant of the
	// dispatch options but the one that is supported by all underlying FD
	// types.
	Readv PacketDispatchMode = iota
	// RecvMMsg enables use of recvmmsg() syscall instead of readv() to
	// read inbound packets. This reduces # of syscalls needed to process
	// packets.
	//
	// NOTE: recvmmsg() is only supported for sockets, so if the underlying
	// FD is not a socket then the code will still fall back to the readv()
	// path.
	RecvMMsg
	// PacketMMap enables use of PACKET_RX_RING to receive packets from the
	// NIC. PacketMMap requires that the underlying FD be an AF_PACKET. The
	// primary use-case for this is runsc which uses an AF_PACKET FD to
	// receive packets from the veth device.
	PacketMMap
)

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

	views  [][]buffer.View
	iovecs [][]syscall.Iovec
	// msgHdrs is only used by the RecvMMsg dispatcher.
	msgHdrs []rawfile.MMsgHdr

	inboundDispatcher linkDispatcher
	dispatcher        stack.NetworkDispatcher

	// packetDispatchMode controls the packet dispatcher used by this
	// endpoint.
	packetDispatchMode PacketDispatchMode

	// ringBuffer is only used when PacketMMap dispatcher is used and points
	// to the start of the mmapped PACKET_RX_RING buffer.
	ringBuffer []byte

	// ringOffset is the current offset into the ring buffer where the next
	// inbound packet will be placed by the kernel.
	ringOffset int

	// gsoMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	gsoMaxSize uint32
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	FD                 int
	MTU                uint32
	EthernetHeader     bool
	ClosedFunc         func(*tcpip.Error)
	Address            tcpip.LinkAddress
	SaveRestore        bool
	DisconnectOk       bool
	GSOMaxSize         uint32
	PacketDispatchMode PacketDispatchMode
	TXChecksumOffload  bool
	RXChecksumOffload  bool
}

// New creates a new fd-based endpoint.
//
// Makes fd non-blocking, but does not take ownership of fd, which must remain
// open for the lifetime of the returned endpoint.
func New(opts *Options) tcpip.LinkEndpointID {
	if err := syscall.SetNonblock(opts.FD, true); err != nil {
		// TODO : replace panic with an error return.
		panic(fmt.Sprintf("syscall.SetNonblock(%v) failed: %v", opts.FD, err))
	}

	caps := stack.LinkEndpointCapabilities(0)
	if opts.RXChecksumOffload {
		caps |= stack.CapabilityRXChecksumOffload
	}

	if opts.TXChecksumOffload {
		caps |= stack.CapabilityTXChecksumOffload
	}

	hdrSize := 0
	if opts.EthernetHeader {
		hdrSize = header.EthernetMinimumSize
		caps |= stack.CapabilityResolutionRequired
	}

	if opts.SaveRestore {
		caps |= stack.CapabilitySaveRestore
	}

	if opts.DisconnectOk {
		caps |= stack.CapabilityDisconnectOk
	}

	e := &endpoint{
		fd:                 opts.FD,
		mtu:                opts.MTU,
		caps:               caps,
		closed:             opts.ClosedFunc,
		addr:               opts.Address,
		hdrSize:            hdrSize,
		packetDispatchMode: opts.PacketDispatchMode,
	}

	if opts.GSOMaxSize != 0 && isSocketFD(opts.FD) {
		e.caps |= stack.CapabilityGSO
		e.gsoMaxSize = opts.GSOMaxSize
	}
	if isSocketFD(opts.FD) && e.packetDispatchMode == PacketMMap {
		if err := e.setupPacketRXRing(); err != nil {
			// TODO: replace panic with an error return.
			panic(fmt.Sprintf("e.setupPacketRXRing failed: %v", err))
		}
		e.inboundDispatcher = e.packetMMapDispatch
		return stack.RegisterLinkEndpoint(e)
	}

	// For non-socket FDs we read one packet a time (e.g. TAP devices)
	msgsPerRecv := 1
	e.inboundDispatcher = e.dispatch
	// If the provided FD is a socket then we optimize packet reads by
	// using recvmmsg() instead of read() to read packets in a batch.
	if isSocketFD(opts.FD) && e.packetDispatchMode == RecvMMsg {
		e.inboundDispatcher = e.recvMMsgDispatch
		msgsPerRecv = MaxMsgsPerRecv
	}

	e.views = make([][]buffer.View, msgsPerRecv)
	for i := range e.views {
		e.views[i] = make([]buffer.View, len(BufConfig))
	}
	e.iovecs = make([][]syscall.Iovec, msgsPerRecv)
	iovLen := len(BufConfig)
	if e.Capabilities()&stack.CapabilityGSO != 0 {
		// virtioNetHdr is prepended before each packet.
		iovLen++
	}
	for i := range e.iovecs {
		e.iovecs[i] = make([]syscall.Iovec, iovLen)
	}
	e.msgHdrs = make([]rawfile.MMsgHdr, msgsPerRecv)
	for i := range e.msgHdrs {
		e.msgHdrs[i].Msg.Iov = &e.iovecs[i][0]
		e.msgHdrs[i].Msg.Iovlen = uint64(iovLen)
	}

	return stack.RegisterLinkEndpoint(e)
}

func isSocketFD(fd int) bool {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		// TODO : replace panic with an error return.
		panic(fmt.Sprintf("syscall.Fstat(%v,...) failed: %v", fd, err))
	}
	return (stat.Mode & syscall.S_IFSOCK) == syscall.S_IFSOCK
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// Link endpoints are not savable. When transportation endpoints are
	// saved, they stop sending outgoing packets and all incoming packets
	// are rejected.
	go e.dispatchLoop() // S/R-SAFE: See above.
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
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

// virtioNetHdr is declared in linux/virtio_net.h.
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

// These constants are declared in linux/virtio_net.h.
const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

	_VIRTIO_NET_HDR_GSO_TCPV4 = 1
	_VIRTIO_NET_HDR_GSO_TCPV6 = 4
)

// WritePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, hdr buffer.Prependable, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize))
		ethHdr := &header.EthernetFields{
			DstAddr: r.RemoteLinkAddress,
			Type:    protocol,
		}

		// Preserve the src address if it's set in the route.
		if r.LocalLinkAddress != "" {
			ethHdr.SrcAddr = r.LocalLinkAddress
		} else {
			ethHdr.SrcAddr = e.addr
		}
		eth.Encode(ethHdr)
	}

	if e.Capabilities()&stack.CapabilityGSO != 0 {
		vnetHdr := virtioNetHdr{}
		vnetHdrBuf := vnetHdrToByteSlice(&vnetHdr)
		if gso != nil {
			vnetHdr.hdrLen = uint16(hdr.UsedLength())
			if gso.NeedsCsum {
				vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
				vnetHdr.csumStart = header.EthernetMinimumSize + gso.L3HdrLen
				vnetHdr.csumOffset = gso.CsumOffset
			}
			if gso.Type != stack.GSONone && uint16(payload.Size()) > gso.MSS {
				switch gso.Type {
				case stack.GSOTCPv4:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
				case stack.GSOTCPv6:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
				default:
					panic(fmt.Sprintf("Unknown gso type: %v", gso.Type))
				}
				vnetHdr.gsoSize = gso.MSS
			}
		}

		return rawfile.NonBlockingWrite3(e.fd, vnetHdrBuf, hdr.View(), payload.ToView())
	}

	if payload.Size() == 0 {
		return rawfile.NonBlockingWrite(e.fd, hdr.View())
	}

	return rawfile.NonBlockingWrite3(e.fd, hdr.View(), payload.ToView(), nil)
}

// WriteRawPacket writes a raw packet directly to the file descriptor.
func (e *endpoint) WriteRawPacket(dest tcpip.Address, packet []byte) *tcpip.Error {
	return rawfile.NonBlockingWrite(e.fd, packet)
}

func (e *endpoint) capViews(k, n int, buffers []int) int {
	c := 0
	for i, s := range buffers {
		c += s
		if c >= n {
			e.views[k][i].CapLength(s - (c - n))
			return i + 1
		}
	}
	return len(buffers)
}

func (e *endpoint) allocateViews(bufConfig []int) {
	for k := 0; k < len(e.views); k++ {
		var vnetHdr [virtioNetHdrSize]byte
		vnetHdrOff := 0
		if e.Capabilities()&stack.CapabilityGSO != 0 {
			// The kernel adds virtioNetHdr before each packet, but
			// we don't use it, so so we allocate a buffer for it,
			// add it in iovecs but don't add it in a view.
			e.iovecs[k][0] = syscall.Iovec{
				Base: &vnetHdr[0],
				Len:  uint64(virtioNetHdrSize),
			}
			vnetHdrOff++
		}
		for i := 0; i < len(bufConfig); i++ {
			if e.views[k][i] != nil {
				break
			}
			b := buffer.NewView(bufConfig[i])
			e.views[k][i] = b
			e.iovecs[k][i+vnetHdrOff] = syscall.Iovec{
				Base: &b[0],
				Len:  uint64(len(b)),
			}
		}
	}
}

// dispatch reads one packet from the file descriptor and dispatches it.
func (e *endpoint) dispatch() (bool, *tcpip.Error) {
	e.allocateViews(BufConfig)

	n, err := rawfile.BlockingReadv(e.fd, e.iovecs[0])
	if err != nil {
		return false, err
	}
	if e.Capabilities()&stack.CapabilityGSO != 0 {
		// Skip virtioNetHdr which is added before each packet, it
		// isn't used and it isn't in a view.
		n -= virtioNetHdrSize
	}
	if n <= e.hdrSize {
		return false, nil
	}

	var (
		p             tcpip.NetworkProtocolNumber
		remote, local tcpip.LinkAddress
	)
	if e.hdrSize > 0 {
		eth := header.Ethernet(e.views[0][0])
		p = eth.Type()
		remote = eth.SourceAddress()
		local = eth.DestinationAddress()
	} else {
		// We don't get any indication of what the packet is, so try to guess
		// if it's an IPv4 or IPv6 packet.
		switch header.IPVersion(e.views[0][0]) {
		case header.IPv4Version:
			p = header.IPv4ProtocolNumber
		case header.IPv6Version:
			p = header.IPv6ProtocolNumber
		default:
			return true, nil
		}
	}

	used := e.capViews(0, n, BufConfig)
	vv := buffer.NewVectorisedView(n, e.views[0][:used])
	vv.TrimFront(e.hdrSize)

	e.dispatcher.DeliverNetworkPacket(e, remote, local, p, vv)

	// Prepare e.views for another packet: release used views.
	for i := 0; i < used; i++ {
		e.views[0][i] = nil
	}

	return true, nil
}

// recvMMsgDispatch reads more than one packet at a time from the file
// descriptor and dispatches it.
func (e *endpoint) recvMMsgDispatch() (bool, *tcpip.Error) {
	e.allocateViews(BufConfig)

	nMsgs, err := rawfile.BlockingRecvMMsg(e.fd, e.msgHdrs)
	if err != nil {
		return false, err
	}
	// Process each of received packets.
	for k := 0; k < nMsgs; k++ {
		n := int(e.msgHdrs[k].Len)
		if e.Capabilities()&stack.CapabilityGSO != 0 {
			n -= virtioNetHdrSize
		}
		if n <= e.hdrSize {
			return false, nil
		}

		var (
			p             tcpip.NetworkProtocolNumber
			remote, local tcpip.LinkAddress
		)
		if e.hdrSize > 0 {
			eth := header.Ethernet(e.views[k][0])
			p = eth.Type()
			remote = eth.SourceAddress()
			local = eth.DestinationAddress()
		} else {
			// We don't get any indication of what the packet is, so try to guess
			// if it's an IPv4 or IPv6 packet.
			switch header.IPVersion(e.views[k][0]) {
			case header.IPv4Version:
				p = header.IPv4ProtocolNumber
			case header.IPv6Version:
				p = header.IPv6ProtocolNumber
			default:
				return true, nil
			}
		}

		used := e.capViews(k, int(n), BufConfig)
		vv := buffer.NewVectorisedView(int(n), e.views[k][:used])
		vv.TrimFront(e.hdrSize)
		e.dispatcher.DeliverNetworkPacket(e, remote, local, p, vv)

		// Prepare e.views for another packet: release used views.
		for i := 0; i < used; i++ {
			e.views[k][i] = nil
		}
	}

	for k := 0; k < nMsgs; k++ {
		e.msgHdrs[k].Len = 0
	}

	return true, nil
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop() *tcpip.Error {
	for {
		cont, err := e.inboundDispatcher()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			return err
		}
	}
}

// GSOMaxSize returns the maximum GSO packet size.
func (e *endpoint) GSOMaxSize() uint32 {
	return e.gsoMaxSize
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
func (e *InjectableEndpoint) Inject(protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, protocol, vv)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32, capabilities stack.LinkEndpointCapabilities) (tcpip.LinkEndpointID, *InjectableEndpoint) {
	syscall.SetNonblock(fd, true)

	e := &InjectableEndpoint{endpoint: endpoint{
		fd:   fd,
		mtu:  mtu,
		caps: capabilities,
	}}

	return stack.RegisterLinkEndpoint(e), e
}
