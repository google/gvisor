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

// Package fdbased provides the implemention of data-link layer endpoints
// backed by boundary-preserving file descriptors (e.g., TUN devices,
// seqpacket/datagram sockets).
//
// FD based endpoints can be used in the networking stack by calling New() to
// create a new endpoint, and then passing it as an argument to
// Stack.CreateNIC().
//
// FD based endpoints can use more than one file descriptor to read incoming
// packets. If there are more than one FDs specified and the underlying FD is an
// AF_PACKET then the endpoint will enable FANOUT mode on the socket so that the
// host kernel will consistently hash the packets to the sockets. This ensures
// that packets for the same TCP streams are not reordered.
//
// Similarly if more than one FD's are specified where the underlying FD is not
// AF_PACKET then it's the caller's responsibility to ensure that all inbound
// packets on the descriptors are consistently 5 tuple hashed to one of the
// descriptors to prevent TCP reordering.
//
// Since netstack today does not compute 5 tuple hashes for outgoing packets we
// only use the first FD to write outbound packets. Once 5 tuple hashes for
// all outbound packets are available we will make use of all underlying FD's to
// write outbound packets.
package fdbased

import (
	"fmt"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	dispatch() (bool, *tcpip.Error)
}

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

func (p PacketDispatchMode) String() string {
	switch p {
	case Readv:
		return "Readv"
	case RecvMMsg:
		return "RecvMMsg"
	case PacketMMap:
		return "PacketMMap"
	default:
		return fmt.Sprintf("unknown packet dispatch mode %v", p)
	}
}

type endpoint struct {
	// fds is the set of file descriptors each identifying one inbound/outbound
	// channel. The endpoint will dispatch from all inbound channels as well as
	// hash outbound packets to specific channels based on the packet hash.
	fds []int

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

	inboundDispatchers []linkDispatcher
	dispatcher         stack.NetworkDispatcher

	// packetDispatchMode controls the packet dispatcher used by this
	// endpoint.
	packetDispatchMode PacketDispatchMode

	// gsoMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	gsoMaxSize uint32

	// wg keeps track of running goroutines.
	wg sync.WaitGroup
}

// Options specify the details about the fd-based endpoint to be created.
type Options struct {
	// FDs is a set of FDs used to read/write packets.
	FDs []int

	// MTU is the mtu to use for this endpoint.
	MTU uint32

	// EthernetHeader if true, indicates that the endpoint should read/write
	// ethernet frames instead of IP packets.
	EthernetHeader bool

	// ClosedFunc is a function to be called when an endpoint's peer (if
	// any) closes its end of the communication pipe.
	ClosedFunc func(*tcpip.Error)

	// Address is the link address for this endpoint. Only used if
	// EthernetHeader is true.
	Address tcpip.LinkAddress

	// SaveRestore if true, indicates that this NIC capability set should
	// include CapabilitySaveRestore
	SaveRestore bool

	// DisconnectOk if true, indicates that this NIC capability set should
	// include CapabilityDisconnectOk.
	DisconnectOk bool

	// GSOMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	GSOMaxSize uint32

	// SoftwareGSOEnabled indicates whether software GSO is enabled or not.
	SoftwareGSOEnabled bool

	// PacketDispatchMode specifies the type of inbound dispatcher to be
	// used for this endpoint.
	PacketDispatchMode PacketDispatchMode

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool
}

// fanoutID is used for AF_PACKET based endpoints to enable PACKET_FANOUT
// support in the host kernel. This allows us to use multiple FD's to receive
// from the same underlying NIC. The fanoutID needs to be the same for a given
// set of FD's that point to the same NIC. Trying to set the PACKET_FANOUT
// option for an FD with a fanoutID already in use by another FD for a different
// NIC will return an EINVAL.
var fanoutID = 1

// New creates a new fd-based endpoint.
//
// Makes fd non-blocking, but does not take ownership of fd, which must remain
// open for the lifetime of the returned endpoint (until after the endpoint has
// stopped being using and Wait returns).
func New(opts *Options) (stack.LinkEndpoint, error) {
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

	if len(opts.FDs) == 0 {
		return nil, fmt.Errorf("opts.FD is empty, at least one FD must be specified")
	}

	e := &endpoint{
		fds:                opts.FDs,
		mtu:                opts.MTU,
		caps:               caps,
		closed:             opts.ClosedFunc,
		addr:               opts.Address,
		hdrSize:            hdrSize,
		packetDispatchMode: opts.PacketDispatchMode,
	}

	// Create per channel dispatchers.
	for i := 0; i < len(e.fds); i++ {
		fd := e.fds[i]
		if err := syscall.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("syscall.SetNonblock(%v) failed: %v", fd, err)
		}

		isSocket, err := isSocketFD(fd)
		if err != nil {
			return nil, err
		}
		if isSocket {
			if opts.GSOMaxSize != 0 {
				if opts.SoftwareGSOEnabled {
					e.caps |= stack.CapabilitySoftwareGSO
				} else {
					e.caps |= stack.CapabilityHardwareGSO
				}
				e.gsoMaxSize = opts.GSOMaxSize
			}
		}
		inboundDispatcher, err := createInboundDispatcher(e, fd, isSocket)
		if err != nil {
			return nil, fmt.Errorf("createInboundDispatcher(...) = %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	// Increment fanoutID to ensure that we don't re-use the same fanoutID for
	// the next endpoint.
	fanoutID++

	return e, nil
}

func createInboundDispatcher(e *endpoint, fd int, isSocket bool) (linkDispatcher, error) {
	// By default use the readv() dispatcher as it works with all kinds of
	// FDs (tap/tun/unix domain sockets and af_packet).
	inboundDispatcher, err := newReadVDispatcher(fd, e)
	if err != nil {
		return nil, fmt.Errorf("newReadVDispatcher(%d, %+v) = %v", fd, e, err)
	}

	if isSocket {
		sa, err := unix.Getsockname(fd)
		if err != nil {
			return nil, fmt.Errorf("unix.Getsockname(%d) = %v", fd, err)
		}
		switch sa.(type) {
		case *unix.SockaddrLinklayer:
			// enable PACKET_FANOUT mode is the underlying socket is
			// of type AF_PACKET.
			const fanoutType = 0x8000 // PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG
			fanoutArg := fanoutID | fanoutType<<16
			if err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
				return nil, fmt.Errorf("failed to enable PACKET_FANOUT option: %v", err)
			}
		}

		switch e.packetDispatchMode {
		case PacketMMap:
			inboundDispatcher, err = newPacketMMapDispatcher(fd, e)
			if err != nil {
				return nil, fmt.Errorf("newPacketMMapDispatcher(%d, %+v) = %v", fd, e, err)
			}
		case RecvMMsg:
			// If the provided FD is a socket then we optimize
			// packet reads by using recvmmsg() instead of read() to
			// read packets in a batch.
			inboundDispatcher, err = newRecvMMsgDispatcher(fd, e)
			if err != nil {
				return nil, fmt.Errorf("newRecvMMsgDispatcher(%d, %+v) = %v", fd, e, err)
			}
		}
	}
	return inboundDispatcher, nil
}

func isSocketFD(fd int) (bool, error) {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return false, fmt.Errorf("syscall.Fstat(%v,...) failed: %v", fd, err)
	}
	return (stat.Mode & syscall.S_IFSOCK) == syscall.S_IFSOCK, nil
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	// Link endpoints are not savable. When transportation endpoints are
	// saved, they stop sending outgoing packets and all incoming packets
	// are rejected.
	for i := range e.inboundDispatchers {
		e.wg.Add(1)
		go func(i int) { // S/R-SAFE: See above.
			e.dispatchLoop(e.inboundDispatchers[i])
			e.wg.Done()
		}(i)
	}
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

// Wait implements stack.LinkEndpoint.Wait. It waits for the endpoint to stop
// reading from its FD.
func (e *endpoint) Wait() {
	e.wg.Wait()
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
func (e *endpoint) WritePacket(r *stack.Route, gso *stack.GSO, protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) *tcpip.Error {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(pkt.Header.Prepend(header.EthernetMinimumSize))
		pkt.LinkHeader = buffer.View(eth)
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

	if e.Capabilities()&stack.CapabilityHardwareGSO != 0 {
		vnetHdr := virtioNetHdr{}
		vnetHdrBuf := vnetHdrToByteSlice(&vnetHdr)
		if gso != nil {
			vnetHdr.hdrLen = uint16(pkt.Header.UsedLength())
			if gso.NeedsCsum {
				vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
				vnetHdr.csumStart = header.EthernetMinimumSize + gso.L3HdrLen
				vnetHdr.csumOffset = gso.CsumOffset
			}
			if gso.Type != stack.GSONone && uint16(pkt.Data.Size()) > gso.MSS {
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

		return rawfile.NonBlockingWrite3(e.fds[0], vnetHdrBuf, pkt.Header.View(), pkt.Data.ToView())
	}

	if pkt.Data.Size() == 0 {
		return rawfile.NonBlockingWrite(e.fds[0], pkt.Header.View())
	}

	return rawfile.NonBlockingWrite3(e.fds[0], pkt.Header.View(), pkt.Data.ToView(), nil)
}

// WritePackets writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) WritePackets(r *stack.Route, gso *stack.GSO, hdrs []stack.PacketDescriptor, payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) (int, *tcpip.Error) {
	var ethHdrBuf []byte
	// hdr + data
	iovLen := 2
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		ethHdrBuf = make([]byte, header.EthernetMinimumSize)
		eth := header.Ethernet(ethHdrBuf)
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
		iovLen++
	}

	n := len(hdrs)

	views := payload.Views()
	/*
	 * Each bondary in views can add one more iovec.
	 *
	 * payload |      |          |         |
	 *         -----------------------------
	 * packets |    |    |    |    |    |  |
	 *         -----------------------------
	 * iovecs  |    | |  |    |  | |    |  |
	 */
	iovec := make([]syscall.Iovec, n*iovLen+len(views)-1)
	mmsgHdrs := make([]rawfile.MMsgHdr, n)

	iovecIdx := 0
	viewIdx := 0
	viewOff := 0
	off := 0
	nextOff := 0
	for i := range hdrs {
		prevIovecIdx := iovecIdx
		mmsgHdr := &mmsgHdrs[i]
		mmsgHdr.Msg.Iov = &iovec[iovecIdx]
		packetSize := hdrs[i].Size
		hdr := &hdrs[i].Hdr

		off = hdrs[i].Off
		if off != nextOff {
			// We stop in a different point last time.
			size := packetSize
			viewIdx = 0
			viewOff = 0
			for size > 0 {
				if size >= len(views[viewIdx]) {
					viewIdx++
					viewOff = 0
					size -= len(views[viewIdx])
				} else {
					viewOff = size
					size = 0
				}
			}
		}
		nextOff = off + packetSize

		if ethHdrBuf != nil {
			v := &iovec[iovecIdx]
			v.Base = &ethHdrBuf[0]
			v.Len = uint64(len(ethHdrBuf))
			iovecIdx++
		}

		v := &iovec[iovecIdx]
		hdrView := hdr.View()
		v.Base = &hdrView[0]
		v.Len = uint64(len(hdrView))
		iovecIdx++

		for packetSize > 0 {
			vec := &iovec[iovecIdx]
			iovecIdx++

			v := views[viewIdx]
			vec.Base = &v[viewOff]
			s := len(v) - viewOff
			if s <= packetSize {
				viewIdx++
				viewOff = 0
			} else {
				s = packetSize
				viewOff += s
			}
			vec.Len = uint64(s)
			packetSize -= s
		}

		mmsgHdr.Msg.Iovlen = uint64(iovecIdx - prevIovecIdx)
	}

	packets := 0
	for packets < n {
		sent, err := rawfile.NonBlockingSendMMsg(e.fds[0], mmsgHdrs)
		if err != nil {
			return packets, err
		}
		packets += sent
		mmsgHdrs = mmsgHdrs[sent:]
	}
	return packets, nil
}

// WriteRawPacket implements stack.LinkEndpoint.WriteRawPacket.
func (e *endpoint) WriteRawPacket(vv buffer.VectorisedView) *tcpip.Error {
	return rawfile.NonBlockingWrite(e.fds[0], vv.ToView())
}

// InjectOutobund implements stack.InjectableEndpoint.InjectOutbound.
func (e *endpoint) InjectOutbound(dest tcpip.Address, packet []byte) *tcpip.Error {
	return rawfile.NonBlockingWrite(e.fds[0], packet)
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) *tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
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

// InjectInbound injects an inbound packet.
func (e *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt tcpip.PacketBuffer) {
	e.dispatcher.DeliverNetworkPacket(e, "" /* remote */, "" /* local */, protocol, pkt)
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32, capabilities stack.LinkEndpointCapabilities) *InjectableEndpoint {
	syscall.SetNonblock(fd, true)

	return &InjectableEndpoint{endpoint: endpoint{
		fds:  []int{fd},
		mtu:  mtu,
		caps: capabilities,
	}}
}
