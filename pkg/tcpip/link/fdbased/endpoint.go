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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// linkDispatcher reads packets from the link FD and dispatches them to the
// NetworkDispatcher.
type linkDispatcher interface {
	Stop()
	dispatch() (bool, tcpip.Error)
	release()
}

// PacketDispatchMode are the various supported methods of receiving and
// dispatching packets from the underlying FD.
type PacketDispatchMode int

// BatchSize is the number of packets to write in each syscall. It is 47
// because when GvisorGSO is in use then a single 65KB TCP segment can get
// split into 46 segments of 1420 bytes and a single 216 byte segment.
const BatchSize = 47

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
		return fmt.Sprintf("unknown packet dispatch mode '%d'", p)
	}
}

var _ stack.LinkEndpoint = (*endpoint)(nil)
var _ stack.GSOEndpoint = (*endpoint)(nil)

type fdInfo struct {
	fd       int
	isSocket bool
}

type endpoint struct {
	// fds is the set of file descriptors each identifying one inbound/outbound
	// channel. The endpoint will dispatch from all inbound channels as well as
	// hash outbound packets to specific channels based on the packet hash.
	fds []fdInfo

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
	closed func(tcpip.Error)

	inboundDispatchers []linkDispatcher

	mu sync.RWMutex
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher

	// packetDispatchMode controls the packet dispatcher used by this
	// endpoint.
	packetDispatchMode PacketDispatchMode

	// gsoMaxSize is the maximum GSO packet size. It is zero if GSO is
	// disabled.
	gsoMaxSize uint32

	// wg keeps track of running goroutines.
	wg sync.WaitGroup

	// gsoKind is the supported kind of GSO.
	gsoKind stack.SupportedGSO

	// maxSyscallHeaderBytes has the same meaning as
	// Options.MaxSyscallHeaderBytes.
	maxSyscallHeaderBytes uintptr

	// writevMaxIovs is the maximum number of iovecs that may be passed to
	// rawfile.NonBlockingWriteIovec, as possibly limited by
	// maxSyscallHeaderBytes. (No analogous limit is defined for
	// rawfile.NonBlockingSendMMsg, since in that case the maximum number of
	// iovecs also depends on the number of mmsghdrs. Instead, if sendBatch
	// encounters a packet whose iovec count is limited by
	// maxSyscallHeaderBytes, it falls back to writing the packet using writev
	// via WritePacket.)
	writevMaxIovs int
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
	ClosedFunc func(tcpip.Error)

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

	// GvisorGSOEnabled indicates whether Gvisor GSO is enabled or not.
	GvisorGSOEnabled bool

	// PacketDispatchMode specifies the type of inbound dispatcher to be
	// used for this endpoint.
	PacketDispatchMode PacketDispatchMode

	// TXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityTXChecksumOffload.
	TXChecksumOffload bool

	// RXChecksumOffload if true, indicates that this endpoints capability
	// set should include CapabilityRXChecksumOffload.
	RXChecksumOffload bool

	// If MaxSyscallHeaderBytes is non-zero, it is the maximum number of bytes
	// of struct iovec, msghdr, and mmsghdr that may be passed by each host
	// system call.
	MaxSyscallHeaderBytes int

	// AFXDPFD is used with the experimental AF_XDP mode.
	// TODO(b/240191988): Use multiple sockets.
	// TODO(b/240191988): How do we handle the MTU issue?
	AFXDPFD *int

	// InterfaceIndex is the interface index of the underlying device.
	InterfaceIndex int
}

// fanoutID is used for AF_PACKET based endpoints to enable PACKET_FANOUT
// support in the host kernel. This allows us to use multiple FD's to receive
// from the same underlying NIC. The fanoutID needs to be the same for a given
// set of FD's that point to the same NIC. Trying to set the PACKET_FANOUT
// option for an FD with a fanoutID already in use by another FD for a different
// NIC will return an EINVAL.
//
// Since fanoutID must be unique within the network namespace, we start with
// the PID to avoid collisions. The only way to be sure of avoiding collisions
// is to run in a new network namespace.
var fanoutID atomicbitops.Int32 = atomicbitops.FromInt32(int32(unix.Getpid()))

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

	if opts.MaxSyscallHeaderBytes < 0 {
		return nil, fmt.Errorf("opts.MaxSyscallHeaderBytes is negative")
	}

	e := &endpoint{
		mtu:                   opts.MTU,
		caps:                  caps,
		closed:                opts.ClosedFunc,
		addr:                  opts.Address,
		hdrSize:               hdrSize,
		packetDispatchMode:    opts.PacketDispatchMode,
		maxSyscallHeaderBytes: uintptr(opts.MaxSyscallHeaderBytes),
		writevMaxIovs:         rawfile.MaxIovs,
	}
	if e.maxSyscallHeaderBytes != 0 {
		if max := int(e.maxSyscallHeaderBytes / rawfile.SizeofIovec); max < e.writevMaxIovs {
			e.writevMaxIovs = max
		}
	}

	// Increment fanoutID to ensure that we don't re-use the same fanoutID
	// for the next endpoint.
	fid := fanoutID.Add(1)

	// Create per channel dispatchers.
	for _, fd := range opts.FDs {
		if err := unix.SetNonblock(fd, true); err != nil {
			return nil, fmt.Errorf("unix.SetNonblock(%v) failed: %v", fd, err)
		}

		isSocket, err := isSocketFD(fd)
		if err != nil {
			return nil, err
		}
		e.fds = append(e.fds, fdInfo{fd: fd, isSocket: isSocket})
		if isSocket {
			if opts.GSOMaxSize != 0 {
				if opts.GvisorGSOEnabled {
					e.gsoKind = stack.GvisorGSOSupported
				} else {
					e.gsoKind = stack.HostGSOSupported
				}
				e.gsoMaxSize = opts.GSOMaxSize
			}
		}

		inboundDispatcher, err := createInboundDispatcher(e, fd, isSocket, fid)
		if err != nil {
			return nil, fmt.Errorf("createInboundDispatcher(...) = %v", err)
		}
		e.inboundDispatchers = append(e.inboundDispatchers, inboundDispatcher)
	}

	return e, nil
}

func createInboundDispatcher(e *endpoint, fd int, isSocket bool, fID int32) (linkDispatcher, error) {
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
			// Enable PACKET_FANOUT mode if the underlying socket is of type
			// AF_PACKET. We do not enable PACKET_FANOUT_FLAG_DEFRAG as that will
			// prevent gvisor from receiving fragmented packets and the host does the
			// reassembly on our behalf before delivering the fragments. This makes it
			// hard to test fragmentation reassembly code in Netstack.
			//
			// See: include/uapi/linux/if_packet.h (struct fanout_args).
			//
			// NOTE: We are using SetSockOptInt here even though the underlying
			// option is actually a struct. The code follows the example in the
			// kernel documentation as described at the link below:
			//
			// See: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
			//
			// This works out because the actual implementation for the option zero
			// initializes the structure and will initialize the max_members field
			// to a proper value if zero.
			//
			// See: https://github.com/torvalds/linux/blob/7acac4b3196caee5e21fb5ea53f8bc124e6a16fc/net/packet/af_packet.c#L3881
			const fanoutType = unix.PACKET_FANOUT_HASH
			fanoutArg := (int(fID) & 0xffff) | fanoutType<<16
			if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_FANOUT, fanoutArg); err != nil {
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
		case Readv:
		default:
			return nil, fmt.Errorf("unknown dispatch mode %d", e.packetDispatchMode)
		}
	}
	return inboundDispatcher, nil
}

func isSocketFD(fd int) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return false, fmt.Errorf("unix.Fstat(%v,...) failed: %v", fd, err)
	}
	return (stat.Mode & unix.S_IFSOCK) == unix.S_IFSOCK, nil
}

// Attach launches the goroutine that reads packets from the file descriptor and
// dispatches them via the provided dispatcher. If one is already attached,
// then nothing happens.
//
// Attach implements stack.LinkEndpoint.Attach.
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// nil means the NIC is being removed.
	if dispatcher == nil && e.dispatcher != nil {
		for _, dispatcher := range e.inboundDispatchers {
			dispatcher.Stop()
		}
		e.Wait()
		e.dispatcher = nil
		return
	}
	if dispatcher != nil && e.dispatcher == nil {
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
}

// IsAttached implements stack.LinkEndpoint.IsAttached.
func (e *endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
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

// marshal serializes h to a newly-allocated byte slice, in little-endian byte
// order.
//
// Note: Virtio v1.0 onwards specifies little-endian as the byte ordering used
// for general serialization. This makes it difficult to use go-marshal for
// virtio types, as go-marshal implicitly uses the native byte ordering.
func (h *virtioNetHdr) marshal() []byte {
	buf := [virtioNetHdrSize]byte{
		0: byte(h.flags),
		1: byte(h.gsoType),

		// Manually lay out the fields in little-endian byte order. Little endian =>
		// least significant bit goes to the lower address.

		2: byte(h.hdrLen),
		3: byte(h.hdrLen >> 8),

		4: byte(h.gsoSize),
		5: byte(h.gsoSize >> 8),

		6: byte(h.csumStart),
		7: byte(h.csumStart >> 8),

		8: byte(h.csumOffset),
		9: byte(h.csumOffset >> 8),
	}
	return buf[:]
}

// These constants are declared in linux/virtio_net.h.
const (
	_VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

	_VIRTIO_NET_HDR_GSO_TCPV4 = 1
	_VIRTIO_NET_HDR_GSO_TCPV6 = 4
)

// AddHeader implements stack.LinkEndpoint.AddHeader.
func (e *endpoint) AddHeader(pkt stack.PacketBufferPtr) {
	if e.hdrSize > 0 {
		// Add ethernet header if needed.
		eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			SrcAddr: pkt.EgressRoute.LocalLinkAddress,
			DstAddr: pkt.EgressRoute.RemoteLinkAddress,
			Type:    pkt.NetworkProtocolNumber,
		})
	}
}

// writePacket writes outbound packets to the file descriptor. If it is not
// currently writable, the packet is dropped.
func (e *endpoint) writePacket(pkt stack.PacketBufferPtr) tcpip.Error {
	fdInfo := e.fds[pkt.Hash%uint32(len(e.fds))]
	fd := fdInfo.fd
	var vnetHdrBuf []byte
	if e.gsoKind == stack.HostGSOSupported {
		vnetHdr := virtioNetHdr{}
		if pkt.GSOOptions.Type != stack.GSONone {
			vnetHdr.hdrLen = uint16(pkt.HeaderSize())
			if pkt.GSOOptions.NeedsCsum {
				vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
				vnetHdr.csumStart = header.EthernetMinimumSize + pkt.GSOOptions.L3HdrLen
				vnetHdr.csumOffset = pkt.GSOOptions.CsumOffset
			}
			if pkt.GSOOptions.Type != stack.GSONone && uint16(pkt.Data().Size()) > pkt.GSOOptions.MSS {
				switch pkt.GSOOptions.Type {
				case stack.GSOTCPv4:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
				case stack.GSOTCPv6:
					vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
				default:
					panic(fmt.Sprintf("Unknown gso type: %v", pkt.GSOOptions.Type))
				}
				vnetHdr.gsoSize = pkt.GSOOptions.MSS
			}
		}
		vnetHdrBuf = vnetHdr.marshal()
	}

	views := pkt.AsSlices()
	numIovecs := len(views)
	if len(vnetHdrBuf) != 0 {
		numIovecs++
	}
	if numIovecs > e.writevMaxIovs {
		numIovecs = e.writevMaxIovs
	}

	// Allocate small iovec arrays on the stack.
	var iovecsArr [8]unix.Iovec
	iovecs := iovecsArr[:0]
	if numIovecs > len(iovecsArr) {
		iovecs = make([]unix.Iovec, 0, numIovecs)
	}
	iovecs = rawfile.AppendIovecFromBytes(iovecs, vnetHdrBuf, numIovecs)
	for _, v := range views {
		iovecs = rawfile.AppendIovecFromBytes(iovecs, v, numIovecs)
	}
	return rawfile.NonBlockingWriteIovec(fd, iovecs)
}

func (e *endpoint) sendBatch(batchFDInfo fdInfo, pkts []stack.PacketBufferPtr) (int, tcpip.Error) {
	// Degrade to writePacket if underlying fd is not a socket.
	if !batchFDInfo.isSocket {
		var written int
		var err tcpip.Error
		for written < len(pkts) {
			if err = e.writePacket(pkts[written]); err != nil {
				break
			}
			written++
		}
		return written, err
	}

	// Send a batch of packets through batchFD.
	batchFD := batchFDInfo.fd
	mmsgHdrsStorage := make([]rawfile.MMsgHdr, 0, len(pkts))
	packets := 0
	for packets < len(pkts) {
		mmsgHdrs := mmsgHdrsStorage
		batch := pkts[packets:]
		syscallHeaderBytes := uintptr(0)
		for _, pkt := range batch {
			var vnetHdrBuf []byte
			if e.gsoKind == stack.HostGSOSupported {
				vnetHdr := virtioNetHdr{}
				if pkt.GSOOptions.Type != stack.GSONone {
					vnetHdr.hdrLen = uint16(pkt.HeaderSize())
					if pkt.GSOOptions.NeedsCsum {
						vnetHdr.flags = _VIRTIO_NET_HDR_F_NEEDS_CSUM
						vnetHdr.csumStart = header.EthernetMinimumSize + pkt.GSOOptions.L3HdrLen
						vnetHdr.csumOffset = pkt.GSOOptions.CsumOffset
					}
					if pkt.GSOOptions.Type != stack.GSONone && uint16(pkt.Data().Size()) > pkt.GSOOptions.MSS {
						switch pkt.GSOOptions.Type {
						case stack.GSOTCPv4:
							vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV4
						case stack.GSOTCPv6:
							vnetHdr.gsoType = _VIRTIO_NET_HDR_GSO_TCPV6
						default:
							panic(fmt.Sprintf("Unknown gso type: %v", pkt.GSOOptions.Type))
						}
						vnetHdr.gsoSize = pkt.GSOOptions.MSS
					}
				}
				vnetHdrBuf = vnetHdr.marshal()
			}

			views := pkt.AsSlices()
			numIovecs := len(views)
			if len(vnetHdrBuf) != 0 {
				numIovecs++
			}
			if numIovecs > rawfile.MaxIovs {
				numIovecs = rawfile.MaxIovs
			}
			if e.maxSyscallHeaderBytes != 0 {
				syscallHeaderBytes += rawfile.SizeofMMsgHdr + uintptr(numIovecs)*rawfile.SizeofIovec
				if syscallHeaderBytes > e.maxSyscallHeaderBytes {
					// We can't fit this packet into this call to sendmmsg().
					// We could potentially do so if we reduced numIovecs
					// further, but this might incur considerable extra
					// copying. Leave it to the next batch instead.
					break
				}
			}

			// We can't easily allocate iovec arrays on the stack here since
			// they will escape this loop iteration via mmsgHdrs.
			iovecs := make([]unix.Iovec, 0, numIovecs)
			iovecs = rawfile.AppendIovecFromBytes(iovecs, vnetHdrBuf, numIovecs)
			for _, v := range views {
				iovecs = rawfile.AppendIovecFromBytes(iovecs, v, numIovecs)
			}

			var mmsgHdr rawfile.MMsgHdr
			mmsgHdr.Msg.Iov = &iovecs[0]
			mmsgHdr.Msg.SetIovlen(len(iovecs))
			mmsgHdrs = append(mmsgHdrs, mmsgHdr)
		}

		if len(mmsgHdrs) == 0 {
			// We can't fit batch[0] into a mmsghdr while staying under
			// e.maxSyscallHeaderBytes. Use WritePacket, which will avoid the
			// mmsghdr (by using writev) and re-buffer iovecs more aggressively
			// if necessary (by using e.writevMaxIovs instead of
			// rawfile.MaxIovs).
			pkt := batch[0]
			if err := e.writePacket(pkt); err != nil {
				return packets, err
			}
			packets++
		} else {
			for len(mmsgHdrs) > 0 {
				sent, err := rawfile.NonBlockingSendMMsg(batchFD, mmsgHdrs)
				if err != nil {
					return packets, err
				}
				packets += sent
				mmsgHdrs = mmsgHdrs[sent:]
			}
		}
	}

	return packets, nil
}

// WritePackets writes outbound packets to the underlying file descriptors. If
// one is not currently writable, the packet is dropped.
//
// Being a batch API, each packet in pkts should have the following
// fields populated:
//   - pkt.EgressRoute
//   - pkt.GSOOptions
//   - pkt.NetworkProtocolNumber
func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	// Preallocate to avoid repeated reallocation as we append to batch.
	batch := make([]stack.PacketBufferPtr, 0, BatchSize)
	batchFDInfo := fdInfo{fd: -1, isSocket: false}
	sentPackets := 0
	for _, pkt := range pkts.AsSlice() {
		if len(batch) == 0 {
			batchFDInfo = e.fds[pkt.Hash%uint32(len(e.fds))]
		}
		pktFDInfo := e.fds[pkt.Hash%uint32(len(e.fds))]
		if sendNow := pktFDInfo != batchFDInfo; !sendNow {
			batch = append(batch, pkt)
			continue
		}
		n, err := e.sendBatch(batchFDInfo, batch)
		sentPackets += n
		if err != nil {
			return sentPackets, err
		}
		batch = batch[:0]
		batch = append(batch, pkt)
		batchFDInfo = pktFDInfo
	}

	if len(batch) != 0 {
		n, err := e.sendBatch(batchFDInfo, batch)
		sentPackets += n
		if err != nil {
			return sentPackets, err
		}
	}
	return sentPackets, nil
}

// InjectOutbound implements stack.InjectableEndpoint.InjectOutbound.
func (e *endpoint) InjectOutbound(dest tcpip.Address, packet *bufferv2.View) tcpip.Error {
	return rawfile.NonBlockingWrite(e.fds[0].fd, packet.AsSlice())
}

// dispatchLoop reads packets from the file descriptor in a loop and dispatches
// them to the network stack.
func (e *endpoint) dispatchLoop(inboundDispatcher linkDispatcher) tcpip.Error {
	for {
		cont, err := inboundDispatcher.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err)
			}
			inboundDispatcher.release()
			return err
		}
	}
}

// GSOMaxSize implements stack.GSOEndpoint.
func (e *endpoint) GSOMaxSize() uint32 {
	return e.gsoMaxSize
}

// SupportsHWGSO implements stack.GSOEndpoint.
func (e *endpoint) SupportedGSO() stack.SupportedGSO {
	return e.gsoKind
}

// ARPHardwareType implements stack.LinkEndpoint.ARPHardwareType.
func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	if e.hdrSize > 0 {
		return header.ARPHardwareEther
	}
	return header.ARPHardwareNone
}

// InjectableEndpoint is an injectable fd-based endpoint. The endpoint writes
// to the FD, but does not read from it. All reads come from injected packets.
type InjectableEndpoint struct {
	endpoint

	mu sync.RWMutex
	// +checklocks:mu
	dispatcher stack.NetworkDispatcher
}

// Attach saves the stack network-layer dispatcher for use later when packets
// are injected.
func (e *InjectableEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// InjectInbound injects an inbound packet. If the endpoint is not attached, the
// packet is not delivered.
func (e *InjectableEndpoint) InjectInbound(protocol tcpip.NetworkProtocolNumber, pkt stack.PacketBufferPtr) {
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d != nil {
		d.DeliverNetworkPacket(protocol, pkt)
	}
}

// NewInjectable creates a new fd-based InjectableEndpoint.
func NewInjectable(fd int, mtu uint32, capabilities stack.LinkEndpointCapabilities) (*InjectableEndpoint, error) {
	unix.SetNonblock(fd, true)
	isSocket, err := isSocketFD(fd)
	if err != nil {
		return nil, err
	}

	return &InjectableEndpoint{endpoint: endpoint{
		fds:           []fdInfo{{fd: fd, isSocket: isSocket}},
		mtu:           mtu,
		caps:          capabilities,
		writevMaxIovs: rawfile.MaxIovs,
	}}, nil
}
