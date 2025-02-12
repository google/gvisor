// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package packetmmap contains the packet mmap implementation for netstack.
//
// See https://docs.kernel.org/networking/packet_mmap.html for a full
// description of the PACKET_MMAP interface.
package packetmmap

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/socket"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

var _ stack.PacketMMapEndpoint = (*Endpoint)(nil)
var _ memmap.Mappable = (*Endpoint)(nil)

// ringBufferMode is the mode of a packet ring buffer.
type ringBufferMode uint

const (
	rxRingBuffer ringBufferMode = 1 << iota
	txRingBuffer
)

// Endpoint is a memmap.Mappable implementation for stack.PacketMMapEndpoint. It
// implements the PACKET_MMAP interface as described in
// https://docs.kernel.org/networking/packet_mmap.html.
//
// +stateify savable
type Endpoint struct {
	// mu protects specific fields within ringBuffer in addition to those marked
	// with checklocks annotations in Endpoint. See the ringBuffer type for more
	// details. The lock order for the ring buffers is:
	//
	//	mu
	//	  rxRingBuffer.dataMu
	//	  txRingBuffer.dataMu
	mu           sync.Mutex `state:"nosave"`
	rxRingBuffer ringBuffer
	txRingBuffer ringBuffer

	mapped atomicbitops.Uint32

	// +checklocks:mu
	mode ringBufferMode
	// +checklocks:mu
	cooked bool

	packetEP  stack.MappablePacketEndpoint
	reserve   uint32
	nicID     tcpip.NICID
	netProto  tcpip.NetworkProtocolNumber
	version   int
	headerLen uint32

	received atomicbitops.Uint32
	dropped  atomicbitops.Uint32

	stack *stack.Stack
	wq    *waiter.Queue

	mappingsMu sync.Mutex `state:"nosave"`
	// +checklocks:mappingsMu
	mappings memmap.MappingSet
}

// Init initializes the endpoint. It is called when the endpoint is created
// during setsockopt(PACKET_(RX|TX)_RING) with the options retrieved from its
// corresponding packet socket.
func (m *Endpoint) Init(ctx context.Context, opts stack.PacketMMapOpts) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stack = opts.Stack
	m.wq = opts.Wq
	m.cooked = opts.Cooked
	m.packetEP = opts.PacketEndpoint
	m.nicID = opts.NICID
	m.netProto = opts.NetProto
	m.version = opts.Version
	m.reserve = opts.Reserve
	m.nicID = opts.NICID
	m.netProto = opts.NetProto
	switch m.version {
	case linux.TPACKET_V1:
		m.headerLen = linux.TPACKET_HDRLEN
	case linux.TPACKET_V2:
		m.headerLen = linux.TPACKET2_HDRLEN
	default:
		panic(fmt.Sprintf("invalid version %d supplied to InitPacketMMap", m.version))
	}
	if opts.Req.TpBlockNr != 0 {
		if opts.Req.TpBlockSize <= 0 {
			return linuxerr.EINVAL
		}
		if opts.Req.TpBlockSize%hostarch.PageSize != 0 {
			return linuxerr.EINVAL
		}
		if opts.Req.TpFrameSize < m.headerLen+m.reserve {
			return linuxerr.EINVAL
		}
		if opts.Req.TpFrameSize&(linux.TPACKET_ALIGNMENT-1) != 0 {
			return linuxerr.EINVAL
		}
		framesPerBlock := opts.Req.TpBlockSize / opts.Req.TpFrameSize
		if framesPerBlock == 0 {
			return linuxerr.EINVAL
		}
		if framesPerBlock > ^uint32(0)/opts.Req.TpFrameSize {
			return linuxerr.EINVAL
		}
		if framesPerBlock*opts.Req.TpBlockNr != opts.Req.TpFrameNr {
			return linuxerr.EINVAL
		}
	} else if opts.Req.TpFrameNr != 0 {
		return linuxerr.EINVAL
	}
	if opts.IsRx {
		if err := m.rxRingBuffer.init(ctx, opts.Req); err != nil {
			return err
		}
		m.mode |= rxRingBuffer
	} else {
		if err := m.txRingBuffer.init(ctx, opts.Req); err != nil {
			return err
		}
		m.mode |= txRingBuffer
	}
	return nil
}

// Close implements stack.PacketMMapEndpoint.Close.
func (m *Endpoint) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode&rxRingBuffer != 0 {
		m.rxRingBuffer.destroy()
	}
	if m.mode&txRingBuffer != 0 {
		m.txRingBuffer.destroy()
	}
	m.mapped.Store(0)
}

// Readiness implements stack.PacketMmapEndpoint.Readiness.
func (m *Endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := waiter.WritableEvents & mask
	if m.mode&rxRingBuffer != 0 {
		st, err := m.rxRingBuffer.prevFrameStatus()
		if err != nil {
			return result
		}
		if st != linux.TP_STATUS_KERNEL {
			result |= waiter.ReadableEvents
		}
	}
	return result
}

// HandlePacket implements stack.PacketMMapEndpoint.HandlePacket.
func (m *Endpoint) HandlePacket(nicID tcpip.NICID, netProto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	const minMacLen = 16
	var (
		status                           = uint32(linux.TP_STATUS_USER)
		macOffset, netOffset, dataLength uint32
		clone                            *stack.PacketBuffer
	)

	m.mu.Lock()
	cooked := m.cooked
	if !m.rxRingBuffer.hasRoom() {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}
	m.mu.Unlock()

	if pkt.GSOOptions.Type != stack.GSONone && pkt.GSOOptions.NeedsCsum {
		status |= linux.TP_STATUS_CSUM_NOT_READY
	}
	if pkt.GSOOptions.Type == stack.GSOTCPv4 || pkt.GSOOptions.Type == stack.GSOTCPv6 {
		status |= linux.TP_STATUS_GSO_TCP
	}

	pktBuf := pkt.ToBuffer()
	if cooked {
		pktBuf.TrimFront(int64(len(pkt.LinkHeader().Slice()) + len(pkt.VirtioNetHeader().Slice())))
		// Cooked packet endpoints don't include the link-headers in received
		// packets.
		netOffset = linux.TPacketAlign(m.headerLen+minMacLen) + m.reserve
		macOffset = netOffset
	} else {
		virtioNetHdrLen := uint32(len(pkt.VirtioNetHeader().Slice()))
		macLen := uint32(len(pkt.LinkHeader().Slice())) + virtioNetHdrLen
		netOffset = linux.TPacketAlign(m.headerLen+macLen) + m.reserve
		if macLen < minMacLen {
			netOffset = linux.TPacketAlign(m.headerLen+minMacLen) + m.reserve
		}
		if virtioNetHdrLen > 0 {
			netOffset += virtioNetHdrLen
		}
		macOffset = netOffset - macLen
	}
	if netOffset > uint32(^uint16(0)) {
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}
	dataLength = uint32(pktBuf.Size())

	// If the packet is too large to fit in the ring buffer, copy it to the
	// receive queue.
	if macOffset+dataLength > m.rxRingBuffer.frameSize {
		clone = pkt.Clone()
		defer clone.DecRef()
		dataLength = m.rxRingBuffer.frameSize - macOffset
		if int(dataLength) < 0 {
			dataLength = 0
		}
	}

	m.mu.Lock()
	tpStatus, err := m.rxRingBuffer.currFrameStatus()
	if err != nil || tpStatus != linux.TP_STATUS_KERNEL {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}

	slot, ok := m.rxRingBuffer.testAndMarkHead()
	if !ok {
		m.mu.Unlock()
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}
	m.rxRingBuffer.incHead()

	if clone != nil {
		status |= linux.TP_STATUS_COPY
		m.packetEP.HandlePacketMMapCopy(nicID, netProto, clone)
	}
	m.mu.Unlock()

	// Unlock around writing to the internal mappings to allow other threads to
	// write to the ring buffer.
	hdrView := buffer.NewViewSize(int(macOffset))
	m.marshalFrameHeader(pktBuf, macOffset, netOffset, dataLength, hdrView)
	pktBuf.Truncate(int64(dataLength))
	m.marshalSockAddr(pkt, hdrView)

	if err := m.rxRingBuffer.writeFrame(slot, hdrView, pktBuf); err != nil {
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rxRingBuffer.writeStatus(slot, status); err != nil {
		m.stack.Stats().DroppedPackets.Increment()
		m.dropped.Add(1)
		return
	}
	m.received.Add(1)
	m.wq.Notify(waiter.ReadableEvents)
}

// AddMapping implements memmap.Mappable.AddMapping.
func (m *Endpoint) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.AddMapping(ms, ar, offset, writable)
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (m *Endpoint) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.RemoveMapping(ms, ar, offset, writable)
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (m *Endpoint) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	m.mappingsMu.Lock()
	defer m.mappingsMu.Unlock()
	m.mappings.AddMapping(ms, dstAR, offset, writable)
	return nil
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (*Endpoint) InvalidateUnsavable(context.Context) error {
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (m *Endpoint) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	translationSize := 0
	if m.mode&rxRingBuffer != 0 {
		translationSize++
	}
	if m.mode&txRingBuffer != 0 {
		translationSize++
	}

	ts := make([]memmap.Translation, 0, translationSize)
	var err error

	if m.mode&rxRingBuffer != 0 {
		ts, err = m.rxRingBuffer.AppendTranslation(ctx, required, optional, at, ts)
	}
	if m.mode&txRingBuffer != 0 {
		// Translate went outside the bounds of the RX ring buffer, which is valid
		// if there is also a TX ring buffer.
		if err != nil {
			if len(ts) > 0 {
				required.Start = ts[len(ts)-1].Source.End
				optional.Start = ts[len(ts)-1].Source.End
			}
		}
		ts, err = m.txRingBuffer.AppendTranslation(ctx, required, optional, at, ts)
	}
	return ts, err
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (m *Endpoint) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if opts.Offset != 0 {
		return linuxerr.EINVAL
	}
	var size uint64
	if m.mode&rxRingBuffer != 0 {
		size += m.rxRingBuffer.bufferSize()
	}
	if m.mode&txRingBuffer != 0 {
		size += m.txRingBuffer.bufferSize()
	}
	if size != opts.Length {
		return linuxerr.EINVAL
	}
	m.mapped.Store(1)
	return nil
}

// Mapped returns whether the endpoint has been mapped.
func (m *Endpoint) Mapped() bool {
	return m.mapped.Load() != 0
}

// Stats implements stack.PacketMMapEndpoint.Stats.
func (m *Endpoint) Stats() tcpip.TpacketStats {
	rcv := m.received.Swap(0)
	drop := m.dropped.Swap(0)
	return tcpip.TpacketStats{
		Packets: uint32(rcv + drop),
		Dropped: uint32(drop),
	}
}

func toLinuxPacketType(pktType tcpip.PacketType) uint8 {
	switch pktType {
	case tcpip.PacketHost:
		return linux.PACKET_HOST
	case tcpip.PacketOtherHost:
		return linux.PACKET_OTHERHOST
	case tcpip.PacketOutgoing:
		return linux.PACKET_OUTGOING
	case tcpip.PacketBroadcast:
		return linux.PACKET_BROADCAST
	case tcpip.PacketMulticast:
		return linux.PACKET_MULTICAST
	default:
		panic(fmt.Sprintf("unknown packet type: %d", pktType))
	}
}

func (m *Endpoint) marshalSockAddr(pkt *stack.PacketBuffer, view *buffer.View) {
	var sll linux.SockAddrLink
	sll.Family = linux.AF_PACKET
	sll.Protocol = socket.Htons(uint16(m.netProto))
	sll.PacketType = toLinuxPacketType(pkt.PktType)
	sll.InterfaceIndex = int32(m.nicID)
	sll.HardwareAddrLen = header.EthernetAddressSize

	if len(pkt.LinkHeader().Slice()) != 0 {
		hdr := header.Ethernet(pkt.LinkHeader().Slice())
		copy(sll.HardwareAddr[:], hdr.SourceAddress())
	}
	var hdrSize uint32
	if m.version == linux.TPACKET_V2 {
		hdrSize = uint32((*linux.Tpacket2Hdr)(nil).SizeBytes())
	} else {
		hdrSize = uint32((*linux.TpacketHdr)(nil).SizeBytes())
	}
	sll.MarshalBytes(view.AsSlice()[linux.TPacketAlign(hdrSize):])
}

func (m *Endpoint) marshalFrameHeader(pktBuf buffer.Buffer, macOffset, netOffset, dataLength uint32, view *buffer.View) {
	t := m.stack.Clock().Now()
	switch m.version {
	case linux.TPACKET_V1:
		hdr := linux.TpacketHdr{
			// The status is set separately to ensure the frame is written before the
			// status is set.
			TpStatus:  linux.TP_STATUS_KERNEL,
			TpLen:     uint32(pktBuf.Size()),
			TpSnaplen: dataLength,
			TpMac:     uint16(macOffset),
			TpNet:     uint16(netOffset),
			TpSec:     uint32(t.Unix()),
			TpUsec:    uint32(t.UnixMicro() % 1e6),
		}
		hdr.MarshalBytes(view.AsSlice())
	case linux.TPACKET_V2:
		hdr := linux.Tpacket2Hdr{
			TpStatus:  linux.TP_STATUS_KERNEL,
			TpLen:     uint32(pktBuf.Size()),
			TpSnaplen: dataLength,
			TpMac:     uint16(macOffset),
			TpNet:     uint16(netOffset),
			TpSec:     uint32(t.Unix()),
			TpNSec:    uint32(t.UnixNano() % 1e9),
		}
		hdr.MarshalBytes(view.AsSlice())
	default:
		panic(fmt.Sprintf("invalid version %d supplied to HandlePacket", m.version))
	}
}
