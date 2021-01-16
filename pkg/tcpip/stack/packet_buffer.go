// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type headerType int

const (
	linkHeader headerType = iota
	networkHeader
	transportHeader
	numHeaderType
)

// PacketBufferOptions specifies options for PacketBuffer creation.
type PacketBufferOptions struct {
	// ReserveHeaderBytes is the number of bytes to reserve for headers. Total
	// number of bytes pushed onto the headers must not exceed this value.
	ReserveHeaderBytes int

	// Data is the initial unparsed data for the new packet. If set, it will be
	// owned by the new packet.
	Data buffer.VectorisedView
}

// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints.
//
// The whole packet is expected to be a series of bytes in the following order:
// LinkHeader, NetworkHeader, TransportHeader, and Data. Any of them can be
// empty. Use of PacketBuffer in any other order is unsupported.
//
// PacketBuffer must be created with NewPacketBuffer.
type PacketBuffer struct {
	_ sync.NoCopy

	// PacketBufferEntry is used to build an intrusive list of
	// PacketBuffers.
	PacketBufferEntry

	// Data holds the payload of the packet.
	//
	// For inbound packets, Data is initially the whole packet. Then gets moved to
	// headers via PacketHeader.Consume, when the packet is being parsed.
	//
	// For outbound packets, Data is the innermost layer, defined by the protocol.
	// Headers are pushed in front of it via PacketHeader.Push.
	//
	// The bytes backing Data are immutable, a.k.a. users shouldn't write to its
	// backing storage.
	Data buffer.VectorisedView

	// headers stores metadata about each header.
	headers [numHeaderType]headerInfo

	// header is the internal storage for outbound packets. Headers will be pushed
	// (prepended) on this storage as the packet is being constructed.
	//
	// TODO(gvisor.dev/issue/2404): Switch to an implementation that header and
	// data are held in the same underlying buffer storage.
	header buffer.Prependable

	// NetworkProtocolNumber is only valid when NetworkHeader().View().IsEmpty()
	// returns false.
	// TODO(gvisor.dev/issue/3574): Remove the separately passed protocol
	// numbers in registration APIs that take a PacketBuffer.
	NetworkProtocolNumber tcpip.NetworkProtocolNumber

	// TransportProtocol is only valid if it is non zero.
	// TODO(gvisor.dev/issue/3810): This and the network protocol number should
	// be moved into the headerinfo. This should resolve the validity issue.
	TransportProtocolNumber tcpip.TransportProtocolNumber

	// Hash is the transport layer hash of this packet. A value of zero
	// indicates no valid hash has been set.
	Hash uint32

	// Owner is implemented by task to get the uid and gid.
	// Only set for locally generated packets.
	Owner tcpip.PacketOwner

	// The following fields are only set by the qdisc layer when the packet
	// is added to a queue.
	EgressRoute RouteInfo
	GSOOptions  *GSO

	// NatDone indicates if the packet has been manipulated as per NAT
	// iptables rule.
	NatDone bool

	// PktType indicates the SockAddrLink.PacketType of the packet as defined in
	// https://www.man7.org/linux/man-pages/man7/packet.7.html.
	PktType tcpip.PacketType

	// NICID is the ID of the interface the network packet was received at.
	NICID tcpip.NICID

	// RXTransportChecksumValidated indicates that transport checksum verification
	// may be safely skipped.
	RXTransportChecksumValidated bool

	// NetworkPacketInfo holds an incoming packet's network-layer information.
	NetworkPacketInfo NetworkPacketInfo
}

// NewPacketBuffer creates a new PacketBuffer with opts.
func NewPacketBuffer(opts PacketBufferOptions) *PacketBuffer {
	pk := &PacketBuffer{
		Data: opts.Data,
	}
	if opts.ReserveHeaderBytes != 0 {
		pk.header = buffer.NewPrependable(opts.ReserveHeaderBytes)
	}
	return pk
}

// ReservedHeaderBytes returns the number of bytes initially reserved for
// headers.
func (pk *PacketBuffer) ReservedHeaderBytes() int {
	return pk.header.UsedLength() + pk.header.AvailableLength()
}

// AvailableHeaderBytes returns the number of bytes currently available for
// headers. This is relevant to PacketHeader.Push method only.
func (pk *PacketBuffer) AvailableHeaderBytes() int {
	return pk.header.AvailableLength()
}

// LinkHeader returns the handle to link-layer header.
func (pk *PacketBuffer) LinkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: linkHeader,
	}
}

// NetworkHeader returns the handle to network-layer header.
func (pk *PacketBuffer) NetworkHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: networkHeader,
	}
}

// TransportHeader returns the handle to transport-layer header.
func (pk *PacketBuffer) TransportHeader() PacketHeader {
	return PacketHeader{
		pk:  pk,
		typ: transportHeader,
	}
}

// HeaderSize returns the total size of all headers in bytes.
func (pk *PacketBuffer) HeaderSize() int {
	// Note for inbound packets (Consume called), headers are not stored in
	// pk.header. Thus, calculation of size of each header is needed.
	var size int
	for i := range pk.headers {
		size += len(pk.headers[i].buf)
	}
	return size
}

// Size returns the size of packet in bytes.
func (pk *PacketBuffer) Size() int {
	return pk.HeaderSize() + pk.Data.Size()
}

// Views returns the underlying storage of the whole packet.
func (pk *PacketBuffer) Views() []buffer.View {
	// Optimization for outbound packets that headers are in pk.header.
	useHeader := true
	for i := range pk.headers {
		if !canUseHeader(&pk.headers[i]) {
			useHeader = false
			break
		}
	}

	dataViews := pk.Data.Views()

	var vs []buffer.View
	if useHeader {
		vs = make([]buffer.View, 0, 1+len(dataViews))
		vs = append(vs, pk.header.View())
	} else {
		vs = make([]buffer.View, 0, len(pk.headers)+len(dataViews))
		for i := range pk.headers {
			if v := pk.headers[i].buf; len(v) > 0 {
				vs = append(vs, v)
			}
		}
	}
	return append(vs, dataViews...)
}

func canUseHeader(h *headerInfo) bool {
	// h.offset will be negative if the header was pushed in to prependable
	// portion, or doesn't matter when it's empty.
	return len(h.buf) == 0 || h.offset < 0
}

func (pk *PacketBuffer) push(typ headerType, size int) buffer.View {
	h := &pk.headers[typ]
	if h.buf != nil {
		panic(fmt.Sprintf("push must not be called twice: type %s", typ))
	}
	h.buf = buffer.View(pk.header.Prepend(size))
	h.offset = -pk.header.UsedLength()
	return h.buf
}

func (pk *PacketBuffer) consume(typ headerType, size int) (v buffer.View, consumed bool) {
	h := &pk.headers[typ]
	if h.buf != nil {
		panic(fmt.Sprintf("consume must not be called twice: type %s", typ))
	}
	v, ok := pk.Data.PullUp(size)
	if !ok {
		return
	}
	pk.Data.TrimFront(size)
	h.buf = v
	return h.buf, true
}

// Clone makes a shallow copy of pk.
//
// Clone should be called in such cases so that no modifications is done to
// underlying packet payload.
func (pk *PacketBuffer) Clone() *PacketBuffer {
	return &PacketBuffer{
		PacketBufferEntry:            pk.PacketBufferEntry,
		Data:                         pk.Data.Clone(nil),
		headers:                      pk.headers,
		header:                       pk.header,
		Hash:                         pk.Hash,
		Owner:                        pk.Owner,
		GSOOptions:                   pk.GSOOptions,
		NetworkProtocolNumber:        pk.NetworkProtocolNumber,
		NatDone:                      pk.NatDone,
		TransportProtocolNumber:      pk.TransportProtocolNumber,
		PktType:                      pk.PktType,
		NICID:                        pk.NICID,
		RXTransportChecksumValidated: pk.RXTransportChecksumValidated,
		NetworkPacketInfo:            pk.NetworkPacketInfo,
	}
}

// Network returns the network header as a header.Network.
//
// Network should only be called when NetworkHeader has been set.
func (pk *PacketBuffer) Network() header.Network {
	switch netProto := pk.NetworkProtocolNumber; netProto {
	case header.IPv4ProtocolNumber:
		return header.IPv4(pk.NetworkHeader().View())
	case header.IPv6ProtocolNumber:
		return header.IPv6(pk.NetworkHeader().View())
	default:
		panic(fmt.Sprintf("unknown network protocol number %d", netProto))
	}
}

// CloneToInbound makes a shallow copy of the packet buffer to be used as an
// inbound packet.
//
// See PacketBuffer.Data for details about how a packet buffer holds an inbound
// packet.
func (pk *PacketBuffer) CloneToInbound() *PacketBuffer {
	return NewPacketBuffer(PacketBufferOptions{
		Data: buffer.NewVectorisedView(pk.Size(), pk.Views()),
	})
}

// headerInfo stores metadata about a header in a packet.
type headerInfo struct {
	// buf is the memorized slice for both prepended and consumed header.
	// When header is prepended, buf serves as memorized value, which is a slice
	// of pk.header. When header is consumed, buf is the slice pulled out from
	// pk.Data, which is the only place to hold this header.
	buf buffer.View

	// offset will be a negative number denoting the offset where this header is
	// from the end of pk.header, if it is prepended. Otherwise, zero.
	offset int
}

// PacketHeader is a handle object to a header in the underlying packet.
type PacketHeader struct {
	pk  *PacketBuffer
	typ headerType
}

// View returns the underlying storage of h.
func (h PacketHeader) View() buffer.View {
	return h.pk.headers[h.typ].buf
}

// Push pushes size bytes in the front of its residing packet, and returns the
// backing storage. Callers may only call one of Push or Consume once on each
// header in the lifetime of the underlying packet.
func (h PacketHeader) Push(size int) buffer.View {
	return h.pk.push(h.typ, size)
}

// Consume moves the first size bytes of the unparsed data portion in the packet
// to h, and returns the backing storage. In the case of data is shorter than
// size, consumed will be false, and the state of h will not be affected.
// Callers may only call one of Push or Consume once on each header in the
// lifetime of the underlying packet.
func (h PacketHeader) Consume(size int) (v buffer.View, consumed bool) {
	return h.pk.consume(h.typ, size)
}

// PayloadSince returns packet payload starting from and including a particular
// header.
//
// The returned View is owned by the caller - its backing buffer is separate
// from the packet header's underlying packet buffer.
func PayloadSince(h PacketHeader) buffer.View {
	size := h.pk.Data.Size()
	for _, hinfo := range h.pk.headers[h.typ:] {
		size += len(hinfo.buf)
	}

	v := make(buffer.View, 0, size)

	for _, hinfo := range h.pk.headers[h.typ:] {
		v = append(v, hinfo.buf...)
	}

	for _, view := range h.pk.Data.Views() {
		v = append(v, view...)
	}

	return v
}
