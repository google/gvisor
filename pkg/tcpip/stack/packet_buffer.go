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
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
)

// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints. Clone() should be called in such cases so that
// modifications to the Data field do not affect other copies.
type PacketBuffer struct {
	_ sync.NoCopy

	// PacketBufferEntry is used to build an intrusive list of
	// PacketBuffers.
	PacketBufferEntry

	// Data holds the payload of the packet. For inbound packets, it also
	// holds the headers, which are consumed as the packet moves up the
	// stack. Headers are guaranteed not to be split across views.
	//
	// The bytes backing Data are immutable, but Data itself may be trimmed
	// or otherwise modified.
	Data buffer.VectorisedView

	// Header holds the headers of outbound packets. As a packet is passed
	// down the stack, each layer adds to Header. Note that forwarded
	// packets don't populate Headers on their way out -- their headers and
	// payload are never parsed out and remain in Data.
	//
	// TODO(gvisor.dev/issue/170): Forwarded packets don't currently
	// populate Header, but should. This will be doable once early parsing
	// (https://github.com/google/gvisor/pull/1995) is supported.
	Header buffer.Prependable

	// These fields are used by both inbound and outbound packets. They
	// typically overlap with the Data and Header fields.
	//
	// The bytes backing these views are immutable. Each field may be nil
	// if either it has not been set yet or no such header exists (e.g.
	// packets sent via loopback may not have a link header).
	//
	// These fields may be Views into other slices (either Data or Header).
	// SR dosen't support this, so deep copies are necessary in some cases.
	LinkHeader      buffer.View
	NetworkHeader   buffer.View
	TransportHeader buffer.View

	// Hash is the transport layer hash of this packet. A value of zero
	// indicates no valid hash has been set.
	Hash uint32

	// Owner is implemented by task to get the uid and gid.
	// Only set for locally generated packets.
	Owner tcpip.PacketOwner

	// The following fields are only set by the qdisc layer when the packet
	// is added to a queue.
	EgressRoute           *Route
	GSOOptions            *GSO
	NetworkProtocolNumber tcpip.NetworkProtocolNumber

	// NatDone indicates if the packet has been manipulated as per NAT
	// iptables rule.
	NatDone bool
}

// Clone makes a copy of pk. It clones the Data field, which creates a new
// VectorisedView but does not deep copy the underlying bytes.
//
// Clone also does not deep copy any of its other fields.
//
// FIXME(b/153685824): Data gets copied but not other header references.
func (pk *PacketBuffer) Clone() *PacketBuffer {
	return &PacketBuffer{
		PacketBufferEntry:     pk.PacketBufferEntry,
		Data:                  pk.Data.Clone(nil),
		Header:                pk.Header,
		LinkHeader:            pk.LinkHeader,
		NetworkHeader:         pk.NetworkHeader,
		TransportHeader:       pk.TransportHeader,
		Hash:                  pk.Hash,
		Owner:                 pk.Owner,
		EgressRoute:           pk.EgressRoute,
		GSOOptions:            pk.GSOOptions,
		NetworkProtocolNumber: pk.NetworkProtocolNumber,
		NatDone:               pk.NatDone,
	}
}
