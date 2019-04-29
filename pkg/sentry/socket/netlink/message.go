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

package netlink

import (
	"fmt"
	"math"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// alignUp rounds a length up to an alignment.
//
// Preconditions: align is a power of two.
func alignUp(length int, align uint) int {
	return (length + int(align) - 1) &^ (int(align) - 1)
}

// Message contains a complete serialized netlink message.
type Message struct {
	buf []byte
}

// NewMessage creates a new Message containing the passed header.
//
// The header length will be updated by Finalize.
func NewMessage(hdr linux.NetlinkMessageHeader) *Message {
	return &Message{
		buf: binary.Marshal(nil, usermem.ByteOrder, hdr),
	}
}

// Finalize returns the []byte containing the entire message, with the total
// length set in the message header. The Message must not be modified after
// calling Finalize.
func (m *Message) Finalize() []byte {
	// Update length, which is the first 4 bytes of the header.
	usermem.ByteOrder.PutUint32(m.buf, uint32(len(m.buf)))

	// Align the message. Note that the message length in the header (set
	// above) is the useful length of the message, not the total aligned
	// length. See net/netlink/af_netlink.c:__nlmsg_put.
	aligned := alignUp(len(m.buf), linux.NLMSG_ALIGNTO)
	m.putZeros(aligned - len(m.buf))
	return m.buf
}

// putZeros adds n zeros to the message.
func (m *Message) putZeros(n int) {
	for n > 0 {
		m.buf = append(m.buf, 0)
		n--
	}
}

// Put serializes v into the message.
func (m *Message) Put(v interface{}) {
	m.buf = binary.Marshal(m.buf, usermem.ByteOrder, v)
}

// PutAttr adds v to the message as a netlink attribute.
//
// Preconditions: The serialized attribute (linux.NetlinkAttrHeaderSize +
// binary.Size(v) fits in math.MaxUint16 bytes.
func (m *Message) PutAttr(atype uint16, v interface{}) {
	l := linux.NetlinkAttrHeaderSize + int(binary.Size(v))
	if l > math.MaxUint16 {
		panic(fmt.Sprintf("attribute too large: %d", l))
	}

	m.Put(linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})
	m.Put(v)

	// Align the attribute.
	aligned := alignUp(l, linux.NLA_ALIGNTO)
	m.putZeros(aligned - l)
}

// PutAttrString adds s to the message as a netlink attribute.
func (m *Message) PutAttrString(atype uint16, s string) {
	l := linux.NetlinkAttrHeaderSize + len(s) + 1
	m.Put(linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})

	// String + NUL-termination.
	m.Put([]byte(s))
	m.putZeros(1)

	// Align the attribute.
	aligned := alignUp(l, linux.NLA_ALIGNTO)
	m.putZeros(aligned - l)
}

// MessageSet contains a series of netlink messages.
type MessageSet struct {
	// Multi indicates that this a multi-part message, to be terminated by
	// NLMSG_DONE. NLMSG_DONE is sent even if the set contains only one
	// Message.
	//
	// If Multi is set, all added messages will have NLM_F_MULTI set.
	Multi bool

	// PortID is the destination port for all messages.
	PortID int32

	// Seq is the sequence counter for all messages in the set.
	Seq uint32

	// Messages contains the messages in the set.
	Messages []*Message
}

// NewMessageSet creates a new MessageSet.
//
// portID is the destination port to set as PortID in all messages.
//
// seq is the sequence counter to set as seq in all messages in the set.
func NewMessageSet(portID int32, seq uint32) *MessageSet {
	return &MessageSet{
		PortID: portID,
		Seq:    seq,
	}
}

// AddMessage adds a new message to the set and returns it for further
// additions.
//
// The passed header will have Seq, PortID and the multi flag set
// automatically.
func (ms *MessageSet) AddMessage(hdr linux.NetlinkMessageHeader) *Message {
	hdr.Seq = ms.Seq
	hdr.PortID = uint32(ms.PortID)
	if ms.Multi {
		hdr.Flags |= linux.NLM_F_MULTI
	}

	m := NewMessage(hdr)
	ms.Messages = append(ms.Messages, m)
	return m
}
