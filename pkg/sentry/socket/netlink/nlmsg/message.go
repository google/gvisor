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

// Package nlmsg provides helpers to parse and construct netlink messages.
package nlmsg

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// alignPad returns the length of padding required for alignment.
//
// Preconditions: align is a power of two.
func alignPad(length int, align uint) int {
	return bits.AlignUp(length, align) - length
}

// Message contains a complete serialized netlink message.
type Message struct {
	hdr linux.NetlinkMessageHeader
	buf []byte
}

// NewMessage creates a new Message containing the passed header.
//
// The header length will be updated by Finalize.
func NewMessage(hdr linux.NetlinkMessageHeader) *Message {
	return &Message{
		hdr: hdr,
		buf: marshal.Marshal(&hdr),
	}
}

// ParseMessage parses the first message seen at buf, returning the rest of the
// buffer. If message is malformed, ok of false is returned. For last message,
// padding check is loose, if there isn't enough padding, whole buf is consumed
// and ok is set to true.
func ParseMessage(buf []byte) (msg *Message, rest []byte, ok bool) {
	b := BytesView(buf)

	hdrBytes, ok := b.Extract(linux.NetlinkMessageHeaderSize)
	if !ok {
		return
	}
	var hdr linux.NetlinkMessageHeader
	hdr.UnmarshalUnsafe(hdrBytes)

	// Msg portion.
	totalMsgLen := int(hdr.Length)
	_, ok = b.Extract(totalMsgLen - linux.NetlinkMessageHeaderSize)
	if !ok {
		return
	}

	// Padding.
	numPad := alignPad(totalMsgLen, linux.NLMSG_ALIGNTO)
	// Linux permits the last message not being aligned, just consume all of it.
	// Ref: net/netlink/af_netlink.c:netlink_rcv_skb
	if numPad > len(b) {
		numPad = len(b)
	}
	_, ok = b.Extract(numPad)
	if !ok {
		return
	}

	return &Message{
		hdr: hdr,
		buf: buf[:totalMsgLen],
	}, []byte(b), true
}

// Header returns the header of this message.
func (m *Message) Header() linux.NetlinkMessageHeader {
	return m.hdr
}

// GetData unmarshals the payload message header from this netlink message, and
// returns the attributes portion.
func (m *Message) GetData(msg marshal.Marshallable) (AttrsView, bool) {
	b := BytesView(m.buf)

	_, ok := b.Extract(linux.NetlinkMessageHeaderSize)
	if !ok {
		return nil, false
	}

	size := msg.SizeBytes()
	msgBytes, ok := b.Extract(size)
	if !ok {
		return nil, false
	}
	msg.UnmarshalUnsafe(msgBytes)

	numPad := alignPad(linux.NetlinkMessageHeaderSize+size, linux.NLMSG_ALIGNTO)
	// Linux permits the last message not being aligned, just consume all of it.
	// Ref: net/netlink/af_netlink.c:netlink_rcv_skb
	if numPad > len(b) {
		numPad = len(b)
	}
	_, ok = b.Extract(numPad)
	if !ok {
		return nil, false
	}

	return AttrsView(b), true
}

// Finalize returns the []byte containing the entire message, with the total
// length set in the message header. The Message must not be modified after
// calling Finalize.
func (m *Message) Finalize() []byte {
	// Update length, which is the first 4 bytes of the header.
	hostarch.ByteOrder.PutUint32(m.buf, uint32(len(m.buf)))

	// Align the message. Note that the message length in the header (set
	// above) is the useful length of the message, not the total aligned
	// length. See net/netlink/af_netlink.c:__nlmsg_put.
	aligned := bits.AlignUp(len(m.buf), linux.NLMSG_ALIGNTO)
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
func (m *Message) Put(v marshal.Marshallable) {
	m.buf = append(m.buf, marshal.Marshal(v)...)
}

// PutAttr adds v to the message as a netlink attribute.
//
// Preconditions: The serialized attribute (linux.NetlinkAttrHeaderSize +
// v.SizeBytes()) fits in math.MaxUint16 bytes.
func (m *Message) PutAttr(atype uint16, v marshal.Marshallable) {
	l := linux.NetlinkAttrHeaderSize + v.SizeBytes()
	if l > math.MaxUint16 {
		panic(fmt.Sprintf("attribute too large: %d", l))
	}

	m.Put(&linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})
	m.Put(v)

	// Align the attribute.
	aligned := bits.AlignUp(l, linux.NLA_ALIGNTO)
	m.putZeros(aligned - l)
}

// PutAttrString adds s to the message as a netlink attribute.
func (m *Message) PutAttrString(atype uint16, s string) {
	l := linux.NetlinkAttrHeaderSize + len(s) + 1
	m.Put(&linux.NetlinkAttrHeader{
		Type:   atype,
		Length: uint16(l),
	})

	// String + NUL-termination.
	m.Put(primitive.AsByteSlice([]byte(s)))
	m.putZeros(1)

	// Align the attribute.
	aligned := bits.AlignUp(l, linux.NLA_ALIGNTO)
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

// AttrsView is a view into the attributes portion of a netlink message.
type AttrsView []byte

// Empty returns whether there is no attribute left in v.
func (v AttrsView) Empty() bool {
	return len(v) == 0
}

// ParseFirst parses first netlink attribute at the beginning of v.
func (v AttrsView) ParseFirst() (hdr linux.NetlinkAttrHeader, value []byte, rest AttrsView, ok bool) {
	b := BytesView(v)

	hdrBytes, ok := b.Extract(linux.NetlinkAttrHeaderSize)
	if !ok {
		log.Debugf("Failed to parse netlink attributes at header stage")
		return
	}
	hdr.UnmarshalUnsafe(hdrBytes)

	value, ok = b.Extract(int(hdr.Length) - linux.NetlinkAttrHeaderSize)
	if !ok {
		log.Debugf("Failed to parse %d bytes after %d header bytes", int(hdr.Length)-linux.NetlinkAttrHeaderSize, linux.NetlinkAttrHeaderSize)
		return
	}

	_, ok = b.Extract(alignPad(int(hdr.Length), linux.NLA_ALIGNTO))
	if !ok {
		log.Debugf("Failed to parse netlink attributes at aligning stage")
		return
	}

	return hdr, value, AttrsView(b), ok
}

// Parse parses netlink attributes.
func (v AttrsView) Parse() (map[uint16]BytesView, bool) {
	attrs := make(map[uint16]BytesView)
	attrsView := v
	for !attrsView.Empty() {
		// The index is unspecified, search by the interface name.
		ahdr, value, rest, ok := attrsView.ParseFirst()
		if !ok {
			return nil, false
		}
		attrsView = rest
		attrs[ahdr.Type] = BytesView(value)
	}
	return attrs, true

}

// BytesView supports extracting data from a byte slice with bounds checking.
type BytesView []byte

// Extract removes the first n bytes from v and returns it. If n is out of
// bounds, it returns false.
func (v *BytesView) Extract(n int) ([]byte, bool) {
	if n < 0 || n > len(*v) {
		return nil, false
	}
	extracted := (*v)[:n]
	*v = (*v)[n:]
	return extracted, true
}

// String converts the raw attribute value to string.
func (v *BytesView) String() string {
	b := []byte(*v)
	if len(b) == 0 {
		return ""
	}
	if b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return string(b)
}

// Uint32 converts the raw attribute value to uint32.
func (v *BytesView) Uint32() (uint32, bool) {
	attr := []byte(*v)
	val := primitive.Uint32(0)
	if len(attr) != val.SizeBytes() {
		return 0, false
	}
	val.UnmarshalBytes(attr)
	return uint32(val), true
}

// Uint64 converts the raw attribute value to uint64.
func (v *BytesView) Uint64() (uint64, bool) {
	attr := []byte(*v)
	val := primitive.Uint64(0)
	if len(attr) != val.SizeBytes() {
		return 0, false
	}
	val.UnmarshalBytes(attr)
	return uint64(val), true
}

// Int32 converts the raw attribute value to int32.
func (v *BytesView) Int32() (int32, bool) {
	attr := []byte(*v)
	val := primitive.Int32(0)
	if len(attr) != val.SizeBytes() {
		return 0, false
	}
	val.UnmarshalBytes(attr)
	return int32(val), true
}
