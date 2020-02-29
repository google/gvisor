// Copyright 2020 The gVisor Authors.
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

package testbench

import (
	"fmt"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Layer is the interface that all encapsulations must implement.
//
// A Layer is an encapsulation in a packet, such as TCP, IPv4, IPv6, etc. A
// Layer contains all the fields of the encapsulation. Each field is a pointer
// and may be nil.
type Layer interface {
	// toBytes converts the Layer into bytes. In places where the Layer's field
	// isn't nil, the value that is pointed to is used. When the field is nil, a
	// reasonable default for the Layer is used. For example, "64" for IPv4 TTL
	// and a calculated checksum for TCP or IP. Some layers require information
	// from the previous or next layers in order to compute a default, such as
	// TCP's checksum or Ethernet's type, so each Layer has a doubly-linked list
	// to the layer's neighbors.
	toBytes() ([]byte, error)

	// match checks if the current Layer matches the provided Layer. If either
	// Layer has a nil in a given field, that field is considered matching.
	// Otherwise, the values pointed to by the fields must match.
	match(Layer) bool

	// length in bytes of the current encapsulation
	length() int

	// getNext gets a pointer to the encapsulated Layer.
	getNext() Layer

	// getPrev gets a pointer to the Layer encapsulating this one.
	getPrev() Layer

	// setNext sets the pointer to the encapsulated Layer.
	setNext(Layer)

	// setPrev sets the pointer to the Layer encapsulating this one.
	setPrev(Layer)
}

// LayerBase is the common elements of all layers.
type LayerBase struct {
	next Layer
	prev Layer
}

func (lb *LayerBase) getNext() Layer {
	return lb.next
}

func (lb *LayerBase) getPrev() Layer {
	return lb.prev
}

func (lb *LayerBase) setNext(l Layer) {
	lb.next = l
}

func (lb *LayerBase) setPrev(l Layer) {
	lb.prev = l
}

func equalLayer(x, y Layer) bool {
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		if reflect.ValueOf(x).Kind() == reflect.Ptr && reflect.ValueOf(x).IsNil() {
			return true
		}
		if reflect.ValueOf(y).Kind() == reflect.Ptr && reflect.ValueOf(y).IsNil() {
			return true
		}
		return false

	}, cmp.Ignore())
	return cmp.Equal(x, y, opt, cmpopts.IgnoreUnexported(LayerBase{}))
}

// Ether can construct and match the ethernet excapulation.
type Ether struct {
	LayerBase
	SrcAddr *tcpip.LinkAddress
	DstAddr *tcpip.LinkAddress
	Type    *tcpip.NetworkProtocolNumber
}

func (l *Ether) toBytes() ([]byte, error) {
	b := make([]byte, header.EthernetMinimumSize)
	h := header.Ethernet(b)
	fields := &header.EthernetFields{}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	if l.Type != nil {
		fields.Type = *l.Type
	} else {
		switch n := l.getNext().(type) {
		case *IPv4:
			fields.Type = header.IPv4ProtocolNumber
		default:
			return nil, fmt.Errorf("can't deduce the ethernet header's next protocol: %d", n)
		}
	}
	h.Encode(fields)
	return h, nil
}

// LinkAddress is a helper routine that allocates a new tcpip.LinkAddress value
// to store v and returns a pointer to it.
func LinkAddress(v tcpip.LinkAddress) *tcpip.LinkAddress {
	return &v
}

// NetworkProtocolNumber is a helper routine that allocates a new
// tcpip.NetworkProtocolNumber value to store v and returns a pointer to it.
func NetworkProtocolNumber(v tcpip.NetworkProtocolNumber) *tcpip.NetworkProtocolNumber {
	return &v
}

// ParseEther parses the bytes assuming that they start with an ethernet header
// and continues parsing further encapsulations.
func ParseEther(b []byte) (Layers, error) {
	h := header.Ethernet(b)
	ether := Ether{
		SrcAddr: LinkAddress(h.SourceAddress()),
		DstAddr: LinkAddress(h.DestinationAddress()),
		Type:    NetworkProtocolNumber(h.Type()),
	}
	layers := Layers{&ether}
	switch h.Type() {
	case header.IPv4ProtocolNumber:
		moreLayers, err := ParseIPv4(b[ether.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	default:
		return nil, fmt.Errorf("can't deduce the ethernet header's next protocol: %v", b)
	}
}

func (l *Ether) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Ether) length() int {
	return header.EthernetMinimumSize
}

// IPv4 can construct and match the ethernet excapulation.
type IPv4 struct {
	LayerBase
	IHL            *uint8
	TOS            *uint8
	TotalLength    *uint16
	ID             *uint16
	Flags          *uint8
	FragmentOffset *uint16
	TTL            *uint8
	Protocol       *uint8
	Checksum       *uint16
	SrcAddr        *tcpip.Address
	DstAddr        *tcpip.Address
}

func (l *IPv4) toBytes() ([]byte, error) {
	b := make([]byte, header.IPv4MinimumSize)
	h := header.IPv4(b)
	fields := &header.IPv4Fields{
		IHL:            20,
		TOS:            0,
		TotalLength:    0,
		ID:             0,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            64,
		Protocol:       0,
		Checksum:       0,
		SrcAddr:        tcpip.Address(""),
		DstAddr:        tcpip.Address(""),
	}
	if l.TOS != nil {
		fields.TOS = *l.TOS
	}
	if l.TotalLength != nil {
		fields.TotalLength = *l.TotalLength
	} else {
		fields.TotalLength = uint16(l.length())
		current := l.getNext()
		for current != nil {
			fields.TotalLength += uint16(current.length())
			current = current.getNext()
		}
	}
	if l.ID != nil {
		fields.ID = *l.ID
	}
	if l.Flags != nil {
		fields.Flags = *l.Flags
	}
	if l.FragmentOffset != nil {
		fields.FragmentOffset = *l.FragmentOffset
	}
	if l.TTL != nil {
		fields.TTL = *l.TTL
	}
	if l.Protocol != nil {
		fields.Protocol = *l.Protocol
	} else {
		switch n := l.getNext().(type) {
		case *TCP:
			fields.Protocol = uint8(header.TCPProtocolNumber)
		default:
			return nil, fmt.Errorf("can't deduce the ip header's next protocol: %+v", n)
		}
	}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	if l.Checksum != nil {
		fields.Checksum = *l.Checksum
	}
	h.Encode(fields)
	if l.Checksum == nil {
		h.SetChecksum(^h.CalculateChecksum())
	}
	return h, nil
}

// Uint16 is a helper routine that allocates a new
// uint16 value to store v and returns a pointer to it.
func Uint16(v uint16) *uint16 {
	return &v
}

// Uint8 is a helper routine that allocates a new
// uint8 value to store v and returns a pointer to it.
func Uint8(v uint8) *uint8 {
	return &v
}

// Address is a helper routine that allocates a new tcpip.Address value to store
// v and returns a pointer to it.
func Address(v tcpip.Address) *tcpip.Address {
	return &v
}

// ParseIPv4 parses the bytes assuming that they start with an ipv4 header and
// continues parsing further encapsulations.
func ParseIPv4(b []byte) (Layers, error) {
	h := header.IPv4(b)
	tos, _ := h.TOS()
	ipv4 := IPv4{
		IHL:            Uint8(h.HeaderLength()),
		TOS:            Uint8(tos),
		TotalLength:    Uint16(h.TotalLength()),
		ID:             Uint16(h.ID()),
		Flags:          Uint8(h.Flags()),
		FragmentOffset: Uint16(h.FragmentOffset()),
		TTL:            Uint8(h.TTL()),
		Protocol:       Uint8(h.Protocol()),
		Checksum:       Uint16(h.Checksum()),
		SrcAddr:        Address(h.SourceAddress()),
		DstAddr:        Address(h.DestinationAddress()),
	}
	layers := Layers{&ipv4}
	switch h.Protocol() {
	case uint8(header.TCPProtocolNumber):
		moreLayers, err := ParseTCP(b[ipv4.length():])
		if err != nil {
			return nil, err
		}
		return append(layers, moreLayers...), nil
	}
	return nil, fmt.Errorf("can't deduce the ethernet header's next protocol: %d", h.Protocol())
}

func (l *IPv4) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *IPv4) length() int {
	if l.IHL == nil {
		return header.IPv4MinimumSize
	}
	return int(*l.IHL)
}

// TCP can construct and match the TCP excapulation.
type TCP struct {
	LayerBase
	SrcPort       *uint16
	DstPort       *uint16
	SeqNum        *uint32
	AckNum        *uint32
	DataOffset    *uint8
	Flags         *uint8
	WindowSize    *uint16
	Checksum      *uint16
	UrgentPointer *uint16
}

func (l *TCP) toBytes() ([]byte, error) {
	b := make([]byte, header.TCPMinimumSize)
	h := header.TCP(b)
	if l.SrcPort != nil {
		h.SetSourcePort(*l.SrcPort)
	}
	if l.DstPort != nil {
		h.SetDestinationPort(*l.DstPort)
	}
	if l.SeqNum != nil {
		h.SetSequenceNumber(*l.SeqNum)
	}
	if l.AckNum != nil {
		h.SetAckNumber(*l.AckNum)
	}
	if l.DataOffset != nil {
		h.SetDataOffset(*l.DataOffset)
	}
	if l.Flags != nil {
		h.SetFlags(*l.Flags)
	}
	if l.WindowSize != nil {
		h.SetWindowSize(*l.WindowSize)
	}
	if l.UrgentPointer != nil {
		h.SetUrgentPoiner(*l.UrgentPointer)
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
	}
	if l.Checksum == nil {
		h.SetChecksum(0)
		tcpLength := uint16(l.length())
		current := l.getNext()
		for current != nil {
			tcpLength += uint16(current.length())
			current = current.getNext()
		}

		var xsum uint16
		switch s := l.getPrev().(type) {
		case *IPv4:
			xsum = header.PseudoHeaderChecksum(header.TCPProtocolNumber, *s.SrcAddr, *s.DstAddr, tcpLength)
		default:
			return nil, fmt.Errorf("can't get src and dst addr from previous layer")
		}
		current = l.getNext()
		for current != nil {
			payload, err := current.toBytes()
			if err != nil {
				return nil, fmt.Errorf("can't get bytes for next header: %s", payload)
			}
			xsum = header.Checksum(payload, xsum)
			current = current.getNext()
		}
		h.SetChecksum(^h.CalculateChecksum(xsum))
	}
	return h, nil
}

// Uint32 is a helper routine that allocates a new
// uint32 value to store v and returns a pointer to it.
func Uint32(v uint32) *uint32 {
	return &v
}

// ParseTCP parses the bytes assuming that they start with a tcp header and
// continues parsing further encapsulations.
func ParseTCP(b []byte) (Layers, error) {
	h := header.TCP(b)
	tcp := TCP{
		SrcPort:       Uint16(h.SourcePort()),
		DstPort:       Uint16(h.DestinationPort()),
		SeqNum:        Uint32(h.SequenceNumber()),
		AckNum:        Uint32(h.AckNumber()),
		DataOffset:    Uint8(h.DataOffset()),
		Flags:         Uint8(h.Flags()),
		WindowSize:    Uint16(h.WindowSize()),
		Checksum:      Uint16(h.Checksum()),
		UrgentPointer: Uint16(h.UrgentPointer()),
	}
	layers := Layers{&tcp}
	moreLayers, err := ParsePayload(b[tcp.length():])
	if err != nil {
		return nil, err
	}
	return append(layers, moreLayers...), nil
}

func (l *TCP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *TCP) length() int {
	if l.DataOffset == nil {
		return header.TCPMinimumSize
	}
	return int(*l.DataOffset)
}

// Payload has bytes beyond OSI layer 4.
type Payload struct {
	LayerBase
	Bytes []byte
}

// ParsePayload parses the bytes assuming that they start with a payload and
// continue to the end. There can be no further encapsulations.
func ParsePayload(b []byte) (Layers, error) {
	payload := Payload{
		Bytes: b,
	}
	return Layers{&payload}, nil
}

func (l *Payload) toBytes() ([]byte, error) {
	return l.Bytes, nil
}

func (l *Payload) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Payload) length() int {
	return len(l.Bytes)
}

// Layers is an array of Layer and supports similar functions to Layer.
type Layers []Layer

func (ls *Layers) toBytes() ([]byte, error) {
	for i, l := range *ls {
		if i > 0 {
			l.setPrev((*ls)[i-1])
		}
		if i+1 < len(*ls) {
			l.setNext((*ls)[i+1])
		}
	}
	outBytes := []byte{}
	for _, l := range *ls {
		layerBytes, err := l.toBytes()
		if err != nil {
			return nil, err
		}
		outBytes = append(outBytes, layerBytes...)
	}
	return outBytes, nil
}

func (ls *Layers) match(other Layers) bool {
	if len(*ls) > len(other) {
		return false
	}
	for i := 0; i < len(*ls); i++ {
		if !equalLayer((*ls)[i], other[i]) {
			return false
		}
	}
	return true
}
