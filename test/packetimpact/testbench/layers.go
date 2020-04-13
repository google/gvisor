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
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/imdario/mergo"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Layer is the interface that all encapsulations must implement.
//
// A Layer is an encapsulation in a packet, such as TCP, IPv4, IPv6, etc. A
// Layer contains all the fields of the encapsulation. Each field is a pointer
// and may be nil.
type Layer interface {
	fmt.Stringer

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
	// Otherwise, the values pointed to by the fields must match. The LayerBase is
	// ignored.
	match(Layer) bool

	// length in bytes of the current encapsulation
	length() int

	// next gets a pointer to the encapsulated Layer.
	next() Layer

	// prev gets a pointer to the Layer encapsulating this one.
	prev() Layer

	// setNext sets the pointer to the encapsulated Layer.
	setNext(Layer)

	// setPrev sets the pointer to the Layer encapsulating this one.
	setPrev(Layer)
}

// LayerBase is the common elements of all layers.
type LayerBase struct {
	nextLayer Layer
	prevLayer Layer
}

func (lb *LayerBase) next() Layer {
	return lb.nextLayer
}

func (lb *LayerBase) prev() Layer {
	return lb.prevLayer
}

func (lb *LayerBase) setNext(l Layer) {
	lb.nextLayer = l
}

func (lb *LayerBase) setPrev(l Layer) {
	lb.prevLayer = l
}

// equalLayer compares that two Layer structs match while ignoring field in
// which either input has a nil and also ignoring the LayerBase of the inputs.
func equalLayer(x, y Layer) bool {
	// opt ignores comparison pairs where either of the inputs is a nil.
	opt := cmp.FilterValues(func(x, y interface{}) bool {
		for _, l := range []interface{}{x, y} {
			v := reflect.ValueOf(l)
			if (v.Kind() == reflect.Ptr || v.Kind() == reflect.Slice) && v.IsNil() {
				return true
			}
		}
		return false
	}, cmp.Ignore())
	return cmp.Equal(x, y, opt, cmpopts.IgnoreTypes(LayerBase{}))
}

func stringLayer(l Layer) string {
	v := reflect.ValueOf(l).Elem()
	t := v.Type()
	var ret []string
	for i := 0; i < v.NumField(); i++ {
		t := t.Field(i)
		if t.Anonymous {
			// Ignore the LayerBase in the Layer struct.
			continue
		}
		v := v.Field(i)
		if v.IsNil() {
			continue
		}
		ret = append(ret, fmt.Sprintf("%s:%v", t.Name, reflect.Indirect(v)))
	}
	return fmt.Sprintf("&%s{%s}", t, strings.Join(ret, " "))
}

// Ether can construct and match an ethernet encapsulation.
type Ether struct {
	LayerBase
	SrcAddr *tcpip.LinkAddress
	DstAddr *tcpip.LinkAddress
	Type    *tcpip.NetworkProtocolNumber
}

func (l *Ether) String() string {
	return stringLayer(l)
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
		switch n := l.next().(type) {
		case *IPv4:
			fields.Type = header.IPv4ProtocolNumber
		default:
			// TODO(b/150301488): Support more protocols, like IPv6.
			return nil, fmt.Errorf("ethernet header's next layer is unrecognized: %#v", n)
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

// LayerParser parses the input bytes and returns a Layer along with the next
// LayerParser to run. If there is no more parsing to do, the returned
// LayerParser is nil.
type LayerParser func([]byte) (Layer, LayerParser)

// Parse parses bytes starting with the first LayerParser and using successive
// LayerParsers until all the bytes are parsed.
func Parse(parser LayerParser, b []byte) Layers {
	var layers Layers
	for {
		var layer Layer
		layer, parser = parser(b)
		layers = append(layers, layer)
		if parser == nil {
			break
		}
		b = b[layer.length():]
	}
	layers.linkLayers()
	return layers
}

// ParseEther parses the bytes assuming that they start with an ethernet header
// and continues parsing further encapsulations.
func ParseEther(b []byte) (Layer, LayerParser) {
	h := header.Ethernet(b)
	ether := Ether{
		SrcAddr: LinkAddress(h.SourceAddress()),
		DstAddr: LinkAddress(h.DestinationAddress()),
		Type:    NetworkProtocolNumber(h.Type()),
	}
	var nextParser LayerParser
	switch h.Type() {
	case header.IPv4ProtocolNumber:
		nextParser = ParseIPv4
	default:
		// Assume that the rest is a payload.
		nextParser = ParsePayload
	}
	return &ether, nextParser
}

func (l *Ether) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Ether) length() int {
	return header.EthernetMinimumSize
}

// IPv4 can construct and match an IPv4 encapsulation.
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

func (l *IPv4) String() string {
	return stringLayer(l)
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
		current := l.next()
		for current != nil {
			fields.TotalLength += uint16(current.length())
			current = current.next()
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
		switch n := l.next().(type) {
		case *TCP:
			fields.Protocol = uint8(header.TCPProtocolNumber)
		case *UDP:
			fields.Protocol = uint8(header.UDPProtocolNumber)
		default:
			// TODO(b/150301488): Support more protocols as needed.
			return nil, fmt.Errorf("ipv4 header's next layer is unrecognized: %#v", n)
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
func ParseIPv4(b []byte) (Layer, LayerParser) {
	h := header.IPv4(b)
	tos, _ := h.TOS()
	ipv4 := IPv4{
		IHL:            Uint8(h.HeaderLength()),
		TOS:            &tos,
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
	var nextParser LayerParser
	switch h.TransportProtocol() {
	case header.TCPProtocolNumber:
		nextParser = ParseTCP
	case header.UDPProtocolNumber:
		nextParser = ParseUDP
	default:
		// Assume that the rest is a payload.
		nextParser = ParsePayload
	}
	return &ipv4, nextParser
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

// TCP can construct and match a TCP encapsulation.
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

func (l *TCP) String() string {
	return stringLayer(l)
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
	} else {
		h.SetDataOffset(uint8(l.length()))
	}
	if l.Flags != nil {
		h.SetFlags(*l.Flags)
	}
	if l.WindowSize != nil {
		h.SetWindowSize(*l.WindowSize)
	} else {
		h.SetWindowSize(32768)
	}
	if l.UrgentPointer != nil {
		h.SetUrgentPoiner(*l.UrgentPointer)
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
		return h, nil
	}
	if err := setTCPChecksum(&h, l); err != nil {
		return nil, err
	}
	return h, nil
}

// totalLength returns the length of the provided layer and all following
// layers.
func totalLength(l Layer) int {
	var totalLength int
	for ; l != nil; l = l.next() {
		totalLength += l.length()
	}
	return totalLength
}

// layerChecksum calculates the checksum of the Layer header, including the
// peusdeochecksum of the layer before it and all the bytes after it..
func layerChecksum(l Layer, protoNumber tcpip.TransportProtocolNumber) (uint16, error) {
	totalLength := uint16(totalLength(l))
	var xsum uint16
	switch s := l.prev().(type) {
	case *IPv4:
		xsum = header.PseudoHeaderChecksum(protoNumber, *s.SrcAddr, *s.DstAddr, totalLength)
	default:
		// TODO(b/150301488): Support more protocols, like IPv6.
		return 0, fmt.Errorf("can't get src and dst addr from previous layer: %#v", s)
	}
	var payloadBytes buffer.VectorisedView
	for current := l.next(); current != nil; current = current.next() {
		payload, err := current.toBytes()
		if err != nil {
			return 0, fmt.Errorf("can't get bytes for next header: %s", payload)
		}
		payloadBytes.AppendView(payload)
	}
	xsum = header.ChecksumVV(payloadBytes, xsum)
	return xsum, nil
}

// setTCPChecksum calculates the checksum of the TCP header and sets it in h.
func setTCPChecksum(h *header.TCP, tcp *TCP) error {
	h.SetChecksum(0)
	xsum, err := layerChecksum(tcp, header.TCPProtocolNumber)
	if err != nil {
		return err
	}
	h.SetChecksum(^h.CalculateChecksum(xsum))
	return nil
}

// Uint32 is a helper routine that allocates a new
// uint32 value to store v and returns a pointer to it.
func Uint32(v uint32) *uint32 {
	return &v
}

// ParseTCP parses the bytes assuming that they start with a tcp header and
// continues parsing further encapsulations.
func ParseTCP(b []byte) (Layer, LayerParser) {
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
	return &tcp, ParsePayload
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

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *TCP) merge(other TCP) error {
	return mergo.Merge(l, other, mergo.WithOverride)
}

// UDP can construct and match a UDP encapsulation.
type UDP struct {
	LayerBase
	SrcPort  *uint16
	DstPort  *uint16
	Length   *uint16
	Checksum *uint16
}

func (l *UDP) String() string {
	return stringLayer(l)
}

func (l *UDP) toBytes() ([]byte, error) {
	b := make([]byte, header.UDPMinimumSize)
	h := header.UDP(b)
	if l.SrcPort != nil {
		h.SetSourcePort(*l.SrcPort)
	}
	if l.DstPort != nil {
		h.SetDestinationPort(*l.DstPort)
	}
	if l.Length != nil {
		h.SetLength(*l.Length)
	} else {
		h.SetLength(uint16(totalLength(l)))
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
		return h, nil
	}
	if err := setUDPChecksum(&h, l); err != nil {
		return nil, err
	}
	return h, nil
}

// setUDPChecksum calculates the checksum of the UDP header and sets it in h.
func setUDPChecksum(h *header.UDP, udp *UDP) error {
	h.SetChecksum(0)
	xsum, err := layerChecksum(udp, header.UDPProtocolNumber)
	if err != nil {
		return err
	}
	h.SetChecksum(^h.CalculateChecksum(xsum))
	return nil
}

// ParseUDP parses the bytes assuming that they start with a udp header and
// returns the parsed layer and the next parser to use.
func ParseUDP(b []byte) (Layer, LayerParser) {
	h := header.UDP(b)
	udp := UDP{
		SrcPort:  Uint16(h.SourcePort()),
		DstPort:  Uint16(h.DestinationPort()),
		Length:   Uint16(h.Length()),
		Checksum: Uint16(h.Checksum()),
	}
	return &udp, ParsePayload
}

func (l *UDP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *UDP) length() int {
	if l.Length == nil {
		return header.UDPMinimumSize
	}
	return int(*l.Length)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *UDP) merge(other UDP) error {
	return mergo.Merge(l, other, mergo.WithOverride)
}

// Payload has bytes beyond OSI layer 4.
type Payload struct {
	LayerBase
	Bytes []byte
}

func (l *Payload) String() string {
	return stringLayer(l)
}

// ParsePayload parses the bytes assuming that they start with a payload and
// continue to the end. There can be no further encapsulations.
func ParsePayload(b []byte) (Layer, LayerParser) {
	payload := Payload{
		Bytes: b,
	}
	return &payload, nil
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

// linkLayers sets the linked-list ponters in ls.
func (ls *Layers) linkLayers() {
	for i, l := range *ls {
		if i > 0 {
			l.setPrev((*ls)[i-1])
		} else {
			l.setPrev(nil)
		}
		if i+1 < len(*ls) {
			l.setNext((*ls)[i+1])
		} else {
			l.setNext(nil)
		}
	}
}

func (ls *Layers) toBytes() ([]byte, error) {
	ls.linkLayers()
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
