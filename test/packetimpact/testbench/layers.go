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
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.uber.org/multierr"
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

	// ToBytes converts the Layer into bytes. In places where the Layer's field
	// isn't nil, the value that is pointed to is used. When the field is nil, a
	// reasonable default for the Layer is used. For example, "64" for IPv4 TTL
	// and a calculated checksum for TCP or IP. Some layers require information
	// from the previous or next layers in order to compute a default, such as
	// TCP's checksum or Ethernet's type, so each Layer has a doubly-linked list
	// to the layer's neighbors.
	ToBytes() ([]byte, error)

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
	Prev() Layer

	// setNext sets the pointer to the encapsulated Layer.
	setNext(Layer)

	// setPrev sets the pointer to the Layer encapsulating this one.
	setPrev(Layer)

	// merge overrides the values in the interface with the provided values.
	merge(Layer) error
}

// LayerBase is the common elements of all layers.
type LayerBase struct {
	nextLayer Layer
	prevLayer Layer
}

func (lb *LayerBase) next() Layer {
	return lb.nextLayer
}

// Prev returns the previous layer.
func (lb *LayerBase) Prev() Layer {
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
	if x == nil || y == nil {
		return true
	}
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

// mergeLayer merges y into x. Any fields for which y has a non-nil value, that
// value overwrite the corresponding fields in x.
func mergeLayer(x, y Layer) error {
	if y == nil {
		return nil
	}
	if reflect.TypeOf(x) != reflect.TypeOf(y) {
		return fmt.Errorf("can't merge %T into %T", y, x)
	}
	vx := reflect.ValueOf(x).Elem()
	vy := reflect.ValueOf(y).Elem()
	t := vy.Type()
	for i := 0; i < vy.NumField(); i++ {
		t := t.Field(i)
		if t.Anonymous {
			// Ignore the LayerBase in the Layer struct.
			continue
		}
		v := vy.Field(i)
		if v.IsNil() {
			continue
		}
		vx.Field(i).Set(v)
	}
	return nil
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
		v = reflect.Indirect(v)
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
			ret = append(ret, fmt.Sprintf("%s:\n%v", t.Name, hex.Dump(v.Bytes())))
		} else {
			ret = append(ret, fmt.Sprintf("%s:%v", t.Name, v))
		}
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

// ToBytes implements Layer.ToBytes.
func (l *Ether) ToBytes() ([]byte, error) {
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
		case *IPv6:
			fields.Type = header.IPv6ProtocolNumber
		default:
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

// layerParser parses the input bytes and returns a Layer along with the next
// layerParser to run. If there is no more parsing to do, the returned
// layerParser is nil.
type layerParser func([]byte) (Layer, layerParser)

// parse parses bytes starting with the first layerParser and using successive
// layerParsers until all the bytes are parsed.
func parse(parser layerParser, b []byte) Layers {
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

// parseEther parses the bytes assuming that they start with an ethernet header
// and continues parsing further encapsulations.
func parseEther(b []byte) (Layer, layerParser) {
	h := header.Ethernet(b)
	ether := Ether{
		SrcAddr: LinkAddress(h.SourceAddress()),
		DstAddr: LinkAddress(h.DestinationAddress()),
		Type:    NetworkProtocolNumber(h.Type()),
	}
	var nextParser layerParser
	switch h.Type() {
	case header.IPv4ProtocolNumber:
		nextParser = parseIPv4
	case header.IPv6ProtocolNumber:
		nextParser = parseIPv6
	default:
		// Assume that the rest is a payload.
		nextParser = parsePayload
	}
	return &ether, nextParser
}

func (l *Ether) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Ether) length() int {
	return header.EthernetMinimumSize
}

// merge implements Layer.merge.
func (l *Ether) merge(other Layer) error {
	return mergeLayer(l, other)
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
	Options        *header.IPv4Options
}

func (l *IPv4) String() string {
	return stringLayer(l)
}

// ToBytes implements Layer.ToBytes.
func (l *IPv4) ToBytes() ([]byte, error) {
	// An IPv4 header is variable length depending on the size of the Options.
	hdrLen := header.IPv4MinimumSize
	if l.Options != nil {
		if len(*l.Options)%4 != 0 {
			return nil, fmt.Errorf("invalid header options '%x (len=%d)'; must be 32 bit aligned", *l.Options, len(*l.Options))
		}
		hdrLen += len(*l.Options)
		if hdrLen > header.IPv4MaximumHeaderSize {
			return nil, fmt.Errorf("IPv4 Options %d bytes, Max %d", len(*l.Options), header.IPv4MaximumOptionsSize)
		}
	}
	b := make([]byte, hdrLen)
	h := header.IPv4(b)
	fields := &header.IPv4Fields{
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
		Options:        nil,
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
		case *ICMPv4:
			fields.Protocol = uint8(header.ICMPv4ProtocolNumber)
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

	h.Encode(fields)

	// Put raw option bytes from test definition in header. Options as raw bytes
	// allows us to serialize malformed options, which is not possible with
	// the provided serialization functions.
	if l.Options != nil {
		h.SetHeaderLength(h.HeaderLength() + uint8(len(*l.Options)))
		if got, want := copy(h.Options(), *l.Options), len(*l.Options); got != want {
			return nil, fmt.Errorf("failed to copy option bytes into header, got %d want %d", got, want)
		}
	}

	// Encode cannot set this incorrectly so we need to overwrite what it wrote
	// in order to test handling of a bad IHL value.
	if l.IHL != nil {
		h.SetHeaderLength(*l.IHL)
	}

	if l.Checksum == nil {
		h.SetChecksum(^h.CalculateChecksum())
	} else {
		h.SetChecksum(*l.Checksum)
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

// TCPFlags is a helper routine that allocates a new
// header.TCPFlags value to store v and returns a pointer to it.
func TCPFlags(v header.TCPFlags) *header.TCPFlags {
	return &v
}

// Address is a helper routine that allocates a new tcpip.Address value to
// store v and returns a pointer to it.
func Address(v tcpip.Address) *tcpip.Address {
	return &v
}

// parseIPv4 parses the bytes assuming that they start with an ipv4 header and
// continues parsing further encapsulations.
func parseIPv4(b []byte) (Layer, layerParser) {
	h := header.IPv4(b)
	options := h.Options()
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
		Options:        &options,
	}
	var nextParser layerParser
	// If it is a fragment, don't treat it as having a transport protocol.
	if h.FragmentOffset() != 0 || h.More() {
		return &ipv4, parsePayload
	}
	switch h.TransportProtocol() {
	case header.TCPProtocolNumber:
		nextParser = parseTCP
	case header.UDPProtocolNumber:
		nextParser = parseUDP
	case header.ICMPv4ProtocolNumber:
		nextParser = parseICMPv4
	default:
		// Assume that the rest is a payload.
		nextParser = parsePayload
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

// merge implements Layer.merge.
func (l *IPv4) merge(other Layer) error {
	return mergeLayer(l, other)
}

// IPv6 can construct and match an IPv6 encapsulation.
type IPv6 struct {
	LayerBase
	TrafficClass  *uint8
	FlowLabel     *uint32
	PayloadLength *uint16
	NextHeader    *uint8
	HopLimit      *uint8
	SrcAddr       *tcpip.Address
	DstAddr       *tcpip.Address
}

func (l *IPv6) String() string {
	return stringLayer(l)
}

// ToBytes implements Layer.ToBytes.
func (l *IPv6) ToBytes() ([]byte, error) {
	b := make([]byte, header.IPv6MinimumSize)
	h := header.IPv6(b)
	fields := &header.IPv6Fields{
		HopLimit: 64,
	}
	if l.TrafficClass != nil {
		fields.TrafficClass = *l.TrafficClass
	}
	if l.FlowLabel != nil {
		fields.FlowLabel = *l.FlowLabel
	}
	if l.PayloadLength != nil {
		fields.PayloadLength = *l.PayloadLength
	} else {
		for current := l.next(); current != nil; current = current.next() {
			fields.PayloadLength += uint16(current.length())
		}
	}
	if l.NextHeader != nil {
		fields.TransportProtocol = tcpip.TransportProtocolNumber(*l.NextHeader)
	} else {
		nh, err := nextHeaderByLayer(l.next())
		if err != nil {
			return nil, err
		}
		fields.TransportProtocol = tcpip.TransportProtocolNumber(nh)
	}
	if l.HopLimit != nil {
		fields.HopLimit = *l.HopLimit
	}
	if l.SrcAddr != nil {
		fields.SrcAddr = *l.SrcAddr
	}
	if l.DstAddr != nil {
		fields.DstAddr = *l.DstAddr
	}
	h.Encode(fields)
	return h, nil
}

// nextIPv6PayloadParser finds the corresponding parser for nextHeader.
func nextIPv6PayloadParser(nextHeader uint8) layerParser {
	switch tcpip.TransportProtocolNumber(nextHeader) {
	case header.TCPProtocolNumber:
		return parseTCP
	case header.UDPProtocolNumber:
		return parseUDP
	case header.ICMPv6ProtocolNumber:
		return parseICMPv6
	}
	switch header.IPv6ExtensionHeaderIdentifier(nextHeader) {
	case header.IPv6HopByHopOptionsExtHdrIdentifier:
		return parseIPv6HopByHopOptionsExtHdr
	case header.IPv6DestinationOptionsExtHdrIdentifier:
		return parseIPv6DestinationOptionsExtHdr
	case header.IPv6FragmentExtHdrIdentifier:
		return parseIPv6FragmentExtHdr
	}
	return parsePayload
}

// parseIPv6 parses the bytes assuming that they start with an ipv6 header and
// continues parsing further encapsulations.
func parseIPv6(b []byte) (Layer, layerParser) {
	h := header.IPv6(b)
	tos, flowLabel := h.TOS()
	ipv6 := IPv6{
		TrafficClass:  &tos,
		FlowLabel:     &flowLabel,
		PayloadLength: Uint16(h.PayloadLength()),
		NextHeader:    Uint8(h.NextHeader()),
		HopLimit:      Uint8(h.HopLimit()),
		SrcAddr:       Address(h.SourceAddress()),
		DstAddr:       Address(h.DestinationAddress()),
	}
	nextParser := nextIPv6PayloadParser(h.NextHeader())
	return &ipv6, nextParser
}

func (l *IPv6) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *IPv6) length() int {
	return header.IPv6MinimumSize
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *IPv6) merge(other Layer) error {
	return mergeLayer(l, other)
}

// IPv6HopByHopOptionsExtHdr can construct and match an IPv6HopByHopOptions
// Extension Header.
type IPv6HopByHopOptionsExtHdr struct {
	LayerBase
	NextHeader *header.IPv6ExtensionHeaderIdentifier
	Options    []byte
}

// IPv6DestinationOptionsExtHdr can construct and match an IPv6DestinationOptions
// Extension Header.
type IPv6DestinationOptionsExtHdr struct {
	LayerBase
	NextHeader *header.IPv6ExtensionHeaderIdentifier
	Options    []byte
}

// IPv6FragmentExtHdr can construct and match an IPv6 Fragment Extension Header.
type IPv6FragmentExtHdr struct {
	LayerBase
	NextHeader     *header.IPv6ExtensionHeaderIdentifier
	FragmentOffset *uint16
	MoreFragments  *bool
	Identification *uint32
}

// nextHeaderByLayer finds the correct next header protocol value for layer l.
func nextHeaderByLayer(l Layer) (uint8, error) {
	if l == nil {
		return uint8(header.IPv6NoNextHeaderIdentifier), nil
	}
	switch l.(type) {
	case *TCP:
		return uint8(header.TCPProtocolNumber), nil
	case *UDP:
		return uint8(header.UDPProtocolNumber), nil
	case *ICMPv6:
		return uint8(header.ICMPv6ProtocolNumber), nil
	case *Payload:
		return uint8(header.IPv6NoNextHeaderIdentifier), nil
	case *IPv6HopByHopOptionsExtHdr:
		return uint8(header.IPv6HopByHopOptionsExtHdrIdentifier), nil
	case *IPv6DestinationOptionsExtHdr:
		return uint8(header.IPv6DestinationOptionsExtHdrIdentifier), nil
	case *IPv6FragmentExtHdr:
		return uint8(header.IPv6FragmentExtHdrIdentifier), nil
	default:
		// TODO(b/161005083): Support more protocols as needed.
		return 0, fmt.Errorf("failed to deduce the IPv6 header's next protocol: %T", l)
	}
}

// ipv6OptionsExtHdrToBytes serializes an options extension header into bytes.
func ipv6OptionsExtHdrToBytes(nextHeader *header.IPv6ExtensionHeaderIdentifier, nextLayer Layer, options []byte) ([]byte, error) {
	length := len(options) + 2
	if length%8 != 0 {
		return nil, fmt.Errorf("IPv6 extension headers must be a multiple of 8 octets long, but the length given: %d, options: %s", length, hex.Dump(options))
	}
	bytes := make([]byte, length)
	if nextHeader != nil {
		bytes[0] = byte(*nextHeader)
	} else {
		nh, err := nextHeaderByLayer(nextLayer)
		if err != nil {
			return nil, err
		}
		bytes[0] = nh
	}
	// ExtHdrLen field is the length of the extension header
	// in 8-octet unit, ignoring the first 8 octets.
	// https://tools.ietf.org/html/rfc2460#section-4.3
	// https://tools.ietf.org/html/rfc2460#section-4.6
	bytes[1] = uint8((length - 8) / 8)
	copy(bytes[2:], options)
	return bytes, nil
}

// IPv6ExtHdrIdent is a helper routine that allocates a new
// header.IPv6ExtensionHeaderIdentifier value to store v and returns a pointer
// to it.
func IPv6ExtHdrIdent(id header.IPv6ExtensionHeaderIdentifier) *header.IPv6ExtensionHeaderIdentifier {
	return &id
}

// ToBytes implements Layer.ToBytes.
func (l *IPv6HopByHopOptionsExtHdr) ToBytes() ([]byte, error) {
	return ipv6OptionsExtHdrToBytes(l.NextHeader, l.next(), l.Options)
}

// ToBytes implements Layer.ToBytes.
func (l *IPv6DestinationOptionsExtHdr) ToBytes() ([]byte, error) {
	return ipv6OptionsExtHdrToBytes(l.NextHeader, l.next(), l.Options)
}

// ToBytes implements Layer.ToBytes.
func (l *IPv6FragmentExtHdr) ToBytes() ([]byte, error) {
	var offset, mflag uint16
	var ident uint32
	bytes := make([]byte, header.IPv6FragmentExtHdrLength)
	if l.NextHeader != nil {
		bytes[0] = byte(*l.NextHeader)
	} else {
		nh, err := nextHeaderByLayer(l.next())
		if err != nil {
			return nil, err
		}
		bytes[0] = nh
	}
	bytes[1] = 0 // reserved
	if l.MoreFragments != nil && *l.MoreFragments {
		mflag = 1
	}
	if l.FragmentOffset != nil {
		offset = *l.FragmentOffset
	}
	if l.Identification != nil {
		ident = *l.Identification
	}
	offsetAndMflag := offset<<3 | mflag
	binary.BigEndian.PutUint16(bytes[2:], offsetAndMflag)
	binary.BigEndian.PutUint32(bytes[4:], ident)

	return bytes, nil
}

// parseIPv6ExtHdr parses an IPv6 extension header and returns the NextHeader
// field, the rest of the payload and a parser function for the corresponding
// next extension header.
func parseIPv6ExtHdr(b []byte) (header.IPv6ExtensionHeaderIdentifier, []byte, layerParser) {
	nextHeader := b[0]
	// For HopByHop and Destination options extension headers,
	// This field is the length of the extension header in
	// 8-octet units, not including the first 8 octets.
	// https://tools.ietf.org/html/rfc2460#section-4.3
	// https://tools.ietf.org/html/rfc2460#section-4.6
	length := b[1]*8 + 8
	data := b[2:length]
	nextParser := nextIPv6PayloadParser(nextHeader)
	return header.IPv6ExtensionHeaderIdentifier(nextHeader), data, nextParser
}

// parseIPv6HopByHopOptionsExtHdr parses the bytes assuming that they start
// with an IPv6 HopByHop Options Extension Header.
func parseIPv6HopByHopOptionsExtHdr(b []byte) (Layer, layerParser) {
	nextHeader, options, nextParser := parseIPv6ExtHdr(b)
	return &IPv6HopByHopOptionsExtHdr{NextHeader: &nextHeader, Options: options}, nextParser
}

// parseIPv6DestinationOptionsExtHdr parses the bytes assuming that they start
// with an IPv6 Destination Options Extension Header.
func parseIPv6DestinationOptionsExtHdr(b []byte) (Layer, layerParser) {
	nextHeader, options, nextParser := parseIPv6ExtHdr(b)
	return &IPv6DestinationOptionsExtHdr{NextHeader: &nextHeader, Options: options}, nextParser
}

// Bool is a helper routine that allocates a new
// bool value to store v and returns a pointer to it.
func Bool(v bool) *bool {
	return &v
}

// parseIPv6FragmentExtHdr parses the bytes assuming that they start
// with an IPv6 Fragment Extension Header.
func parseIPv6FragmentExtHdr(b []byte) (Layer, layerParser) {
	nextHeader := b[0]
	var extHdr header.IPv6FragmentExtHdr
	copy(extHdr[:], b[2:])
	fragLayer := IPv6FragmentExtHdr{
		NextHeader:     IPv6ExtHdrIdent(header.IPv6ExtensionHeaderIdentifier(nextHeader)),
		FragmentOffset: Uint16(extHdr.FragmentOffset()),
		MoreFragments:  Bool(extHdr.More()),
		Identification: Uint32(extHdr.ID()),
	}
	// If it is a fragment, we can't interpret it.
	if extHdr.FragmentOffset() != 0 || extHdr.More() {
		return &fragLayer, parsePayload
	}
	return &fragLayer, nextIPv6PayloadParser(nextHeader)
}

func (l *IPv6HopByHopOptionsExtHdr) length() int {
	return len(l.Options) + 2
}

func (l *IPv6HopByHopOptionsExtHdr) match(other Layer) bool {
	return equalLayer(l, other)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *IPv6HopByHopOptionsExtHdr) merge(other Layer) error {
	return mergeLayer(l, other)
}

func (l *IPv6HopByHopOptionsExtHdr) String() string {
	return stringLayer(l)
}

func (l *IPv6DestinationOptionsExtHdr) length() int {
	return len(l.Options) + 2
}

func (l *IPv6DestinationOptionsExtHdr) match(other Layer) bool {
	return equalLayer(l, other)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *IPv6DestinationOptionsExtHdr) merge(other Layer) error {
	return mergeLayer(l, other)
}

func (l *IPv6DestinationOptionsExtHdr) String() string {
	return stringLayer(l)
}

func (*IPv6FragmentExtHdr) length() int {
	return header.IPv6FragmentExtHdrLength
}

func (l *IPv6FragmentExtHdr) match(other Layer) bool {
	return equalLayer(l, other)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *IPv6FragmentExtHdr) merge(other Layer) error {
	return mergeLayer(l, other)
}

func (l *IPv6FragmentExtHdr) String() string {
	return stringLayer(l)
}

// ICMPv6 can construct and match an ICMPv6 encapsulation.
type ICMPv6 struct {
	LayerBase
	Type     *header.ICMPv6Type
	Code     *header.ICMPv6Code
	Checksum *uint16
	Ident    *uint16 // Only in Echo Request/Reply.
	Pointer  *uint32 // Only in Parameter Problem.
	Payload  []byte
}

func (l *ICMPv6) String() string {
	// TODO(eyalsoha): Do something smarter here when *l.Type is ParameterProblem?
	// We could parse the contents of the Payload as if it were an IPv6 packet.
	return stringLayer(l)
}

// ToBytes implements Layer.ToBytes.
func (l *ICMPv6) ToBytes() ([]byte, error) {
	b := make([]byte, header.ICMPv6MinimumSize+len(l.Payload))
	h := header.ICMPv6(b)
	if l.Type != nil {
		h.SetType(*l.Type)
	}
	if l.Code != nil {
		h.SetCode(*l.Code)
	}
	if n := copy(h.Payload(), l.Payload); n != len(l.Payload) {
		panic(fmt.Sprintf("copied %d bytes, expected to copy %d bytes", n, len(l.Payload)))
	}
	typ := h.Type()
	switch typ {
	case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
		if l.Ident != nil {
			h.SetIdent(*l.Ident)
		}
	case header.ICMPv6ParamProblem:
		if l.Pointer != nil {
			h.SetTypeSpecific(*l.Pointer)
		}
	}
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
	} else {
		// It is possible that the ICMPv6 header does not follow the IPv6 header
		// immediately, there could be one or more extension headers in between.
		// We need to search backwards to find the IPv6 header.
		for layer := l.Prev(); layer != nil; layer = layer.Prev() {
			if ipv6, ok := layer.(*IPv6); ok {
				h.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
					Header:      h[:header.ICMPv6PayloadOffset],
					Src:         *ipv6.SrcAddr,
					Dst:         *ipv6.DstAddr,
					PayloadCsum: header.Checksum(l.Payload, 0 /* initial */),
					PayloadLen:  len(l.Payload),
				}))
				break
			}
		}
	}
	return h, nil
}

// ICMPv6Type is a helper routine that allocates a new ICMPv6Type value to store
// v and returns a pointer to it.
func ICMPv6Type(v header.ICMPv6Type) *header.ICMPv6Type {
	return &v
}

// ICMPv6Code is a helper routine that allocates a new ICMPv6Type value to store
// v and returns a pointer to it.
func ICMPv6Code(v header.ICMPv6Code) *header.ICMPv6Code {
	return &v
}

// parseICMPv6 parses the bytes assuming that they start with an ICMPv6 header.
func parseICMPv6(b []byte) (Layer, layerParser) {
	h := header.ICMPv6(b)
	msgType := h.Type()
	icmpv6 := ICMPv6{
		Type:     ICMPv6Type(msgType),
		Code:     ICMPv6Code(h.Code()),
		Checksum: Uint16(h.Checksum()),
		Payload:  h.Payload(),
	}
	switch msgType {
	case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
		icmpv6.Ident = Uint16(h.Ident())
	case header.ICMPv6ParamProblem:
		icmpv6.Pointer = Uint32(h.TypeSpecific())
	}
	return &icmpv6, nil
}

func (l *ICMPv6) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *ICMPv6) length() int {
	return header.ICMPv6MinimumSize + len(l.Payload)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *ICMPv6) merge(other Layer) error {
	return mergeLayer(l, other)
}

// ICMPv4 can construct and match an ICMPv4 encapsulation.
type ICMPv4 struct {
	LayerBase
	Type     *header.ICMPv4Type
	Code     *header.ICMPv4Code
	Checksum *uint16
	Ident    *uint16 // Only in Echo Request/Reply.
	Sequence *uint16 // Only in Echo Request/Reply.
	Pointer  *uint8  // Only in Parameter Problem.
	Payload  []byte
}

func (l *ICMPv4) String() string {
	return stringLayer(l)
}

// ICMPv4Type is a helper routine that allocates a new header.ICMPv4Type value
// to store t and returns a pointer to it.
func ICMPv4Type(t header.ICMPv4Type) *header.ICMPv4Type {
	return &t
}

// ICMPv4Code is a helper routine that allocates a new header.ICMPv4Code value
// to store t and returns a pointer to it.
func ICMPv4Code(t header.ICMPv4Code) *header.ICMPv4Code {
	return &t
}

// ToBytes implements Layer.ToBytes.
func (l *ICMPv4) ToBytes() ([]byte, error) {
	b := make([]byte, header.ICMPv4MinimumSize+len(l.Payload))
	h := header.ICMPv4(b)
	if l.Type != nil {
		h.SetType(*l.Type)
	}
	if l.Code != nil {
		h.SetCode(*l.Code)
	}
	if n := copy(h.Payload(), l.Payload); n != len(l.Payload) {
		panic(fmt.Sprintf("wrong number of bytes copied into h.Payload(): got = %d, want = %d", n, len(l.Payload)))
	}
	typ := h.Type()
	switch typ {
	case header.ICMPv4EchoReply, header.ICMPv4Echo:
		if l.Ident != nil {
			h.SetIdent(*l.Ident)
		}
		if l.Sequence != nil {
			h.SetSequence(*l.Sequence)
		}
	case header.ICMPv4ParamProblem:
		if l.Pointer != nil {
			h.SetPointer(*l.Pointer)
		}
	}

	// The checksum must be handled last because the ICMPv4 header fields are
	// included in the computation.
	if l.Checksum != nil {
		h.SetChecksum(*l.Checksum)
	} else {
		h.SetChecksum(^header.Checksum(h, 0))
	}

	return h, nil
}

// parseICMPv4 parses the bytes as an ICMPv4 header, returning a Layer and a
// parser for the encapsulated payload.
func parseICMPv4(b []byte) (Layer, layerParser) {
	h := header.ICMPv4(b)

	msgType := h.Type()
	icmpv4 := ICMPv4{
		Type:     ICMPv4Type(msgType),
		Code:     ICMPv4Code(h.Code()),
		Checksum: Uint16(h.Checksum()),
		Payload:  h.Payload(),
	}
	switch msgType {
	case header.ICMPv4EchoReply, header.ICMPv4Echo:
		icmpv4.Ident = Uint16(h.Ident())
		icmpv4.Sequence = Uint16(h.Sequence())
	case header.ICMPv4ParamProblem:
		icmpv4.Pointer = Uint8(h.Pointer())
	}
	return &icmpv4, nil
}

func (l *ICMPv4) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *ICMPv4) length() int {
	return header.ICMPv4MinimumSize + len(l.Payload)
}

// merge overrides the values in l with the values from other but only in fields
// where the value is not nil.
func (l *ICMPv4) merge(other Layer) error {
	return mergeLayer(l, other)
}

// TCP can construct and match a TCP encapsulation.
type TCP struct {
	LayerBase
	SrcPort       *uint16
	DstPort       *uint16
	SeqNum        *uint32
	AckNum        *uint32
	DataOffset    *uint8
	Flags         *header.TCPFlags
	WindowSize    *uint16
	Checksum      *uint16
	UrgentPointer *uint16
	Options       []byte
}

func (l *TCP) String() string {
	return stringLayer(l)
}

// ToBytes implements Layer.ToBytes.
func (l *TCP) ToBytes() ([]byte, error) {
	b := make([]byte, l.length())
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
		h.SetFlags(uint8(*l.Flags))
	}
	if l.WindowSize != nil {
		h.SetWindowSize(*l.WindowSize)
	} else {
		h.SetWindowSize(32768)
	}
	if l.UrgentPointer != nil {
		h.SetUrgentPoiner(*l.UrgentPointer)
	}
	copy(b[header.TCPMinimumSize:], l.Options)
	header.AddTCPOptionPadding(b[header.TCPMinimumSize:], len(l.Options))
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

// payload returns a buffer.VectorisedView of l's payload.
func payload(l Layer) (buffer.VectorisedView, error) {
	var payloadBytes buffer.VectorisedView
	for current := l.next(); current != nil; current = current.next() {
		payload, err := current.ToBytes()
		if err != nil {
			return buffer.VectorisedView{}, fmt.Errorf("can't get bytes for next header: %s", payload)
		}
		payloadBytes.AppendView(payload)
	}
	return payloadBytes, nil
}

// layerChecksum calculates the checksum of the Layer header, including the
// peusdeochecksum of the layer before it and all the bytes after it.
func layerChecksum(l Layer, protoNumber tcpip.TransportProtocolNumber) (uint16, error) {
	totalLength := uint16(totalLength(l))
	var xsum uint16
	switch p := l.Prev().(type) {
	case *IPv4:
		xsum = header.PseudoHeaderChecksum(protoNumber, *p.SrcAddr, *p.DstAddr, totalLength)
	case *IPv6:
		xsum = header.PseudoHeaderChecksum(protoNumber, *p.SrcAddr, *p.DstAddr, totalLength)
	default:
		// TODO(b/161246171): Support more protocols.
		return 0, fmt.Errorf("checksum for protocol %d is not supported when previous layer is %T", protoNumber, p)
	}
	payloadBytes, err := payload(l)
	if err != nil {
		return 0, err
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

// parseTCP parses the bytes assuming that they start with a tcp header and
// continues parsing further encapsulations.
func parseTCP(b []byte) (Layer, layerParser) {
	h := header.TCP(b)
	tcp := TCP{
		SrcPort:       Uint16(h.SourcePort()),
		DstPort:       Uint16(h.DestinationPort()),
		SeqNum:        Uint32(h.SequenceNumber()),
		AckNum:        Uint32(h.AckNumber()),
		DataOffset:    Uint8(h.DataOffset()),
		Flags:         TCPFlags(h.Flags()),
		WindowSize:    Uint16(h.WindowSize()),
		Checksum:      Uint16(h.Checksum()),
		UrgentPointer: Uint16(h.UrgentPointer()),
		Options:       b[header.TCPMinimumSize:h.DataOffset()],
	}
	return &tcp, parsePayload
}

func (l *TCP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *TCP) length() int {
	if l.DataOffset == nil {
		// TCP header including the options must end on a 32-bit
		// boundary; the user could potentially give us a slice
		// whose length is not a multiple of 4 bytes, so we have
		// to do the alignment here.
		optlen := (len(l.Options) + 3) & ^3
		return header.TCPMinimumSize + optlen
	}
	return int(*l.DataOffset)
}

// merge implements Layer.merge.
func (l *TCP) merge(other Layer) error {
	return mergeLayer(l, other)
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

// ToBytes implements Layer.ToBytes.
func (l *UDP) ToBytes() ([]byte, error) {
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

// parseUDP parses the bytes assuming that they start with a udp header and
// returns the parsed layer and the next parser to use.
func parseUDP(b []byte) (Layer, layerParser) {
	h := header.UDP(b)
	udp := UDP{
		SrcPort:  Uint16(h.SourcePort()),
		DstPort:  Uint16(h.DestinationPort()),
		Length:   Uint16(h.Length()),
		Checksum: Uint16(h.Checksum()),
	}
	return &udp, parsePayload
}

func (l *UDP) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *UDP) length() int {
	return header.UDPMinimumSize
}

// merge implements Layer.merge.
func (l *UDP) merge(other Layer) error {
	return mergeLayer(l, other)
}

// Payload has bytes beyond OSI layer 4.
type Payload struct {
	LayerBase
	Bytes []byte
}

func (l *Payload) String() string {
	return stringLayer(l)
}

// parsePayload parses the bytes assuming that they start with a payload and
// continue to the end. There can be no further encapsulations.
func parsePayload(b []byte) (Layer, layerParser) {
	payload := Payload{
		Bytes: b,
	}
	return &payload, nil
}

// ToBytes implements Layer.ToBytes.
func (l *Payload) ToBytes() ([]byte, error) {
	return l.Bytes, nil
}

// Length returns payload byte length.
func (l *Payload) Length() int {
	return l.length()
}

func (l *Payload) match(other Layer) bool {
	return equalLayer(l, other)
}

func (l *Payload) length() int {
	return len(l.Bytes)
}

// merge implements Layer.merge.
func (l *Payload) merge(other Layer) error {
	return mergeLayer(l, other)
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

// ToBytes converts the Layers into bytes. It creates a linked list of the Layer
// structs and then concatentates the output of ToBytes on each Layer.
func (ls *Layers) ToBytes() ([]byte, error) {
	ls.linkLayers()
	outBytes := []byte{}
	for _, l := range *ls {
		layerBytes, err := l.ToBytes()
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
	for i, l := range *ls {
		if !equalLayer(l, other[i]) {
			return false
		}
	}
	return true
}

// layerDiff stores the diffs for each field along with the label for the Layer.
// If rows is nil, that means that there was no diff.
type layerDiff struct {
	label string
	rows  []layerDiffRow
}

// layerDiffRow stores the fields and corresponding values for two got and want
// layers. If the value was nil then the string stored is the empty string.
type layerDiffRow struct {
	field, got, want string
}

// diffLayer extracts all differing fields between two layers.
func diffLayer(got, want Layer) []layerDiffRow {
	vGot := reflect.ValueOf(got).Elem()
	vWant := reflect.ValueOf(want).Elem()
	if vGot.Type() != vWant.Type() {
		return nil
	}
	t := vGot.Type()
	var result []layerDiffRow
	for i := 0; i < t.NumField(); i++ {
		t := t.Field(i)
		if t.Anonymous {
			// Ignore the LayerBase in the Layer struct.
			continue
		}
		vGot := vGot.Field(i)
		vWant := vWant.Field(i)
		gotString := ""
		if !vGot.IsNil() {
			gotString = fmt.Sprint(reflect.Indirect(vGot))
		}
		wantString := ""
		if !vWant.IsNil() {
			wantString = fmt.Sprint(reflect.Indirect(vWant))
		}
		result = append(result, layerDiffRow{t.Name, gotString, wantString})
	}
	return result
}

// layerType returns a concise string describing the type of the Layer, like
// "TCP", or "IPv6".
func layerType(l Layer) string {
	return reflect.TypeOf(l).Elem().Name()
}

// diff compares Layers and returns a representation of the difference. Each
// Layer in the Layers is pairwise compared. If an element in either is nil, it
// is considered a match with the other Layer. If two Layers have differing
// types, they don't match regardless of the contents. If two Layers have the
// same type then the fields in the Layer are pairwise compared. Fields that are
// nil always match. Two non-nil fields only match if they point to equal
// values. diff returns an empty string if and only if *ls and other match.
func (ls *Layers) diff(other Layers) string {
	var allDiffs []layerDiff
	// Check the cases where one list is longer than the other, where one or both
	// elements are nil, where the sides have different types, and where the sides
	// have the same type.
	for i := 0; i < len(*ls) || i < len(other); i++ {
		if i >= len(*ls) {
			// Matching ls against other where other is longer than ls. missing
			// matches everything so we just include a label without any rows. Having
			// no rows is a sign that there was no diff.
			allDiffs = append(allDiffs, layerDiff{
				label: "missing matches " + layerType(other[i]),
			})
			continue
		}

		if i >= len(other) {
			// Matching ls against other where ls is longer than other. missing
			// matches everything so we just include a label without any rows. Having
			// no rows is a sign that there was no diff.
			allDiffs = append(allDiffs, layerDiff{
				label: layerType((*ls)[i]) + " matches missing",
			})
			continue
		}

		if (*ls)[i] == nil && other[i] == nil {
			// Matching ls against other where both elements are nil. nil matches
			// everything so we just include a label without any rows. Having no rows
			// is a sign that there was no diff.
			allDiffs = append(allDiffs, layerDiff{
				label: "nil matches nil",
			})
			continue
		}

		if (*ls)[i] == nil {
			// Matching ls against other where the element in ls is nil. nil matches
			// everything so we just include a label without any rows. Having no rows
			// is a sign that there was no diff.
			allDiffs = append(allDiffs, layerDiff{
				label: "nil matches " + layerType(other[i]),
			})
			continue
		}

		if other[i] == nil {
			// Matching ls against other where the element in other is nil. nil
			// matches everything so we just include a label without any rows. Having
			// no rows is a sign that there was no diff.
			allDiffs = append(allDiffs, layerDiff{
				label: layerType((*ls)[i]) + " matches nil",
			})
			continue
		}

		if reflect.TypeOf((*ls)[i]) == reflect.TypeOf(other[i]) {
			// Matching ls against other where both elements have the same type. Match
			// each field pairwise and only report a diff if there is a mismatch,
			// which is only when both sides are non-nil and have differring values.
			diff := diffLayer((*ls)[i], other[i])
			var layerDiffRows []layerDiffRow
			for _, d := range diff {
				if d.got == "" || d.want == "" || d.got == d.want {
					continue
				}
				layerDiffRows = append(layerDiffRows, layerDiffRow{
					d.field,
					d.got,
					d.want,
				})
			}
			if len(layerDiffRows) > 0 {
				allDiffs = append(allDiffs, layerDiff{
					label: layerType((*ls)[i]),
					rows:  layerDiffRows,
				})
			} else {
				allDiffs = append(allDiffs, layerDiff{
					label: layerType((*ls)[i]) + " matches " + layerType(other[i]),
					// Having no rows is a sign that there was no diff.
				})
			}
			continue
		}
		// Neither side is nil and the types are different, so we'll display one
		// side then the other.
		allDiffs = append(allDiffs, layerDiff{
			label: layerType((*ls)[i]) + " doesn't match " + layerType(other[i]),
		})
		diff := diffLayer((*ls)[i], (*ls)[i])
		layerDiffRows := []layerDiffRow{}
		for _, d := range diff {
			if len(d.got) == 0 {
				continue
			}
			layerDiffRows = append(layerDiffRows, layerDiffRow{
				d.field,
				d.got,
				"",
			})
		}
		allDiffs = append(allDiffs, layerDiff{
			label: layerType((*ls)[i]),
			rows:  layerDiffRows,
		})

		layerDiffRows = []layerDiffRow{}
		diff = diffLayer(other[i], other[i])
		for _, d := range diff {
			if len(d.want) == 0 {
				continue
			}
			layerDiffRows = append(layerDiffRows, layerDiffRow{
				d.field,
				"",
				d.want,
			})
		}
		allDiffs = append(allDiffs, layerDiff{
			label: layerType(other[i]),
			rows:  layerDiffRows,
		})
	}

	output := ""
	// These are for output formatting.
	maxLabelLen, maxFieldLen, maxGotLen, maxWantLen := 0, 0, 0, 0
	foundOne := false
	for _, l := range allDiffs {
		if len(l.label) > maxLabelLen && len(l.rows) > 0 {
			maxLabelLen = len(l.label)
		}
		if l.rows != nil {
			foundOne = true
		}
		for _, r := range l.rows {
			if len(r.field) > maxFieldLen {
				maxFieldLen = len(r.field)
			}
			if l := len(fmt.Sprint(r.got)); l > maxGotLen {
				maxGotLen = l
			}
			if l := len(fmt.Sprint(r.want)); l > maxWantLen {
				maxWantLen = l
			}
		}
	}
	if !foundOne {
		return ""
	}
	for _, l := range allDiffs {
		if len(l.rows) == 0 {
			output += "(" + l.label + ")\n"
			continue
		}
		for i, r := range l.rows {
			var label string
			if i == 0 {
				label = l.label + ":"
			}
			output += fmt.Sprintf(
				"%*s %*s %*v %*v\n",
				maxLabelLen+1, label,
				maxFieldLen+1, r.field+":",
				maxGotLen, r.got,
				maxWantLen, r.want,
			)
		}
	}
	return output
}

// merge merges the other Layers into ls. If the other Layers is longer, those
// additional Layer structs are added to ls. The errors from merging are
// collected and returned.
func (ls *Layers) merge(other Layers) error {
	var errs error
	for i, o := range other {
		if i < len(*ls) {
			errs = multierr.Combine(errs, (*ls)[i].merge(o))
		} else {
			*ls = append(*ls, o)
		}
	}
	return errs
}
