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
	"testing"

	"github.com/mohae/deepcopy"
	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestLayerMatch(t *testing.T) {
	var nilPayload *Payload
	noPayload := &Payload{}
	emptyPayload := &Payload{Bytes: []byte{}}
	fullPayload := &Payload{Bytes: []byte{1, 2, 3}}
	emptyTCP := &TCP{SrcPort: Uint16(1234), LayerBase: LayerBase{nextLayer: emptyPayload}}
	fullTCP := &TCP{SrcPort: Uint16(1234), LayerBase: LayerBase{nextLayer: fullPayload}}
	for _, tt := range []struct {
		a, b Layer
		want bool
	}{
		{nilPayload, nilPayload, true},
		{nilPayload, noPayload, true},
		{nilPayload, emptyPayload, true},
		{nilPayload, fullPayload, true},
		{noPayload, noPayload, true},
		{noPayload, emptyPayload, true},
		{noPayload, fullPayload, true},
		{emptyPayload, emptyPayload, true},
		{emptyPayload, fullPayload, false},
		{fullPayload, fullPayload, true},
		{emptyTCP, fullTCP, true},
	} {
		if got := tt.a.match(tt.b); got != tt.want {
			t.Errorf("%s.match(%s) = %t, want %t", tt.a, tt.b, got, tt.want)
		}
		if got := tt.b.match(tt.a); got != tt.want {
			t.Errorf("%s.match(%s) = %t, want %t", tt.b, tt.a, got, tt.want)
		}
	}
}

func TestLayerMergeMismatch(t *testing.T) {
	tcp := &TCP{}
	otherTCP := &TCP{}
	ipv4 := &IPv4{}
	ether := &Ether{}
	for _, tt := range []struct {
		a, b    Layer
		success bool
	}{
		{tcp, tcp, true},
		{tcp, otherTCP, true},
		{tcp, ipv4, false},
		{tcp, ether, false},
		{tcp, nil, true},

		{otherTCP, otherTCP, true},
		{otherTCP, ipv4, false},
		{otherTCP, ether, false},
		{otherTCP, nil, true},

		{ipv4, ipv4, true},
		{ipv4, ether, false},
		{ipv4, nil, true},

		{ether, ether, true},
		{ether, nil, true},
	} {
		if err := tt.a.merge(tt.b); (err == nil) != tt.success {
			t.Errorf("%s.merge(%s) got %s, wanted the opposite", tt.a, tt.b, err)
		}
		if tt.b != nil {
			if err := tt.b.merge(tt.a); (err == nil) != tt.success {
				t.Errorf("%s.merge(%s) got %s, wanted the opposite", tt.b, tt.a, err)
			}
		}
	}
}

func TestLayerMerge(t *testing.T) {
	zero := Uint32(0)
	one := Uint32(1)
	two := Uint32(2)
	empty := []byte{}
	foo := []byte("foo")
	bar := []byte("bar")
	for _, tt := range []struct {
		a, b Layer
		want Layer
	}{
		{&TCP{AckNum: nil}, &TCP{AckNum: nil}, &TCP{AckNum: nil}},
		{&TCP{AckNum: nil}, &TCP{AckNum: zero}, &TCP{AckNum: zero}},
		{&TCP{AckNum: nil}, &TCP{AckNum: one}, &TCP{AckNum: one}},
		{&TCP{AckNum: nil}, &TCP{AckNum: two}, &TCP{AckNum: two}},
		{&TCP{AckNum: nil}, nil, &TCP{AckNum: nil}},

		{&TCP{AckNum: zero}, &TCP{AckNum: nil}, &TCP{AckNum: zero}},
		{&TCP{AckNum: zero}, &TCP{AckNum: zero}, &TCP{AckNum: zero}},
		{&TCP{AckNum: zero}, &TCP{AckNum: one}, &TCP{AckNum: one}},
		{&TCP{AckNum: zero}, &TCP{AckNum: two}, &TCP{AckNum: two}},
		{&TCP{AckNum: zero}, nil, &TCP{AckNum: zero}},

		{&TCP{AckNum: one}, &TCP{AckNum: nil}, &TCP{AckNum: one}},
		{&TCP{AckNum: one}, &TCP{AckNum: zero}, &TCP{AckNum: zero}},
		{&TCP{AckNum: one}, &TCP{AckNum: one}, &TCP{AckNum: one}},
		{&TCP{AckNum: one}, &TCP{AckNum: two}, &TCP{AckNum: two}},
		{&TCP{AckNum: one}, nil, &TCP{AckNum: one}},

		{&TCP{AckNum: two}, &TCP{AckNum: nil}, &TCP{AckNum: two}},
		{&TCP{AckNum: two}, &TCP{AckNum: zero}, &TCP{AckNum: zero}},
		{&TCP{AckNum: two}, &TCP{AckNum: one}, &TCP{AckNum: one}},
		{&TCP{AckNum: two}, &TCP{AckNum: two}, &TCP{AckNum: two}},
		{&TCP{AckNum: two}, nil, &TCP{AckNum: two}},

		{&Payload{Bytes: nil}, &Payload{Bytes: nil}, &Payload{Bytes: nil}},
		{&Payload{Bytes: nil}, &Payload{Bytes: empty}, &Payload{Bytes: empty}},
		{&Payload{Bytes: nil}, &Payload{Bytes: foo}, &Payload{Bytes: foo}},
		{&Payload{Bytes: nil}, &Payload{Bytes: bar}, &Payload{Bytes: bar}},
		{&Payload{Bytes: nil}, nil, &Payload{Bytes: nil}},

		{&Payload{Bytes: empty}, &Payload{Bytes: nil}, &Payload{Bytes: empty}},
		{&Payload{Bytes: empty}, &Payload{Bytes: empty}, &Payload{Bytes: empty}},
		{&Payload{Bytes: empty}, &Payload{Bytes: foo}, &Payload{Bytes: foo}},
		{&Payload{Bytes: empty}, &Payload{Bytes: bar}, &Payload{Bytes: bar}},
		{&Payload{Bytes: empty}, nil, &Payload{Bytes: empty}},

		{&Payload{Bytes: foo}, &Payload{Bytes: nil}, &Payload{Bytes: foo}},
		{&Payload{Bytes: foo}, &Payload{Bytes: empty}, &Payload{Bytes: empty}},
		{&Payload{Bytes: foo}, &Payload{Bytes: foo}, &Payload{Bytes: foo}},
		{&Payload{Bytes: foo}, &Payload{Bytes: bar}, &Payload{Bytes: bar}},
		{&Payload{Bytes: foo}, nil, &Payload{Bytes: foo}},

		{&Payload{Bytes: bar}, &Payload{Bytes: nil}, &Payload{Bytes: bar}},
		{&Payload{Bytes: bar}, &Payload{Bytes: empty}, &Payload{Bytes: empty}},
		{&Payload{Bytes: bar}, &Payload{Bytes: foo}, &Payload{Bytes: foo}},
		{&Payload{Bytes: bar}, &Payload{Bytes: bar}, &Payload{Bytes: bar}},
		{&Payload{Bytes: bar}, nil, &Payload{Bytes: bar}},
	} {
		a := deepcopy.Copy(tt.a).(Layer)
		if err := a.merge(tt.b); err != nil {
			t.Errorf("%s.merge(%s) = %s, wanted nil", tt.a, tt.b, err)
			continue
		}
		if a.String() != tt.want.String() {
			t.Errorf("%s.merge(%s) merge result got %s, want %s", tt.a, tt.b, a, tt.want)
		}
	}
}

func TestLayerStringFormat(t *testing.T) {
	for _, tt := range []struct {
		name string
		l    Layer
		want string
	}{
		{
			name: "TCP",
			l: &TCP{
				SrcPort:    Uint16(34785),
				DstPort:    Uint16(47767),
				SeqNum:     Uint32(3452155723),
				AckNum:     Uint32(2596996163),
				DataOffset: Uint8(5),
				Flags:      Uint8(20),
				WindowSize: Uint16(64240),
				Checksum:   Uint16(0x2e2b),
			},
			want: "&testbench.TCP{" +
				"SrcPort:34785 " +
				"DstPort:47767 " +
				"SeqNum:3452155723 " +
				"AckNum:2596996163 " +
				"DataOffset:5 " +
				"Flags:20 " +
				"WindowSize:64240 " +
				"Checksum:11819" +
				"}",
		},
		{
			name: "UDP",
			l: &UDP{
				SrcPort: Uint16(34785),
				DstPort: Uint16(47767),
				Length:  Uint16(12),
			},
			want: "&testbench.UDP{" +
				"SrcPort:34785 " +
				"DstPort:47767 " +
				"Length:12" +
				"}",
		},
		{
			name: "IPv4",
			l: &IPv4{
				IHL:            Uint8(5),
				TOS:            Uint8(0),
				TotalLength:    Uint16(44),
				ID:             Uint16(0),
				Flags:          Uint8(2),
				FragmentOffset: Uint16(0),
				TTL:            Uint8(64),
				Protocol:       Uint8(6),
				Checksum:       Uint16(0x2e2b),
				SrcAddr:        Address(tcpip.Address([]byte{197, 34, 63, 10})),
				DstAddr:        Address(tcpip.Address([]byte{197, 34, 63, 20})),
			},
			want: "&testbench.IPv4{" +
				"IHL:5 " +
				"TOS:0 " +
				"TotalLength:44 " +
				"ID:0 " +
				"Flags:2 " +
				"FragmentOffset:0 " +
				"TTL:64 " +
				"Protocol:6 " +
				"Checksum:11819 " +
				"SrcAddr:197.34.63.10 " +
				"DstAddr:197.34.63.20" +
				"}",
		},
		{
			name: "Ether",
			l: &Ether{
				SrcAddr: LinkAddress(tcpip.LinkAddress([]byte{0x02, 0x42, 0xc5, 0x22, 0x3f, 0x0a})),
				DstAddr: LinkAddress(tcpip.LinkAddress([]byte{0x02, 0x42, 0xc5, 0x22, 0x3f, 0x14})),
				Type:    NetworkProtocolNumber(4),
			},
			want: "&testbench.Ether{" +
				"SrcAddr:02:42:c5:22:3f:0a " +
				"DstAddr:02:42:c5:22:3f:14 " +
				"Type:4" +
				"}",
		},
		{
			name: "Payload",
			l: &Payload{
				Bytes: []byte("Hooray for packetimpact."),
			},
			want: "&testbench.Payload{Bytes:\n" +
				"00000000  48 6f 6f 72 61 79 20 66  6f 72 20 70 61 63 6b 65  |Hooray for packe|\n" +
				"00000010  74 69 6d 70 61 63 74 2e                           |timpact.|\n" +
				"}",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.String(); got != tt.want {
				t.Errorf("%s.String() = %s, want: %s", tt.name, got, tt.want)
			}
		})
	}
}

func TestConnectionMatch(t *testing.T) {
	conn := Connection{
		layerStates: []layerState{&etherState{}},
	}
	protoNum0 := tcpip.NetworkProtocolNumber(0)
	protoNum1 := tcpip.NetworkProtocolNumber(1)
	for _, tt := range []struct {
		description        string
		override, received Layers
		wantMatch          bool
	}{
		{
			description: "shorter override",
			override:    []Layer{&Ether{}},
			received:    []Layer{&Ether{}, &Payload{Bytes: []byte("hello")}},
			wantMatch:   true,
		},
		{
			description: "longer override",
			override:    []Layer{&Ether{}, &Payload{Bytes: []byte("hello")}},
			received:    []Layer{&Ether{}},
			wantMatch:   false,
		},
		{
			description: "ether layer mismatch",
			override:    []Layer{&Ether{Type: &protoNum0}},
			received:    []Layer{&Ether{Type: &protoNum1}},
			wantMatch:   false,
		},
		{
			description: "both nil",
			override:    nil,
			received:    nil,
			wantMatch:   false,
		},
		{
			description: "nil override",
			override:    nil,
			received:    []Layer{&Ether{}},
			wantMatch:   true,
		},
	} {
		t.Run(tt.description, func(t *testing.T) {
			if gotMatch := conn.match(tt.override, tt.received); gotMatch != tt.wantMatch {
				t.Fatalf("conn.match(%s, %s) = %t, want %t", tt.override, tt.received, gotMatch, tt.wantMatch)
			}
		})
	}
}
