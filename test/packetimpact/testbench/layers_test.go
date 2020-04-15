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
