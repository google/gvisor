// Copyright 2026 The gVisor Authors.
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

package netfilter

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// masqueradeV4 returns an IPv4 MASQUERADE target as iptables builds it.
func masqueradeV4(flags uint32, minPort, maxPort uint16) linux.XTNATTargetV0 {
	xt := linux.XTNATTargetV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV0,
		},
	}
	copy(xt.Target.Name[:], MasqueradeTargetName)
	xt.NfRange.RangeSize = 1
	xt.NfRange.RangeIPV4.Flags = flags
	xt.NfRange.RangeIPV4.MinPort = htons(minPort)
	xt.NfRange.RangeIPV4.MaxPort = htons(maxPort)
	return xt
}

// masqueradeV6 returns an IPv6 MASQUERADE target as ip6tables builds it.
func masqueradeV6(flags uint32, minPort, maxPort uint16) linux.XTNATTargetV1 {
	xt := linux.XTNATTargetV1{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTNATTargetV1,
		},
		Range: linux.NFNATRange{
			Flags:    flags,
			MinProto: htons(minPort),
			MaxProto: htons(maxPort),
		},
	}
	copy(xt.Target.Name[:], MasqueradeTargetName)
	return xt
}

func masqueradeFilter(netProto tcpip.NetworkProtocolNumber) stack.IPHeaderFilter {
	if netProto == header.IPv6ProtocolNumber {
		return emptyIPv6Filter
	}
	return emptyIPv4Filter
}

func TestMasqueradeTargetMakerUnmarshal(t *testing.T) {
	for _, test := range []struct {
		name      string
		netProto  tcpip.NetworkProtocolNumber
		buf       []byte
		wantPorts stack.PortOrIdentRange
	}{
		{
			name:     "ipv4",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(0, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 random-fully",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(linux.NF_NAT_RANGE_PROTO_RANDOM_FULLY, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 to-ports",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5000, 5009)
				return marshal.Marshal(&xt)
			}(),
			wantPorts: stack.PortOrIdentRange{Start: 5000, Size: 10},
		},
		{
			name:     "ipv6",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(0, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv6 random-fully",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(linux.NF_NAT_RANGE_PROTO_RANDOM_FULLY, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv6 to-ports",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5000, 5000)
				return marshal.Marshal(&xt)
			}(),
			wantPorts: stack.PortOrIdentRange{Start: 5000, Size: 1},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			maker := masqueradeTargetMaker{NetworkProtocol: test.netProto}
			target, err := maker.unmarshal(test.buf, masqueradeFilter(test.netProto))
			if err != nil {
				t.Fatalf("unmarshal() failed: %v", err)
			}
			got := target.(*masqueradeTarget)
			if got.NetworkProtocol != test.netProto {
				t.Errorf("NetworkProtocol = %d, want %d", got.NetworkProtocol, test.netProto)
			}
			if got.Ports != test.wantPorts {
				t.Errorf("Ports = %+v, want %+v", got.Ports, test.wantPorts)
			}
			if marshalled := maker.marshal(got); !bytes.Equal(marshalled, test.buf) {
				t.Errorf("marshal() = %v, want %v", marshalled, test.buf)
			}
		})
	}
}

func TestMasqueradeTargetMakerUnmarshalInvalid(t *testing.T) {
	for _, test := range []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		buf      []byte
	}{
		{
			name:     "ipv4 short",
			netProto: header.IPv4ProtocolNumber,
			buf:      make([]byte, linux.SizeOfXTNATTargetV0-1),
		},
		{
			name:     "ipv4 with ipv6 layout",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(0, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 rangesize 0",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(0, 0, 0)
				xt.NfRange.RangeSize = 0
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 rangesize 2",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(0, 0, 0)
				xt.NfRange.RangeSize = 2
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 map-ips",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(linux.NF_NAT_RANGE_MAP_IPS, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv4 inverted port range",
			netProto: header.IPv4ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5009, 5000)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv6 with ipv4 layout",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV4(0, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv6 long",
			netProto: header.IPv6ProtocolNumber,
			buf:      make([]byte, linux.SizeOfXTNATTargetV1+8),
		},
		{
			name:     "ipv6 map-ips",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(linux.NF_NAT_RANGE_MAP_IPS, 0, 0)
				return marshal.Marshal(&xt)
			}(),
		},
		{
			name:     "ipv6 inverted port range",
			netProto: header.IPv6ProtocolNumber,
			buf: func() []byte {
				xt := masqueradeV6(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5009, 5000)
				return marshal.Marshal(&xt)
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			maker := masqueradeTargetMaker{NetworkProtocol: test.netProto}
			if _, err := maker.unmarshal(test.buf, masqueradeFilter(test.netProto)); err != syserr.ErrInvalidArgument {
				t.Errorf("unmarshal() error = %v, want %v", err, syserr.ErrInvalidArgument)
			}
		})
	}
}

func TestMasqueradeTargetMakerMarshalWithoutRaw(t *testing.T) {
	for _, test := range []struct {
		name     string
		netProto tcpip.NetworkProtocolNumber
		ports    stack.PortOrIdentRange
		want     marshal.Marshallable
	}{
		{
			name:     "ipv4",
			netProto: header.IPv4ProtocolNumber,
			want:     func() marshal.Marshallable { xt := masqueradeV4(0, 0, 0); return &xt }(),
		},
		{
			name:     "ipv4 to-ports",
			netProto: header.IPv4ProtocolNumber,
			ports:    stack.PortOrIdentRange{Start: 5000, Size: 10},
			want: func() marshal.Marshallable {
				xt := masqueradeV4(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5000, 5009)
				return &xt
			}(),
		},
		{
			name:     "ipv6",
			netProto: header.IPv6ProtocolNumber,
			want:     func() marshal.Marshallable { xt := masqueradeV6(0, 0, 0); return &xt }(),
		},
		{
			name:     "ipv6 to-ports",
			netProto: header.IPv6ProtocolNumber,
			ports:    stack.PortOrIdentRange{Start: 5000, Size: 10},
			want: func() marshal.Marshallable {
				xt := masqueradeV6(linux.NF_NAT_RANGE_PROTO_SPECIFIED, 5000, 5009)
				return &xt
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			maker := masqueradeTargetMaker{NetworkProtocol: test.netProto}
			target := &masqueradeTarget{MasqueradeTarget: stack.MasqueradeTarget{
				NetworkProtocol: test.netProto,
				Ports:           test.ports,
			}}
			if got, want := maker.marshal(target), marshal.Marshal(test.want); !bytes.Equal(got, want) {
				t.Errorf("marshal() = %v, want %v", got, want)
			}
		})
	}
}
