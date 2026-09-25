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
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestMasqueradeTargetMakerRoundTrip(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol tcpip.NetworkProtocolNumber
		filter   stack.IPHeaderFilter
		size     int
	}{
		{name: "ipv4 legacy layout", protocol: header.IPv4ProtocolNumber, filter: emptyIPv4Filter, size: linux.SizeOfXTNATTargetV0},
		{name: "ipv4 extended layout", protocol: header.IPv4ProtocolNumber, filter: emptyIPv4Filter, size: linux.SizeOfXTNATTargetV2},
		{name: "ipv6 legacy layout", protocol: header.IPv6ProtocolNumber, filter: emptyIPv6Filter, size: linux.SizeOfXTNATTargetV0},
		{name: "ipv6 extended layout", protocol: header.IPv6ProtocolNumber, filter: emptyIPv6Filter, size: linux.SizeOfXTNATTargetV2},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := make([]byte, test.size)
			for i := range raw {
				raw[i] = byte(i + 1)
			}
			maker := masqueradeTargetMaker{
				NetworkProtocol: test.protocol,
			}
			target, err := maker.unmarshal(raw, test.filter)
			if err != nil {
				t.Fatalf("unmarshal() failed: %v", err)
			}
			got, ok := target.(*masqueradeTarget)
			if !ok {
				t.Fatalf("unmarshal() returned %T, want *masqueradeTarget", target)
			}
			if got.NetworkProtocol != test.protocol {
				t.Fatalf("target protocol = %d, want %d", got.NetworkProtocol, test.protocol)
			}

			want := append([]byte(nil), raw...)
			raw[0] ^= 0xff
			if marshalled := maker.marshal(got); !bytes.Equal(marshalled, want) {
				t.Fatalf("marshal() = %v, want exact original bytes %v", marshalled, want)
			}
		})
	}
}

func TestMasqueradeTargetMakerRejectsShortBuffer(t *testing.T) {
	maker := masqueradeTargetMaker{NetworkProtocol: header.IPv4ProtocolNumber}
	if _, err := maker.unmarshal(make([]byte, linux.SizeOfXTEntryTarget-1), emptyIPv4Filter); err != syserr.ErrInvalidArgument {
		t.Fatalf("unmarshal() error = %v, want %v", err, syserr.ErrInvalidArgument)
	}
}

func TestMasqueradeTargetMakerFallbackLayout(t *testing.T) {
	maker := masqueradeTargetMaker{NetworkProtocol: header.IPv4ProtocolNumber}
	target := &masqueradeTarget{MasqueradeTarget: stack.MasqueradeTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	got := maker.marshal(target)
	if len(got) != linux.SizeOfXTNATTargetV0 {
		t.Fatalf("marshal() size = %d, want %d", len(got), linux.SizeOfXTNATTargetV0)
	}
	var xt linux.XTNATTargetV0
	xt.UnmarshalUnsafe(got)
	if xt.Target.Name.String() != MasqueradeTargetName {
		t.Fatalf("target name = %q, want %q", xt.Target.Name.String(), MasqueradeTargetName)
	}
	if xt.Target.TargetSize != linux.SizeOfXTNATTargetV0 {
		t.Fatalf("target size = %d, want %d", xt.Target.TargetSize, linux.SizeOfXTNATTargetV0)
	}
	if xt.NfRange.RangeSize != 1 {
		t.Fatalf("range size = %d, want 1", xt.NfRange.RangeSize)
	}
}
