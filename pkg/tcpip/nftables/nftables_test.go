// Copyright 2024 The gVisor Authors.
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

package nftables

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// makeTestingPacket creates an arbitrary packet for testing.
func makeTestingPacket() *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: 50,
		Payload:            buffer.MakeWithData([]byte{0, 2, 4, 8, 16, 32, 64, 128}),
	})
}

// TestUnsupportedAddressFamily tests that an empty NFTables object returns an
// error when evaluating a packet for an unsupported address family.
func TestUnsupportedAddressFamily(t *testing.T) {
	nf := NewNFTables()
	for _, unsupportedFamily := range []AddressFamily{AddressFamily(NumAFs), AddressFamily(-1)} {
		// Note: the Prerouting hook is arbitrary (any hook would work).
		pkt := makeTestingPacket()
		v, finalPkt, err := nf.EvaluateHook(unsupportedFamily, Prerouting, pkt)
		if err == nil {
			t.Fatalf("expecting error for EvaluateHook with unsupported address family %d; got %s verdict, %s packet, and error %v",
				int(unsupportedFamily),
				v.String(), packetResultString(pkt, finalPkt), err)
		}
	}
}

// TestAcceptAll tests that an empty NFTables object accepts all packets for
// supported hooks and errors for unsupported hooks for all address families
// when evaluating packets at the hook-level.
func TestAcceptAllForSupportedHooks(t *testing.T) {
	for _, family := range []AddressFamily{IP, IP6, Inet, Arp, Bridge, Netdev} {
		t.Run(family.String()+" address family", func(t *testing.T) {
			nf := NewNFTables()
			for _, hook := range []Hook{Prerouting, Input, Forward, Output, Postrouting, Ingress, Egress} {
				pkt := makeTestingPacket()
				v, finalPkt, err := nf.EvaluateHook(family, hook, pkt)

				supported := false
				for _, h := range supportedHooks[family] {
					if h == hook {
						supported = true
						break
					}
				}

				if supported {
					if err != nil || v.Code != VC(linux.NF_ACCEPT) {
						t.Fatalf("expecting accept verdict for EvaluateHook with supported hook %s for family %s; got %s verdict, %s packet, and error %v",
							hook.String(), family.String(),
							v.String(), packetResultString(pkt, finalPkt), err)
					}
				} else {
					if err == nil {
						t.Fatalf("expecting error for EvaluateHook with unsupported hook %s for family %s; got %s verdict, %s packet, and error %v",
							hook.String(), family.String(),
							v.String(), packetResultString(pkt, finalPkt), err)
					}
				}
			}
		})
	}
}

// packetResultString compares 2 packets by equality and returns a string
// representation.
func packetResultString(initial, final *stack.PacketBuffer) string {
	if final == nil {
		return "nil"
	}
	if reflect.DeepEqual(final, initial) {
		return "unmodified"
	}
	return "modified"
}
