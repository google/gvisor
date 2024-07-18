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
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// An arbitrary packet for testing
var pkt *stack.PacketBuffer = stack.NewPacketBuffer(stack.PacketBufferOptions{
	ReserveHeaderBytes: 50,
	Payload:            buffer.MakeWithData([]byte{0, 2, 4, 8, 16, 32, 64, 128}),
})

// TestUnsupportedAddressFamily tests that an empty NFTables object returns an
// error when evaluating a packet for an unsupported address family.
func TestUnsupportedAddressFamily(t *testing.T) {
	nf := NewNFTables()
	for _, unsupportedFamily := range []AddressFamily{AddressFamily(NumAFs), AddressFamily(-1)} {
		// Note: the Prerouting hook is arbitrary (any hook would work).
		v, finalPkt, err := nf.EvaluateHook(unsupportedFamily, Prerouting, pkt)
		if v != NftDrop || finalPkt != nil || err == nil {
			t.Fatalf("got EvaluateHook(unsupported address family %d, %s, packet) = (%s, %s, %v); want (%s, %s, %s)",
				int(unsupportedFamily), Prerouting.String(),
				v.String(), packetResultString(finalPkt, pkt), err,
				NftDrop.String(), "nilPacket", fmt.Sprintf("Invalid address family: %d", int(unsupportedFamily)))
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
				v, finalPkt, err := nf.EvaluateHook(family, hook, pkt)

				supported := false
				for _, h := range supportedHooks[family] {
					if h == hook {
						supported = true
						break
					}
				}

				if supported {
					if v != NftAccept || finalPkt != pkt || err != nil {
						// Should be supported and accept all but an error was returned.
						t.Fatalf("got EvaluateHook(%s, %s, packet) = (%s, %s, %v); want (%s, %s, %s)",
							family.String(), hook.String(),
							v.String(), packetResultString(finalPkt, pkt), err,
							NftAccept.String(), "samePacket", "noError")
					}
				} else {
					if v != NftDrop || finalPkt != nil || err == nil {
						// Should return an error but the packet was accepted.
						t.Fatalf("got EvaluateHook(%s, %s, packet) = (%s, %s, %v); want (%s, %s, hook %s is not valid for address family %s)",
							family.String(), hook.String(),
							v.String(), packetResultString(finalPkt, pkt), err,
							NftDrop.String(), "nilPacket", hook.String(), family.String())
					}
				}
			}
		})
	}
}

// packetResultString compares 2 packets by equality and returns a string
// representation.
func packetResultString(final, initial *stack.PacketBuffer) string {
	// TODO(b/345684870): Compare packet contents instead of pointers.
	switch final {
	case nil:
		return "nilPacket"
	case initial:
		return "samePacket"
	default:
		return "differentPacket"
	}
}
