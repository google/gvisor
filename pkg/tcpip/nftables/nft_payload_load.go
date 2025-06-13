// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// payloadLoad is an operation that loads data from the packet payload into a
// register.
// Note: payload operations are not supported for the verdict register.
type payloadLoad struct {
	base   payloadBase // Payload base to access data from.
	offset uint8       // Number of bytes to skip after the base.
	blen   uint8       // Number of bytes to load.
	dreg   uint8       // Number of the destination register.
}

// payloadBase is the header that determines the location of the packet data.
// Note: corresponds to enum nft_payload_bases from
// include/uapi/linux/netfilter/nf_tables.h and uses the same constants.
type payloadBase int

// payloadBaseStrings is a map of payloadBase to its string representation.
var payloadBaseStrings = map[payloadBase]string{
	linux.NFT_PAYLOAD_LL_HEADER:        "Link Layer Header",
	linux.NFT_PAYLOAD_NETWORK_HEADER:   "Network Header",
	linux.NFT_PAYLOAD_TRANSPORT_HEADER: "Transport Header",
	linux.NFT_PAYLOAD_INNER_HEADER:     "Inner Header",
	linux.NFT_PAYLOAD_TUN_HEADER:       "Tunneling Header",
}

// String for payloadBase returns the string representation of the payload base.
func (base payloadBase) String() string {
	if baseStr, ok := payloadBaseStrings[base]; ok {
		return baseStr
	}
	panic(fmt.Sprintf("Invalid Payload Base: %d", int(base)))
}

// validatePayloadBase ensures the payload base is valid.
func validatePayloadBase(base payloadBase) error {
	switch base {
	// Supported payload bases.
	case linux.NFT_PAYLOAD_LL_HEADER, linux.NFT_PAYLOAD_NETWORK_HEADER, linux.NFT_PAYLOAD_TRANSPORT_HEADER:
		return nil
	// Unsupported payload bases.
	default:
		return fmt.Errorf("invalid payload base: %d", int(base))
	}
}

// getPayloadBuffer gets the data from the packet payload starting from the
// the beginning of the specified base header.
// Returns nil if the payload is not present or invalid.
func getPayloadBuffer(pkt *stack.PacketBuffer, base payloadBase) []byte {
	switch base {
	case linux.NFT_PAYLOAD_LL_HEADER:
		// Note: Assumes Mac Header is present and valid for necessary use cases.
		// Also, doesn't check VLAN tag because VLAN isn't supported by gVisor.
		return pkt.LinkHeader().Slice()
	case linux.NFT_PAYLOAD_NETWORK_HEADER:
		// No checks done in linux kernel.
		return pkt.NetworkHeader().Slice()
	case linux.NFT_PAYLOAD_TRANSPORT_HEADER:
		// Note: Assumes L4 protocol is present and valid for necessary use cases.

		// Errors if the packet is fragmented for IPv4 only.
		if net := pkt.NetworkHeader().Slice(); len(net) > 0 && pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			if h := header.IPv4(net); h.More() || h.FragmentOffset() != 0 {
				break // packet is fragmented
			}
		}
		return pkt.TransportHeader().Slice()
	}
	return nil
}

// newPayloadLoad creates a new payloadLoad operation.
func newPayloadLoad(base payloadBase, offset, blen, dreg uint8) (*payloadLoad, error) {
	if isVerdictRegister(dreg) {
		return nil, fmt.Errorf("payload load operation cannot use verdict register as destination")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && is4ByteRegister(dreg)) {
		return nil, fmt.Errorf("payload length %d is too long for destination register %d", blen, dreg)
	}
	if err := validatePayloadBase(base); err != nil {
		return nil, err
	}
	return &payloadLoad{base: base, offset: offset, blen: blen, dreg: dreg}, nil
}

// evaluate for PayloadLoad loads data from the packet payload into the
// destination register.
func (op payloadLoad) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the packet payload.
	payload := getPayloadBuffer(pkt, op.base)

	// Breaks if could not retrieve packet data.
	if payload == nil || len(payload) < int(op.offset+op.blen) {
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Copies payload data into the specified register.
	data := newBytesData(payload[op.offset : op.offset+op.blen])
	data.storeData(regs, op.dreg)
}
