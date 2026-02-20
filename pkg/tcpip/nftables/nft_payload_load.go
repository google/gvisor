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
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
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
func newPayloadLoad(base payloadBase, offset, blen, dreg uint8) (*payloadLoad, *syserr.AnnotatedError) {
	if isVerdictRegister(dreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "payload load operation does not support verdict register as destination register")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && is4ByteRegister(dreg)) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("payload size %d is not supported for register %d", blen, dreg))
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

// Initialize based on net/netfilter/nft_payload.c nft_payload_init.
func initPayloadLoad(tab *Table, attrs map[uint16]nlmsg.BytesView) (*payloadLoad, *syserr.AnnotatedError) {
	base, ok := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_BASE, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_PAYLOAD_BASE attribute value")
	}
	offset, ok := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_OFFSET, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_PAYLOAD_OFFSET attribute value")
	}
	blen, ok := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_LEN, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_PAYLOAD_LEN attribute value")
	}
	dreg, ok := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_DREG, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_PAYLOAD_DREG attribute value")
	}
	return newPayloadLoad(payloadBase(base), uint8(offset), uint8(blen), uint8(dreg))
}

func (op payloadLoad) GetExprName() string {
	return "payload"
}

func (op payloadLoad) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_PAYLOAD_DREG, nlmsg.PutU32(uint32(op.dreg)))
	m.PutAttr(linux.NFTA_PAYLOAD_BASE, nlmsg.PutU32(uint32(op.base)))
	m.PutAttr(linux.NFTA_PAYLOAD_OFFSET, nlmsg.PutU32(uint32(op.offset)))
	m.PutAttr(linux.NFTA_PAYLOAD_LEN, nlmsg.PutU32(uint32(op.blen)))
	return m.Buffer(), nil
}
