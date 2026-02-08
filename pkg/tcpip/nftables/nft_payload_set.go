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
	"encoding/binary"
	"fmt"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// payloadSet is an operation that sets data in the packet payload to the value
// in a register.
// Note: payload operations are not supported for the verdict register.
type payloadSet struct {
	base       payloadBase // Payload base to access data from.
	offset     uint8       // Number of bytes to skip after the base for data.
	blen       uint8       // Number of bytes to load.
	sreg       uint8       // Number of the source register.
	csumType   uint8       // Type of checksum to use.
	csumOffset uint8       // Number of bytes to skip after the base for checksum.
	csumFlags  uint8       // Flags for checksum.

	// Note: the only flag defined for csumFlags is NFT_PAYLOAD_L4CSUM_PSEUDOHDR.
	// This flag is used to update L4 checksums whenever there has been a change
	// to a field that is part of the pseudo-header for the L4 checksum, not when
	// data within the L4 header is changed (instead setting csumType to
	// NFT_PAYLOAD_CSUM_INET suffices for that case).

	// For example, if any part of the L4 header is changed, csumType is set to
	// NFT_PAYLOAD_CSUM_INET and no flag is set for csumFlags since we only need
	// to update the checksum of the header specified by the payload base.
	// On the other hand, if data in the L3 header is changed that is part of
	// the pseudo-header for the L4 checksum (like saddr/daddr), csumType is set
	// to NFT_PAYLOAD_CSUM_INET and csumFlags to NFT_PAYLOAD_L4CSUM_PSEUDOHDR
	// because in addition to updating the checksum for the header specified by
	// the payload base, we need to separately locate and update the L4 checksum.
}

// validateChecksumType ensures the checksum type is valid.
func validateChecksumType(csumType uint8) *syserr.AnnotatedError {
	switch csumType {
	case linux.NFT_PAYLOAD_CSUM_NONE:
		return nil
	case linux.NFT_PAYLOAD_CSUM_INET:
		return nil
	case linux.NFT_PAYLOAD_CSUM_SCTP:
		return syserr.NewAnnotatedError(syserr.ErrNotSupported, "sctp checksum type not supported")
	default:
		return syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid checksum type: %d", int(csumType)))
	}
}

// newPayloadSet creates a new payloadSet operation.
func newPayloadSet(base payloadBase, offset, blen, sreg, csumType, csumOffset, csumFlags uint8) (*payloadSet, *syserr.AnnotatedError) {
	if isVerdictRegister(sreg) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "payload set operation does not support verdict register as source register")
	}
	if blen > linux.NFT_REG_SIZE || (blen > linux.NFT_REG32_SIZE && is4ByteRegister(sreg)) {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("payload size %d is not supported for register %d", blen, sreg))
	}
	if err := validatePayloadBase(base); err != nil {
		return nil, err
	}
	if err := validateChecksumType(csumType); err != nil {
		return nil, err
	}
	if csumFlags&^linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, fmt.Sprintf("invalid checksum flags: %d", csumFlags))
	}
	return &payloadSet{base: base, offset: offset, blen: blen, sreg: sreg,
		csumType: csumType, csumOffset: csumOffset, csumFlags: csumFlags}, nil
}

// evaluate for PayloadSet sets data in the packet payload to the value in the
// source register.
func (op payloadSet) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	// Gets the packet payload.
	payload := getPayloadBuffer(pkt, op.base)

	// Breaks if could not retrieve packet data.
	if payload == nil || len(payload) < int(op.offset+op.blen) {
		regs.verdict = stack.NFVerdict{Code: VC(linux.NFT_BREAK)}
		return
	}

	// Gets the register data assumed to be in Big Endian.
	regData := getRegisterBuffer(regs, op.sreg)[:op.blen]

	// Returns early if the source data is the same as the existing payload data.
	if slices.Equal(regData, payload[op.offset:op.offset+op.blen]) {
		return
	}

	// Sets payload data to source register data after checksum updates.
	defer copy(payload[op.offset:op.offset+op.blen], regData)

	// Specifies no checksum updates.
	if op.csumType != linux.NFT_PAYLOAD_CSUM_INET && op.csumFlags == 0 {
		return
	}

	// Calculates partial checksums of old and new data.
	// Note: Checksums are done on 2-byte boundaries, so we must append the
	// surrounding bytes in our checksum calculations if the beginning or end
	// of the checksum is not aligned to a 2-byte boundary.
	begin := op.offset
	end := op.offset + op.blen
	if begin%2 != 0 {
		begin--
	}
	if end%2 != 0 && end != uint8(len(payload)) {
		end++
	}
	tempOld := make([]byte, end-begin)
	copy(tempOld, payload[begin:end])
	tempNew := make([]byte, end-begin)
	if begin != op.offset {
		tempNew[0] = payload[begin]
	}
	copy(tempNew[op.offset-begin:], regData)
	if end != op.offset+op.blen {
		tempNew[len(tempNew)-1] = payload[end-1]
	}
	oldDataCsum := checksum.Checksum(tempOld, 0)
	newDataCsum := checksum.Checksum(tempNew, 0)

	// Updates the checksum of the header specified by the payload base.
	if op.csumType == linux.NFT_PAYLOAD_CSUM_INET {
		// Reads the old checksum from the packet payload.
		oldTotalCsum := binary.BigEndian.Uint16(payload[op.csumOffset:])

		// New Total = Old Total - Old Data + New Data
		// Logic is very similar to checksum.checksumUpdate2ByteAlignedUint16
		// in gvisor/pkg/tcpip/header/checksum.go
		newTotalCsum := checksum.Combine(^oldTotalCsum, checksum.Combine(newDataCsum, ^oldDataCsum))
		checksum.Put(payload[op.csumOffset:], ^newTotalCsum)
	}

	// Separately updates the L4 checksum if the pseudo-header flag is set.
	// Note: it is possible to update the L4 checksum without updating the
	// checksum of the header specified by the payload base (ie type is NONE,
	// flag is pseudo-header). Specifically, IPv6 headers don't have their
	// own checksum calculations, but the L4 checksum is still updated for any
	// TCP/UDP headers following the IPv6 header.
	if op.csumFlags&linux.NFT_PAYLOAD_L4CSUM_PSEUDOHDR != 0 {
		if tBytes := pkt.TransportHeader().Slice(); pkt.TransportProtocolNumber != 0 && len(tBytes) > 0 {
			var transport header.Transport
			switch pkt.TransportProtocolNumber {
			case header.TCPProtocolNumber:
				transport = header.TCP(tBytes)
			case header.UDPProtocolNumber:
				transport = header.UDP(tBytes)
			case header.ICMPv4ProtocolNumber:
				transport = header.ICMPv4(tBytes)
			case header.ICMPv6ProtocolNumber:
				transport = header.ICMPv6(tBytes)
			case header.IGMPProtocolNumber:
				transport = header.IGMP(tBytes)
			}
			if transport != nil { // only updates if the transport header is present.
				// New Total = Old Total - Old Data + New Data (same as above)
				transport.SetChecksum(^checksum.Combine(^transport.Checksum(), checksum.Combine(newDataCsum, ^oldDataCsum)))
			}
		}
	}
}

func (op payloadSet) GetExprName() string {
	return "payload"
}

func (op payloadSet) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_PAYLOAD_SREG, nlmsg.PutU32(uint32(op.sreg)))
	m.PutAttr(linux.NFTA_PAYLOAD_BASE, nlmsg.PutU32(uint32(op.base)))
	m.PutAttr(linux.NFTA_PAYLOAD_OFFSET, nlmsg.PutU32(uint32(op.offset)))
	m.PutAttr(linux.NFTA_PAYLOAD_LEN, nlmsg.PutU32(uint32(op.blen)))
	m.PutAttr(linux.NFTA_PAYLOAD_CSUM_TYPE, nlmsg.PutU32(uint32(op.csumType)))
	m.PutAttr(linux.NFTA_PAYLOAD_CSUM_OFFSET, nlmsg.PutU32(uint32(op.csumOffset)))
	m.PutAttr(linux.NFTA_PAYLOAD_CSUM_FLAGS, nlmsg.PutU32(uint32(op.csumFlags)))
	return m.Buffer(), nil
}

func initPayloadSet(tab *Table, attrs map[uint16]nlmsg.BytesView) (*payloadSet, *syserr.AnnotatedError) {
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
	sreg, ok := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_SREG, attrs)
	if !ok {
		return nil, syserr.NewAnnotatedError(syserr.ErrInvalidArgument, "failed to parse NFTA_PAYLOAD_SREG attribute value")
	}
	// Optional attributes; validation is not required.
	csumType, _ := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_CSUM_TYPE, attrs)
	csumOffset, _ := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_CSUM_OFFSET, attrs)
	csumFlags, _ := AttrNetToHost[uint32](linux.NFTA_PAYLOAD_CSUM_FLAGS, attrs)
	return newPayloadSet(payloadBase(base), uint8(offset), uint8(blen), uint8(sreg), uint8(csumType), uint8(csumOffset), uint8(csumFlags))
}
