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

package ipv4

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/internal/testutil"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// calculateZeroChecksumUDPPayload determines the payload for a UDP packet
// such that the calculated checksum is 0.
func calculateZeroChecksumUDPPayload(r *stack.Route, srcPort, dstPort uint16, payloadLen int) []byte {
	udpLen := uint16(header.UDPMinimumSize + payloadLen)
	xsumPseudo := r.PseudoHeaderChecksum(header.UDPProtocolNumber, udpLen)

	udpHeader := make(header.UDP, header.UDPMinimumSize)
	udpHeader.Encode(&header.UDPFields{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  udpLen,
	})

	udpSum := checksum.Checksum(udpHeader, 0)
	S := checksum.Combine(xsumPseudo, udpSum)
	L := ^S

	payload := make([]byte, payloadLen)
	binary.BigEndian.PutUint16(payload, L)
	return payload
}

func TestRecalculateChecksum(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol},
	})

	ep := testutil.NewMockLinkEndpoint(1500, nil, math.MaxInt32)
	defer ep.Close()

	r, err := func() (*stack.Route, error) {
		if err := s.CreateNIC(1, ep); err != nil {
			return nil, fmt.Errorf("CreateNIC(1, _) failed: %s", err)
		}

		src := tcpip.AddrFrom4([4]byte{16, 0, 0, 1})
		dst := tcpip.AddrFrom4([4]byte{16, 0, 0, 2})
		protocolAddr := tcpip.ProtocolAddress{
			Protocol:          ProtocolNumber,
			AddressWithPrefix: src.WithPrefix(),
		}
		if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("AddProtocolAddress(1, %+v, {}) failed: %s", protocolAddr, err)
		}
		{
			mask := tcpip.MaskFromBytes(header.IPv4Broadcast.AsSlice())
			subnet, err := tcpip.NewSubnet(dst, mask)
			if err != nil {
				return nil, fmt.Errorf("NewSubnet(%s, %s) failed: %s", dst, mask, err)
			}
			s.SetRouteTable([]tcpip.Route{{
				Destination: subnet,
				NIC:         1,
			}})
		}
		rt, err := s.FindRoute(1, src, dst, ProtocolNumber, false /* multicastLoop */)
		if err != nil {
			return nil, fmt.Errorf("FindRoute(%d, %s, %s, %d, false) failed: %s", 1, src, dst, ProtocolNumber, err)
		}
		return rt, nil
	}()
	if err != nil {
		t.Fatalf("Failed to create route: %s", err)
	}
	defer r.Release()

	tests := []struct {
		name         string
		pkt          *stack.PacketBuffer
		wantChecksum uint16
		wantErr      bool
	}{
		{
			name: "UDP Zero Checksum",
			pkt: func() *stack.PacketBuffer {
				payload := calculateZeroChecksumUDPPayload(r, 1234, 5678, 2)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
					Payload:            buffer.MakeWithView(buffer.NewViewWithData(payload)),
				})
				pkt.TransportProtocolNumber = header.UDPProtocolNumber

				transportHdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
				header.UDP(transportHdr).Encode(&header.UDPFields{
					SrcPort: 1234,
					DstPort: 5678,
					Length:  uint16(header.UDPMinimumSize + len(payload)),
				})

				ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
				ipHeader.Encode(&header.IPv4Fields{
					Protocol:    uint8(header.UDPProtocolNumber),
					TOS:         0,
					TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)),
				})
				return pkt
			}(),
			wantChecksum: 0xFFFF,
		},
		{
			name: "UDP Non Zero Checksum",
			pkt: func() *stack.PacketBuffer {
				payload := []byte{0x11, 0x22}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
					Payload:            buffer.MakeWithView(buffer.NewViewWithData(payload)),
				})
				pkt.TransportProtocolNumber = header.UDPProtocolNumber

				transportHdr := pkt.TransportHeader().Push(header.UDPMinimumSize)
				header.UDP(transportHdr).Encode(&header.UDPFields{
					SrcPort: 1234,
					DstPort: 5678,
					Length:  uint16(header.UDPMinimumSize + len(payload)),
				})

				ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
				ipHeader.Encode(&header.IPv4Fields{
					Protocol:    uint8(header.UDPProtocolNumber),
					TOS:         0,
					TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize + len(payload)),
				})
				return pkt
			}(),
			wantChecksum: 0xb3b5,
		},
		{
			name: "TCP",
			pkt: func() *stack.PacketBuffer {
				payload := []byte{0x11, 0x22}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
					Payload:            buffer.MakeWithView(buffer.NewViewWithData(payload)),
				})
				pkt.TransportProtocolNumber = header.TCPProtocolNumber

				transportHdr := pkt.TransportHeader().Push(header.TCPMinimumSize)
				header.TCP(transportHdr).Encode(&header.TCPFields{
					SrcPort:    1234,
					DstPort:    5678,
					SeqNum:     1,
					AckNum:     1,
					DataOffset: uint8(header.TCPMinimumSize),
				})

				ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
				ipHeader.Encode(&header.IPv4Fields{
					Protocol:    uint8(header.TCPProtocolNumber),
					TOS:         0,
					TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize + len(payload)),
				})
				return pkt
			}(),
			wantChecksum: 0x63bc,
		},
		{
			name: "Invalid UDP packet",
			pkt: func() *stack.PacketBuffer {
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					ReserveHeaderBytes: header.IPv4MinimumSize + 4,
					Payload:            buffer.MakeWithView(buffer.NewViewSize(0)),
				})
				pkt.TransportProtocolNumber = header.UDPProtocolNumber

				// Insufficient transport header size.
				pkt.TransportHeader().Push(4)

				ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
				ipHeader.Encode(&header.IPv4Fields{
					Protocol:    uint8(header.UDPProtocolNumber),
					TOS:         0,
					TotalLength: uint16(header.IPv4MinimumSize + 4),
				})
				return pkt
			}(),
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkt := test.pkt
			defer pkt.DecRef()
			err := recalculateChecksum(pkt, r)
			if test.wantErr {
				if err == nil {
					t.Errorf("recalculateChecksum succeeded, wanted error")
				}
				return
			}
			if err != nil {
				t.Fatalf("recalculateChecksum failed: %s", err)
			}

			var gotChecksum uint16
			switch pkt.TransportProtocolNumber {
			case header.UDPProtocolNumber:
				gotChecksum = header.UDP(pkt.TransportHeader().Slice()).Checksum()
			case header.TCPProtocolNumber:
				gotChecksum = header.TCP(pkt.TransportHeader().Slice()).Checksum()
			}

			if gotChecksum != test.wantChecksum {
				t.Errorf("got checksum = 0x%04x, want 0x%04x", gotChecksum, test.wantChecksum)
			}
		})
	}
}
