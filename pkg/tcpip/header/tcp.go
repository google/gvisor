// Copyright 2018 Google LLC
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

package header

import (
	"encoding/binary"

	"github.com/google/btree"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/seqnum"
)

// These constants are the offsets of the respective fields in the TCP header.
const (
	TCPSrcPortOffset   = 0
	TCPDstPortOffset   = 2
	TCPSeqNumOffset    = 4
	TCPAckNumOffset    = 8
	TCPDataOffset      = 12
	TCPFlagsOffset     = 13
	TCPWinSizeOffset   = 14
	TCPChecksumOffset  = 16
	TCPUrgentPtrOffset = 18
)

const (
	// MaxWndScale is maximum allowed window scaling, as described in
	// RFC 1323, section 2.3, page 11.
	MaxWndScale = 14

	// TCPMaxSACKBlocks is the maximum number of SACK blocks that can
	// be encoded in a TCP option field.
	TCPMaxSACKBlocks = 4
)

// Flags that may be set in a TCP segment.
const (
	TCPFlagFin = 1 << iota
	TCPFlagSyn
	TCPFlagRst
	TCPFlagPsh
	TCPFlagAck
	TCPFlagUrg
)

// Options that may be present in a TCP segment.
const (
	TCPOptionEOL           = 0
	TCPOptionNOP           = 1
	TCPOptionMSS           = 2
	TCPOptionWS            = 3
	TCPOptionTS            = 8
	TCPOptionSACKPermitted = 4
	TCPOptionSACK          = 5
)

// TCPFields contains the fields of a TCP packet. It is used to describe the
// fields of a packet that needs to be encoded.
type TCPFields struct {
	// SrcPort is the "source port" field of a TCP packet.
	SrcPort uint16

	// DstPort is the "destination port" field of a TCP packet.
	DstPort uint16

	// SeqNum is the "sequence number" field of a TCP packet.
	SeqNum uint32

	// AckNum is the "acknowledgement number" field of a TCP packet.
	AckNum uint32

	// DataOffset is the "data offset" field of a TCP packet.
	DataOffset uint8

	// Flags is the "flags" field of a TCP packet.
	Flags uint8

	// WindowSize is the "window size" field of a TCP packet.
	WindowSize uint16

	// Checksum is the "checksum" field of a TCP packet.
	Checksum uint16

	// UrgentPointer is the "urgent pointer" field of a TCP packet.
	UrgentPointer uint16
}

// TCPSynOptions is used to return the parsed TCP Options in a syn
// segment.
type TCPSynOptions struct {
	// MSS is the maximum segment size provided by the peer in the SYN.
	MSS uint16

	// WS is the window scale option provided by the peer in the SYN.
	//
	// Set to -1 if no window scale option was provided.
	WS int

	// TS is true if the timestamp option was provided in the syn/syn-ack.
	TS bool

	// TSVal is the value of the TSVal field in the timestamp option.
	TSVal uint32

	// TSEcr is the value of the TSEcr field in the timestamp option.
	TSEcr uint32

	// SACKPermitted is true if the SACK option was provided in the SYN/SYN-ACK.
	SACKPermitted bool
}

// SACKBlock represents a single contiguous SACK block.
//
// +stateify savable
type SACKBlock struct {
	// Start indicates the lowest sequence number in the block.
	Start seqnum.Value

	// End indicates the sequence number immediately following the last
	// sequence number of this block.
	End seqnum.Value
}

// Less returns true if r.Start < b.Start.
func (r SACKBlock) Less(b btree.Item) bool {
	return r.Start.LessThan(b.(SACKBlock).Start)
}

// Contains returns true if b is completely contained in r.
func (r SACKBlock) Contains(b SACKBlock) bool {
	return r.Start.LessThanEq(b.Start) && b.End.LessThanEq(r.End)
}

// TCPOptions are used to parse and cache the TCP segment options for a non
// syn/syn-ack segment.
//
// +stateify savable
type TCPOptions struct {
	// TS is true if the TimeStamp option is enabled.
	TS bool

	// TSVal is the value in the TSVal field of the segment.
	TSVal uint32

	// TSEcr is the value in the TSEcr field of the segment.
	TSEcr uint32

	// SACKBlocks are the SACK blocks specified in the segment.
	SACKBlocks []SACKBlock
}

// TCP represents a TCP header stored in a byte array.
type TCP []byte

const (
	// TCPMinimumSize is the minimum size of a valid TCP packet.
	TCPMinimumSize = 20

	// TCPOptionsMaximumSize is the maximum size of TCP options.
	TCPOptionsMaximumSize = 40

	// TCPHeaderMaximumSize is the maximum header size of a TCP packet.
	TCPHeaderMaximumSize = TCPMinimumSize + TCPOptionsMaximumSize

	// TCPProtocolNumber is TCP's transport protocol number.
	TCPProtocolNumber tcpip.TransportProtocolNumber = 6
)

// SourcePort returns the "source port" field of the tcp header.
func (b TCP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[TCPSrcPortOffset:])
}

// DestinationPort returns the "destination port" field of the tcp header.
func (b TCP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[TCPDstPortOffset:])
}

// SequenceNumber returns the "sequence number" field of the tcp header.
func (b TCP) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(b[TCPSeqNumOffset:])
}

// AckNumber returns the "ack number" field of the tcp header.
func (b TCP) AckNumber() uint32 {
	return binary.BigEndian.Uint32(b[TCPAckNumOffset:])
}

// DataOffset returns the "data offset" field of the tcp header.
func (b TCP) DataOffset() uint8 {
	return (b[TCPDataOffset] >> 4) * 4
}

// Payload returns the data in the tcp packet.
func (b TCP) Payload() []byte {
	return b[b.DataOffset():]
}

// Flags returns the flags field of the tcp header.
func (b TCP) Flags() uint8 {
	return b[TCPFlagsOffset]
}

// WindowSize returns the "window size" field of the tcp header.
func (b TCP) WindowSize() uint16 {
	return binary.BigEndian.Uint16(b[TCPWinSizeOffset:])
}

// Checksum returns the "checksum" field of the tcp header.
func (b TCP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[TCPChecksumOffset:])
}

// SetSourcePort sets the "source port" field of the tcp header.
func (b TCP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[TCPSrcPortOffset:], port)
}

// SetDestinationPort sets the "destination port" field of the tcp header.
func (b TCP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[TCPDstPortOffset:], port)
}

// SetChecksum sets the checksum field of the tcp header.
func (b TCP) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(b[TCPChecksumOffset:], checksum)
}

// CalculateChecksum calculates the checksum of the tcp segment.
// partialChecksum is the checksum of the network-layer pseudo-header
// and the checksum of the segment data.
func (b TCP) CalculateChecksum(partialChecksum uint16) uint16 {
	// Calculate the rest of the checksum.
	return Checksum(b[:b.DataOffset()], partialChecksum)
}

// Options returns a slice that holds the unparsed TCP options in the segment.
func (b TCP) Options() []byte {
	return b[TCPMinimumSize:b.DataOffset()]
}

// ParsedOptions returns a TCPOptions structure which parses and caches the TCP
// option values in the TCP segment. NOTE: Invoking this function repeatedly is
// expensive as it reparses the options on each invocation.
func (b TCP) ParsedOptions() TCPOptions {
	return ParseTCPOptions(b.Options())
}

func (b TCP) encodeSubset(seq, ack uint32, flags uint8, rcvwnd uint16) {
	binary.BigEndian.PutUint32(b[TCPSeqNumOffset:], seq)
	binary.BigEndian.PutUint32(b[TCPAckNumOffset:], ack)
	b[TCPFlagsOffset] = flags
	binary.BigEndian.PutUint16(b[TCPWinSizeOffset:], rcvwnd)
}

// Encode encodes all the fields of the tcp header.
func (b TCP) Encode(t *TCPFields) {
	b.encodeSubset(t.SeqNum, t.AckNum, t.Flags, t.WindowSize)
	binary.BigEndian.PutUint16(b[TCPSrcPortOffset:], t.SrcPort)
	binary.BigEndian.PutUint16(b[TCPDstPortOffset:], t.DstPort)
	b[TCPDataOffset] = (t.DataOffset / 4) << 4
	binary.BigEndian.PutUint16(b[TCPChecksumOffset:], t.Checksum)
	binary.BigEndian.PutUint16(b[TCPUrgentPtrOffset:], t.UrgentPointer)
}

// EncodePartial updates a subset of the fields of the tcp header. It is useful
// in cases when similar segments are produced.
func (b TCP) EncodePartial(partialChecksum, length uint16, seqnum, acknum uint32, flags byte, rcvwnd uint16) {
	// Add the total length and "flags" field contributions to the checksum.
	// We don't use the flags field directly from the header because it's a
	// one-byte field with an odd offset, so it would be accounted for
	// incorrectly by the Checksum routine.
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp, length)
	binary.BigEndian.PutUint16(tmp[2:], uint16(flags))
	checksum := Checksum(tmp, partialChecksum)

	// Encode the passed-in fields.
	b.encodeSubset(seqnum, acknum, flags, rcvwnd)

	// Add the contributions of the passed-in fields to the checksum.
	checksum = Checksum(b[TCPSeqNumOffset:TCPSeqNumOffset+8], checksum)
	checksum = Checksum(b[TCPWinSizeOffset:TCPWinSizeOffset+2], checksum)

	// Encode the checksum.
	b.SetChecksum(^checksum)
}

// ParseSynOptions parses the options received in a SYN segment and returns the
// relevant ones. opts should point to the option part of the TCP Header.
func ParseSynOptions(opts []byte, isAck bool) TCPSynOptions {
	limit := len(opts)

	synOpts := TCPSynOptions{
		// Per RFC 1122, page 85: "If an MSS option is not received at
		// connection setup, TCP MUST assume a default send MSS of 536."
		MSS: 536,
		// If no window scale option is specified, WS in options is
		// returned as -1; this is because the absence of the option
		// indicates that the we cannot use window scaling on the
		// receive end either.
		WS: -1,
	}

	for i := 0; i < limit; {
		switch opts[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionMSS:
			if i+4 > limit || opts[i+1] != 4 {
				return synOpts
			}
			mss := uint16(opts[i+2])<<8 | uint16(opts[i+3])
			if mss == 0 {
				return synOpts
			}
			synOpts.MSS = mss
			i += 4

		case TCPOptionWS:
			if i+3 > limit || opts[i+1] != 3 {
				return synOpts
			}
			ws := int(opts[i+2])
			if ws > MaxWndScale {
				ws = MaxWndScale
			}
			synOpts.WS = ws
			i += 3

		case TCPOptionTS:
			if i+10 > limit || opts[i+1] != 10 {
				return synOpts
			}
			synOpts.TSVal = binary.BigEndian.Uint32(opts[i+2:])
			if isAck {
				// If the segment is a SYN-ACK then store the Timestamp Echo Reply
				// in the segment.
				synOpts.TSEcr = binary.BigEndian.Uint32(opts[i+6:])
			}
			synOpts.TS = true
			i += 10
		case TCPOptionSACKPermitted:
			if i+2 > limit || opts[i+1] != 2 {
				return synOpts
			}
			synOpts.SACKPermitted = true
			i += 2

		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return synOpts
			}
			l := int(opts[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return synOpts
			}
			i += l
		}
	}

	return synOpts
}

// ParseTCPOptions extracts and stores all known options in the provided byte
// slice in a TCPOptions structure.
func ParseTCPOptions(b []byte) TCPOptions {
	opts := TCPOptions{}
	limit := len(b)
	for i := 0; i < limit; {
		switch b[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionTS:
			if i+10 > limit || (b[i+1] != 10) {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		case TCPOptionSACK:
			if i+2 > limit {
				// Malformed SACK block, just return and stop parsing.
				return opts
			}
			sackOptionLen := int(b[i+1])
			if i+sackOptionLen > limit || (sackOptionLen-2)%8 != 0 {
				// Malformed SACK block, just return and stop parsing.
				return opts
			}
			numBlocks := (sackOptionLen - 2) / 8
			opts.SACKBlocks = []SACKBlock{}
			for j := 0; j < numBlocks; j++ {
				start := binary.BigEndian.Uint32(b[i+2+j*8:])
				end := binary.BigEndian.Uint32(b[i+2+j*8+4:])
				opts.SACKBlocks = append(opts.SACKBlocks, SACKBlock{
					Start: seqnum.Value(start),
					End:   seqnum.Value(end),
				})
			}
			i += sackOptionLen
		default:
			// We don't recognize this option, just skip over it.
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			// If the length is incorrect or if l+i overflows the
			// total options length then return false.
			if l < 2 || i+l > limit {
				return opts
			}
			i += l
		}
	}
	return opts
}

// EncodeMSSOption encodes the MSS TCP option with the provided MSS values in
// the supplied buffer. If the provided buffer is not large enough then it just
// returns without encoding anything. It returns the number of bytes written to
// the provided buffer.
func EncodeMSSOption(mss uint32, b []byte) int {
	// mssOptionSize is the number of bytes in a valid MSS option.
	const mssOptionSize = 4

	if len(b) < mssOptionSize {
		return 0
	}
	b[0], b[1], b[2], b[3] = TCPOptionMSS, mssOptionSize, byte(mss>>8), byte(mss)
	return mssOptionSize
}

// EncodeWSOption encodes the WS TCP option with the WS value in the
// provided buffer. If the provided buffer is not large enough then it just
// returns without encoding anything. It returns the number of bytes written to
// the provided buffer.
func EncodeWSOption(ws int, b []byte) int {
	if len(b) < 3 {
		return 0
	}
	b[0], b[1], b[2] = TCPOptionWS, 3, uint8(ws)
	return int(b[1])
}

// EncodeTSOption encodes the provided tsVal and tsEcr values as a TCP timestamp
// option into the provided buffer. If the buffer is smaller than expected it
// just returns without encoding anything. It returns the number of bytes
// written to the provided buffer.
func EncodeTSOption(tsVal, tsEcr uint32, b []byte) int {
	if len(b) < 10 {
		return 0
	}
	b[0], b[1] = TCPOptionTS, 10
	binary.BigEndian.PutUint32(b[2:], tsVal)
	binary.BigEndian.PutUint32(b[6:], tsEcr)
	return int(b[1])
}

// EncodeSACKPermittedOption encodes a SACKPermitted option into the provided
// buffer. If the buffer is smaller than required it just returns without
// encoding anything. It returns the number of bytes written to the provided
// buffer.
func EncodeSACKPermittedOption(b []byte) int {
	if len(b) < 2 {
		return 0
	}

	b[0], b[1] = TCPOptionSACKPermitted, 2
	return int(b[1])
}

// EncodeSACKBlocks encodes the provided SACK blocks as a TCP SACK option block
// in the provided slice. It tries to fit in as many blocks as possible based on
// number of bytes available in the provided buffer. It returns the number of
// bytes written to the provided buffer.
func EncodeSACKBlocks(sackBlocks []SACKBlock, b []byte) int {
	if len(sackBlocks) == 0 {
		return 0
	}
	l := len(sackBlocks)
	if l > TCPMaxSACKBlocks {
		l = TCPMaxSACKBlocks
	}
	if ll := (len(b) - 2) / 8; ll < l {
		l = ll
	}
	if l == 0 {
		// There is not enough space in the provided buffer to add
		// any SACK blocks.
		return 0
	}
	b[0] = TCPOptionSACK
	b[1] = byte(l*8 + 2)
	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint32(b[i*8+2:], uint32(sackBlocks[i].Start))
		binary.BigEndian.PutUint32(b[i*8+6:], uint32(sackBlocks[i].End))
	}
	return int(b[1])
}

// EncodeNOP adds an explicit NOP to the option list.
func EncodeNOP(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	b[0] = TCPOptionNOP
	return 1
}

// AddTCPOptionPadding adds the required number of TCPOptionNOP to quad align
// the option buffer. It adds padding bytes after the offset specified and
// returns the number of padding bytes added. The passed in options slice
// must have space for the padding bytes.
func AddTCPOptionPadding(options []byte, offset int) int {
	paddingToAdd := -offset & 3
	// Now add any padding bytes that might be required to quad align the
	// options.
	for i := offset; i < offset+paddingToAdd; i++ {
		options[i] = TCPOptionNOP
	}
	return paddingToAdd
}
