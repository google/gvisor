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

// Binary gvisor2pcap converts gVisor packet sniffer output to .pcap files that
// can be fed to Wireshark or tcpdump.
//
// gvisor2pcap currently supports only TCP on IPv4. It doesn't handle SACK
// blocks.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/bits"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// packetTruncateSize is the maximum per-packet size to store in pcap output.
// We reconstruct packet headers during conversion, but have no access to their
// payloads. So there's never a reason to store more than their headers.
const packetTruncateSize = header.IPv4MaximumHeaderSize + header.TCPHeaderMaximumSize

// Flags.
var (
	inFileName  = flag.String("in", "/dev/stdin", "log file containing sniffer output to be parsed (default: stdin)")
	outFileName = flag.String("out", "/dev/stdout", "file to write to (default: stdout)")
)

// Regular expression for matching sniffer output.
var snifferOutput = regexp.MustCompile(`^.*sniffer\.go.*(send|recv).*$`)

func main() {
	if err := run(); err != nil {
		log.Warningf("%v", err)
		os.Exit(1)
	}
}

// run is basically a main function that can return errors.
func run() error {
	flag.Parse()

	// Open the input log file.
	input, err := os.Open(*inFileName)
	if err != nil {
		return fmt.Errorf("failed to open input file %s: %w", *inFileName, err)
	}
	defer input.Close()

	// Open the output pcap file.
	output, err := os.Create(*outFileName)
	if err != nil {
		return fmt.Errorf("failed to open output file %s: %w", *outFileName, err)
	}
	defer output.Close()

	// Write the pcap header.
	ep, err := sniffer.NewWithWriter(nil, output, packetTruncateSize)
	if err != nil {
		return fmt.Errorf("failed to create sniffer: %w", err)
	}
	// Suppress text output.
	sniffer.LogPackets.Store(0)

	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		if err := processLine(ep, scanner); err != nil {
			log.Infof("skipping line: %v: %q", err, scanner.Text())
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("encountered scanner error: %w", err)
	}

	return nil
}

func processLine(ep *sniffer.Endpoint, scanner *bufio.Scanner) error {
	// Filter for sniffer output.
	line := scanner.Text()
	if !snifferOutput.MatchString(line) {
		return nil
	}

	// Timestamp has the form "I0829 21:58:10.197938".
	tokens := strings.Fields(line)
	if len(tokens) < 2 {
		return fmt.Errorf("not enough tokens for timestamp")
	}
	tsStr := fmt.Sprintf("%s %s", tokens[0], tokens[1])
	timestamp, err := time.Parse("I0102 15:04:05.000000", tsStr)
	if err != nil {
		return fmt.Errorf("couldn't parse timestamp: %w", err)
	}

	// Discard text leading up to "send" or "recv".
	for i, token := range tokens {
		if token == "send" || token == "recv" {
			tokens = tokens[i:]
			break
		}
	}

	// Get the direction.
	var direction sniffer.Direction
	switch tokens[0] {
	case "send":
		direction = sniffer.DirectionSend
	case "recv":
		direction = sniffer.DirectionRecv
	default:
		panic(fmt.Sprintf("unknown direction %q", tokens[0]))
	}
	tokens = tokens[1:]

	// Get the transport protocol. We only support TCP for now.
	if len(tokens) == 0 {
		return fmt.Errorf("not enough tokens for transport protocol")
	}
	var transProto tcpip.TransportProtocolNumber
	switch tokens[0] {
	case "tcp":
		transProto = header.TCPProtocolNumber
	default:
		return fmt.Errorf("unhandled protocol %s", tokens[0])
	}
	tokens = tokens[1:]

	// The next few tokens look like "1.2.3.4:500 -> 6.7.8.9:1000".
	srcIP, srcPort, err := consumeIPPort(&tokens)
	if err != nil {
		return fmt.Errorf("bad source: %w", err)
	}
	if len(tokens) == 0 {
		return fmt.Errorf("not enough tokens for '->'")
	}
	if tokens[0] != "->" {
		return fmt.Errorf("'->' was expected but not found")
	}
	tokens = tokens[1:]
	dstIP, dstPort, err := consumeIPPort(&tokens)
	if err != nil {
		return fmt.Errorf("bad source: %w", err)
	}

	// Packet length is of the form "len:200". It describes the
	// payload length not including headers.
	length, err := consumeFieldUint[uint16](&tokens, "len")
	if err != nil {
		return fmt.Errorf("bad length: %w", err)
	}

	// Packet ID is of the form "id:0xa20f".
	id, err := consumeFieldUint[uint16](&tokens, "id")
	if err != nil {
		return fmt.Errorf("bad id: %w", err)
	}

	// TCP flags are trickier. If every flag is set, we'll see
	// "flags:FSRPAUEC". Each unset flag becomes whitespace, so
	// flags are a variable number of tokens in length. We look for
	// the tokens before and after the flags ("flags:" and
	// "seqnum:") to find them.
	var ok bool
	if len(tokens) == 0 {
		return fmt.Errorf("not enough tokens for 'flags:'")
	}
	tokens[0], ok = strings.CutPrefix(tokens[0], "flags:")
	if !ok {
		return fmt.Errorf("missing \"flags:\"")
	}
	if len(tokens[0]) == 0 {
		tokens = tokens[1:]
	}

	flagsEnd := -1
	for i, token := range tokens {
		if strings.HasPrefix(token, "seqnum:") {
			flagsEnd = i
			break
		}
	}
	if flagsEnd == -1 {
		return fmt.Errorf("bad flags/seqnum formatting")
	}
	var flags header.TCPFlags
	for _, token := range tokens[:flagsEnd] {
		// Tokens may be a single flag e.g. "S", or multiple e.g. "PA".
		for _, flag := range token {
			switch flag {
			case 'F':
				flags |= header.TCPFlagFin
			case 'S':
				flags |= header.TCPFlagSyn
			case 'R':
				flags |= header.TCPFlagRst
			case 'P':
				flags |= header.TCPFlagPsh
			case 'A':
				flags |= header.TCPFlagAck
			case 'U':
				flags |= header.TCPFlagUrg
			case 'E':
				flags |= header.TCPFlagEce
			case 'C':
				flags |= header.TCPFlagCwr
			default:
				return fmt.Errorf("unknown TCP flag %v", flag)
			}
		}
	}
	tokens = tokens[flagsEnd:]

	// Sequence number.
	seqnum, err := consumeFieldUint[uint32](&tokens, "seqnum")
	if err != nil {
		return fmt.Errorf("bad sequence number: %w", err)
	}

	// Acknowledgement number.
	ack, err := consumeFieldUint[uint32](&tokens, "ack")
	if err != nil {
		return fmt.Errorf("bad ack number: %w", err)
	}

	// Window size.
	window, err := consumeFieldUint[uint16](&tokens, "win")
	if err != nil {
		return fmt.Errorf("bad window size: %w", err)
	}

	// Checksum.
	csum, err := consumeFieldUint[uint16](&tokens, "xsum")
	if err != nil {
		return fmt.Errorf("bad id: %w", err)
	}

	// Options can be one of two types.
	if len(tokens) == 0 {
		return fmt.Errorf("not enough tokens for 'options:'")
	}
	firstOpt, hasOptions := strings.CutPrefix(tokens[0], "options:{")
	if !hasOptions {
		return fmt.Errorf("bad \"options:\" field")
	}
	tokens[0] = firstOpt
	var options any
	switch strings.Split(firstOpt, ":")[0] {
	case "MSS":
		mss, err := consumeFieldUint[uint16](&tokens, "MSS")
		if err != nil {
			return fmt.Errorf("bad mss: %w", err)
		}
		windowScale, err := consumeFieldUint[uint16](&tokens, "WS")
		if err != nil {
			// -1 is special output for "no window scaling".
			if tokens[0] != "WS:-1" {
				return fmt.Errorf("bad window scale: %w", err)
			}
			tokens = tokens[1:]
		}
		timestamp, err := consumeFieldBool(&tokens, "TS")
		if err != nil {
			return fmt.Errorf("bad timestamp: %w", err)
		}
		tsVal, err := consumeFieldUint[uint32](&tokens, "TSVal")
		if err != nil {
			return fmt.Errorf("bad timestamp value: %w", err)
		}
		tsEcr, err := consumeFieldUint[uint32](&tokens, "TSEcr")
		if err != nil {
			return fmt.Errorf("bad timestamp echo reply: %w", err)
		}
		sackPermitted, err := consumeFieldBool(&tokens, "SACKPermitted")
		if err != nil {
			return fmt.Errorf("bad SACKPermitted: %w", err)
		}
		// "Flags:" can be ignored, as it's used internally only.
		if !strings.HasPrefix(tokens[0], "Flags:") {
			return fmt.Errorf("bad \"Flags:\"")
		}
		tokens = tokens[1:]
		if len(tokens) == 0 {
			return fmt.Errorf("not enough tokens for 'options:' closing brace")
		}
		if tokens[0] != "}" {
			return fmt.Errorf("'}' was expected but not found")
		}
		tokens = tokens[1:]
		options = header.TCPSynOptions{
			MSS:           mss,
			WS:            int(windowScale),
			TS:            timestamp,
			TSVal:         tsVal,
			TSEcr:         tsEcr,
			SACKPermitted: sackPermitted,
		}
	case "TS":
		timestamp, err := consumeFieldBool(&tokens, "TS")
		if err != nil {
			return fmt.Errorf("bad timestamp: %w", err)
		}
		tsVal, err := consumeFieldUint[uint32](&tokens, "TSVal")
		if err != nil {
			return fmt.Errorf("bad timestamp value: %w", err)
		}
		tsEcr, err := consumeFieldUint[uint32](&tokens, "TSEcr")
		if err != nil {
			return fmt.Errorf("bad timestamp echo reply: %w", err)
		}

		// For now, just skip SACK blocks by looking for a "]".
		if !strings.HasPrefix(tokens[0], "SACKBlocks:[") {
			return fmt.Errorf("bad missing SACKBlocks field")
		}
		for i, token := range tokens {
			if strings.Contains(token, "]") {
				tokens = tokens[i+1:]
			}
		}

		options = header.TCPOptions{
			TS:         timestamp,
			TSVal:      tsVal,
			TSEcr:      tsEcr,
			SACKBlocks: nil,
		}

	default:
		return fmt.Errorf("bad option: %q", firstOpt)
	}

	// There may be a GSO field.
	if len(tokens) != 0 {
		if !strings.HasPrefix(tokens[0], "gso:") {
			return fmt.Errorf("unknown option %q", tokens[0])
		}
		// At time of writing there are 6 fields in this struct
		// (GSOOptions). We don't need them, but we want to log if
		// we've encountered something we don't understand.
		if len(tokens) != 6 {
			return fmt.Errorf("extra options")
		}
	}

	// TODO(krakauer): Tons of copied code from tcp package.
	optsBuf := make([]byte, 40)
	switch options := options.(type) {
	case header.TCPSynOptions:
		offset := header.EncodeMSSOption(uint32(options.MSS), optsBuf)

		// Special ordering is required here. If both TS and SACK are enabled,
		// then the SACK option precedes TS, with no padding. If they are
		// enabled individually, then we see padding before the option.
		if options.TS && options.SACKPermitted {
			offset += header.EncodeSACKPermittedOption(optsBuf[offset:])
			offset += header.EncodeTSOption(options.TSVal, options.TSEcr, optsBuf[offset:])
		} else if options.TS {
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeTSOption(options.TSVal, options.TSEcr, optsBuf[offset:])
		} else if options.SACKPermitted {
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeSACKPermittedOption(optsBuf[offset:])
		}

		// Initialize the WS option.
		if options.WS >= 0 {
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeWSOption(options.WS, optsBuf[offset:])
		}

		optsBuf = optsBuf[:offset]

		// Padding to the end; note that this never apply unless we add a
		// fastopen option, we always expect the offset to remain the same.
		if delta := header.AddTCPOptionPadding(optsBuf, offset); delta != 0 {
			panic("unexpected option encoding")
		}

	case header.TCPOptions:
		offset := 0
		if options.TS {
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeNOP(optsBuf[offset:])
			offset += header.EncodeTSOption(options.TSVal, options.TSEcr, optsBuf[offset:])
		}
		optsBuf = optsBuf[:offset]

		// We expect the above to produce an aligned offset.
		if delta := header.AddTCPOptionPadding(optsBuf, offset); delta != 0 {
			panic("unexpected option encoding")
		}

	default:
		panic(fmt.Sprintf("bad options type %T", options))
	}

	// Build TCP header.
	tcpHdr := header.TCP(make([]byte, header.TCPMinimumSize+len(optsBuf)))
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seqnum,
		AckNum:     ack,
		DataOffset: uint8(header.TCPMinimumSize + len(optsBuf)),
		Flags:      flags,
		WindowSize: window,
	})
	copy(tcpHdr[header.TCPMinimumSize:], optsBuf)
	length += uint16(len(tcpHdr))

	// Build IP header.
	var ipHdr []byte
	if srcIP.Is4() {
		length += header.IPv4MinimumSize
		hdr := make(header.IPv4, header.IPv4MinimumSize)
		hdr.Encode(&header.IPv4Fields{
			TotalLength: length,
			ID:          id,
			TTL:         10, // Made up.
			TOS:         0,  // Made up.
			Protocol:    uint8(transProto),
			Checksum:    csum,
			SrcAddr:     tcpip.AddrFrom4(srcIP.As4()),
			DstAddr:     tcpip.AddrFrom4(dstIP.As4()),
			Options:     nil,
		})
		ipHdr = hdr
	} else {
		length += header.IPv6MinimumSize
		hdr := make(header.IPv6, header.IPv6MinimumSize)
		hdr.Encode(&header.IPv6Fields{
			PayloadLength:     uint16(len(tcpHdr)),
			TransportProtocol: transProto,
			SrcAddr:           tcpip.AddrFrom16(srcIP.As16()),
			DstAddr:           tcpip.AddrFrom16(dstIP.As16()),
			ExtensionHeaders:  header.IPv6ExtHdrSerializer{},
		})
		ipHdr = hdr
	}

	// Build PacketBuffer.
	data := make([]byte, length)
	copy(data, ipHdr)
	copy(data[len(ipHdr):], tcpHdr)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(data),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.TCPProtocolNumber

	// Inject packet into sniffer to generate pcap output.
	ep.DumpPacket(direction, header.IPv4ProtocolNumber, pkt, &timestamp)
	pkt.DecRef()

	return nil
}

// consumeFieldUint returns the int value of a field of the form: "name:123" or
// "name:0xabc".
func consumeFieldUint[T uint16 | uint32](tokens *[]string, name string) (T, error) {
	if len(*tokens) == 0 {
		return 0, fmt.Errorf("no tokens available to find uint")
	}
	field := strings.Split((*tokens)[0], ":")
	if len(field) != 2 || field[0] != name {
		return 0, fmt.Errorf("bad field: %q", field)
	}
	base := 10
	if len(field[1]) >= 2 && strings.HasPrefix(field[1], "0x") {
		field[1] = field[1][2:]
		base = 16
	}

	// Get the bit length of T so we can pass it to ParseUint.
	bitLen := bits.OnesCount64(uint64(T(0) - 1))

	value, err := strconv.ParseUint(field[1], base, bitLen)
	if err != nil {
		return 0, fmt.Errorf("field has bad value %q: %w", field[1], err)
	}
	*tokens = (*tokens)[1:]
	return T(value), nil
}

// consumeFieldBool returns the bool value of a field of the form: "name:true"
// or "name:false".
func consumeFieldBool(tokens *[]string, name string) (bool, error) {
	if len(*tokens) == 0 {
		return false, fmt.Errorf("no tokens available to find bool")
	}
	field := strings.Split((*tokens)[0], ":")
	if len(field) != 2 || field[0] != name {
		return false, fmt.Errorf("bad field: %q", field)
	}
	defer func() { *tokens = (*tokens)[1:] }()
	switch field[1] {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("unrecognized boolean value %q", (*tokens)[0])
	}
}

func consumeIPPort(tokens *[]string) (netip.Addr, uint16, error) {
	if len(*tokens) == 0 {
		return netip.Addr{}, 0, fmt.Errorf("no tokens available to find address:port")
	}
	token := (*tokens)[0]
	lastColon := strings.LastIndex(token, ":")
	if lastColon < 0 {
		return netip.Addr{}, 0, fmt.Errorf("bad address:port %q", token)
	}
	address, err := netip.ParseAddr(token[:lastColon])
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad source address %q", token[:lastColon])
	}
	port, err := strconv.ParseUint(token[lastColon+1:], 10, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("bad source port %q", token[lastColon+1:])
	}
	*tokens = (*tokens)[1:]
	return address, uint16(port), nil
}
