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

package gvisor2pcap_test

import (
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// TestGvisor2PCAP ensures that gVisor packet logs remain compatible with
// gvisor2pcap.
func TestGvisor2PCAP(t *testing.T) {
	tempDir := t.TempDir()
	tempIn := path.Join(tempDir, "in.log")
	in, err := os.Create(tempIn)
	if err != nil {
		t.Fatalf("couldn't create input file: %v", err)
	}

	// Capture sniffer output.
	log.SetTarget(log.GoogleEmitter{Writer: &log.Writer{Next: in}})

	// Run packets through the sniffer generate output.
	snfr := sniffer.New(nil)
	pkts := buildPackets()
	defer pkts.Reset()
	for _, pkt := range pkts.AsSlice() {
		snfr.DumpPacket(sniffer.DirectionRecv, pkt.NetworkProtocolNumber, pkt, nil)
	}
	for _, pkt := range pkts.AsSlice() {
		snfr.DumpPacket(sniffer.DirectionSend, pkt.NetworkProtocolNumber, pkt, nil)
	}

	testBinary(t, tempIn, tempDir)
}

func buildPackets() stack.PacketBufferList {
	// The various sizes and fields of generated packets are arbitrary.
	var pbl stack.PacketBufferList
	for _, ipGen := range []func([]byte, tcpip.TransportProtocolNumber) *stack.PacketBuffer{genIPv4, genIPv6} {
		for _, transportGen := range []func() ([]byte, tcpip.TransportProtocolNumber){genTCP, genUDP} {
			transHdr, proto := transportGen()
			pbl.PushBack(ipGen(transHdr, proto))
		}
	}
	return pbl
}

func genTCP() ([]byte, tcpip.TransportProtocolNumber) {
	tcp := header.TCP(make([]byte, header.TCPMinimumSize))
	tcp.Encode(&header.TCPFields{
		SeqNum:     800,
		AckNum:     902,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 4096,
	})
	return []byte(tcp), header.TCPProtocolNumber
}

func genUDP() ([]byte, tcpip.TransportProtocolNumber) {
	udp := header.UDP(make([]byte, header.UDPMinimumSize))
	udp.Encode(&header.UDPFields{
		SrcPort:  343,
		DstPort:  2401,
		Length:   uint16(len(udp)),
		Checksum: 0,
	})
	return []byte(udp), header.UDPProtocolNumber
}

func genIPv4(payload []byte, proto tcpip.TransportProtocolNumber) *stack.PacketBuffer {
	pktLen := uint16(header.IPv4MinimumSize + len(payload))
	pktData := make([]byte, header.IPv4MinimumSize)
	ip := header.IPv4(pktData)
	ip.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    pktLen,
		ID:             1,
		Flags:          0,
		FragmentOffset: 0,
		TTL:            48,
		Protocol:       uint8(proto),
		SrcAddr:        tcpip.AddrFromSlice([]byte("\x01\x02\x03\x04")),
		DstAddr:        tcpip.AddrFromSlice([]byte("\x05\x06\x07\x08")),
	})
	ip.SetChecksum(42)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append(pktData, payload...)),
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	return pkt
}

func genIPv6(payload []byte, proto tcpip.TransportProtocolNumber) *stack.PacketBuffer {
	pktData := make([]byte, header.IPv6MinimumSize)
	ip := header.IPv6(pktData)
	ip.Encode(&header.IPv6Fields{
		TrafficClass:      1,
		FlowLabel:         2,
		PayloadLength:     uint16(len(payload)),
		TransportProtocol: proto,
		HopLimit:          78,
		SrcAddr:           tcpip.AddrFromSlice([]byte("\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04\x01\x02\x03\x04")),
		DstAddr:           tcpip.AddrFromSlice([]byte("\x05\x06\x07\x08\x05\x06\x07\x08\x05\x06\x07\x08\x05\x06\x07\x08")),
		ExtensionHeaders:  header.IPv6ExtHdrSerializer{},
	})
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append(pktData, payload...)),
	})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	return pkt
}

// TestGolden runs against the packet logs from `wget`. This is a larger,
// more realistic log than we could reasonably generate ourselves.
//
// One way to generate a new golden is via docker configured to run `runsc`
// with `--log-packets`. Build an image with wget and run
// `docker run --runtime runsc wget-image wget -4 google.com`
func TestGolden(t *testing.T) {
	tempDir := t.TempDir()
	packetLogFile, err := testutil.FindFile("tools/gvisor2pcap/wget.log")
	if err != nil {
		t.Fatalf("couldn't get log path: %v", err)
	}

	testBinary(t, packetLogFile, tempDir)
}

// TestGolden6 runs against the packet logs from `wget -6`. This is a larger,
// more realistic log than we could reasonably generate ourselves.
//
// One way to generate a new golden is via docker configured to run `runsc`
// with `--log-packets`. Build an image with wget and run
// `docker run --runtime runsc wget-image wget -6 google.com`
func TestGolden6(t *testing.T) {
	tempDir := t.TempDir()
	packetLogFile, err := testutil.FindFile("tools/gvisor2pcap/wget6.log")
	if err != nil {
		t.Fatalf("couldn't get log path: %v", err)
	}

	testBinary(t, packetLogFile, tempDir)
}

// allowedErrors matches output for packets that are known to be unhandled.
var allowedErrors = regexp.MustCompile("unhandled protocol (udp|arp|icmp)")

// testBinary runs gvisor2pcap with an input and checks that packets are either
// handled or in the set of known unhandled packet types.
func testBinary(t *testing.T, inputPath, outDir string) {
	// Run gvisor2pcap.
	gvisor2pcap, err := testutil.FindFile("tools/gvisor2pcap/gvisor2pcap")
	if err != nil {
		t.Fatalf("couldn't get binary: %v", err)
	}

	tempOut := path.Join(outDir, "out.pcap")
	cmd := exec.Command(gvisor2pcap, "--out", tempOut, "--in", inputPath)
	binaryOutput, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("couldn't start command %v: %v: %v", cmd, err, string(binaryOutput))
	}

	// Ensure we generated an output file.
	if output, err := os.ReadFile(tempOut); err != nil {
		t.Errorf("couldn't read output file %q: %v", tempOut, err)
	} else if len(output) == 0 {
		t.Errorf("generated no output in %q", tempOut)
	}

	for _, line := range strings.Split(string(binaryOutput), "\n") {
		if len(line) > 0 && !allowedErrors.MatchString(line) {
			t.Errorf("unexpected error output: %q", line)
		}
	}
}
