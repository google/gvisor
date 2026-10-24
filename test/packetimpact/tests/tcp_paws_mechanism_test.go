// Copyright 2020 The gVisor Authors.
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

package tcp_paws_mechanism_test

import (
	"encoding/hex"
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestPAWSMechanism(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	const sentTSVal uint32 = 1000
	options := make([]byte, header.TCPOptionTSLength)
	header.EncodeTSOption(sentTSVal, 0, options)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn), Options: options})
	synAck, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("didn't get synack during handshake: %s", err)
	}
	parsedSynOpts := header.ParseSynOptions(synAck.Options, true)
	if !parsedSynOpts.TS {
		t.Fatalf("expected TSOpt from DUT, options we got:\n%s", hex.Dump(synAck.Options))
	}
	tsecr := parsedSynOpts.TSVal
	// A stale final ACK must not complete the handshake. The challenge ACK
	// proves it was processed before checking the listener's readiness.
	header.EncodeTSOption(sentTSVal-1, tsecr, options)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: options})
	if _, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second); err != nil {
		t.Fatalf("expected an ACK rejecting the stale handshake timestamp: %s", err)
	}
	if got := dut.Poll(t, []unix.PollFd{{Fd: listenFD, Events: unix.POLLIN}}, 0); len(got) != 0 {
		t.Fatalf("listener became readable after stale handshake ACK: %v", got)
	}
	header.EncodeTSOption(sentTSVal, tsecr, options)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: options})
	acceptFD, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFD)

	sampleData := []byte("Sample Data")
	header.EncodeTSOption(sentTSVal, tsecr, options)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: options}, &testbench.Payload{Bytes: sampleData})

	gotTCP, err := conn.Expect(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected an ACK but got none: %s", err)
	}

	parsedOpts := header.ParseTCPOptions(gotTCP.Options)
	if !parsedOpts.TS {
		t.Fatalf("expected TS option in response, options we got:\n%s", hex.Dump(gotTCP.Options))
	}
	if parsedOpts.TSVal < tsecr {
		t.Fatalf("TSVal should be non-decreasing, but %d < %d", parsedOpts.TSVal, tsecr)
	}
	if parsedOpts.TSEcr != sentTSVal {
		t.Fatalf("TSEcr should match our sent TSVal, %d != %d", parsedOpts.TSEcr, sentTSVal)
	}
	tsecr = parsedOpts.TSVal
	lastAckNum := gotTCP.AckNum

	badTSVal := sentTSVal - 100
	header.EncodeTSOption(badTSVal, tsecr, options)
	conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck), Options: options}, &testbench.Payload{Bytes: sampleData})

	gotTCP, err = conn.Expect(t, testbench.TCP{AckNum: lastAckNum, Flags: testbench.TCPFlags(header.TCPFlagAck)}, time.Second)
	if err != nil {
		t.Fatalf("expected segment with AckNum %d but got none: %s", lastAckNum, err)
	}
	parsedOpts = header.ParseTCPOptions(gotTCP.Options)
	if !parsedOpts.TS {
		t.Fatalf("expected TS option in response, options we got:\n%s", hex.Dump(gotTCP.Options))
	}
	if parsedOpts.TSVal < tsecr {
		t.Fatalf("TSVal should be non-decreasing, but %d < %d", parsedOpts.TSVal, tsecr)
	}
	if parsedOpts.TSEcr != sentTSVal {
		t.Fatalf("TSEcr should match our sent TSVal, %d != %d", parsedOpts.TSEcr, sentTSVal)
	}

	// Unlike stale data, a reset with an acceptable sequence number must
	// close the connection even if its timestamp is old (RFC 7323, 5.2).
	conn.Send(t, testbench.TCP{SeqNum: lastAckNum, Flags: testbench.TCPFlags(header.TCPFlagRst), Options: options})
	dut.PollOne(t, acceptFD, unix.POLLERR, time.Second)
	if got, want := dut.GetSockOptInt(t, acceptFD, unix.SOL_SOCKET, unix.SO_ERROR), int32(unix.ECONNRESET); got != want {
		t.Fatalf("SO_ERROR = %d, want %d", got, want)
	}
}
