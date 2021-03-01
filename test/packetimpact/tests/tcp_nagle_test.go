// Copyright 2021 The gVisor Authors.
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

package tcp_nagle_test

import (
	"flag"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

func TestTCPNagleMSS(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFD, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFD)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	const mss = uint32(header.TCPDefaultMSS)
	options := make([]byte, header.TCPOptionMSSLength)
	header.EncodeMSSOption(mss, options)
	conn.ConnectWithOptions(t, options)

	acceptFD, _ := dut.Accept(t, listenFD)
	defer dut.Close(t, acceptFD)

	payload := []byte("SampleData")
	dut.Send(t, acceptFD, payload, 0)
	expectedPayload := testbench.Payload{Bytes: payload}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagPsh | header.TCPFlagAck)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Packet < mss size will be help up.
	payload = []byte("SampleData")
	dut.Send(t, acceptFD, payload, 0)
	expectedData := payload

	// Send packet of size mss.
	largeData := make([]byte, mss)
	expectedData = append(expectedData, largeData...)
	dut.Send(t, acceptFD, largeData, 0)

	// Expect the coalesced packet of size mss.
	expectedPayload = testbench.Payload{Bytes: expectedData[:mss]}
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck)}, &expectedPayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}

	// Check all packets of size == mss are sent.
	seqNum1 := *conn.RemoteSeqNum(t)
	for i, sn := 0, seqNum1; i < 5; i++ {
		payload = make([]byte, mss)
		dut.Send(t, acceptFD, payload, 0)

		gotOne, err := conn.Expect(t, testbench.TCP{SeqNum: testbench.Uint32(uint32(sn))}, time.Second)
		if err != nil {
			t.Fatalf("Expect #%d: %s", i+1, err)
			continue
		}
		if gotOne == nil {
			t.Fatalf("#%d: expected a packet within a second but got none", i+1)
		}
		sn.UpdateForward(seqnum.Size(mss))
	}
}
