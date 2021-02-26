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

package tcp_zero_window_probe_retransmit_test

import (
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

// TestZeroWindowProbeRetransmit tests retransmits of zero window probes
// to be sent at exponentially inreasing time intervals.
func TestZeroWindowProbeRetransmit(t *testing.T) {
	dut := testbench.NewDUT(t)
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	acceptFd, _ := dut.Accept(t, listenFd)
	defer dut.Close(t, acceptFd)

	dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

	sampleData := []byte("Sample Data")
	samplePayload := &testbench.Payload{Bytes: sampleData}

	// Send and receive sample data to the dut.
	dut.Send(t, acceptFd, sampleData, 0)
	if _, err := conn.ExpectData(t, &testbench.TCP{}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck | header.TCPFlagPsh)}, samplePayload)
	if _, err := conn.ExpectData(t, &testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, nil, time.Second); err != nil {
		t.Fatalf("expected packet was not received: %s", err)
	}

	// Check for the dut to keep the connection alive as long as the zero window
	// probes are acknowledged. Check if the zero window probes are sent at
	// exponentially increasing intervals. The timeout intervals are function
	// of the recorded first zero probe transmission duration.
	//
	// Advertize zero receive window again.
	conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck), WindowSize: testbench.Uint16(0)})
	probeSeq := testbench.Uint32(uint32(*conn.RemoteSeqNum(t) - 1))
	ackProbe := testbench.Uint32(uint32(*conn.RemoteSeqNum(t)))

	// Ask the dut to send out data.
	dut.Send(t, acceptFd, sampleData, 0)

	var prev time.Duration
	// Expect the dut to keep the connection alive as long as the remote is
	// acknowledging the zero-window probes.
	for i := 1; i <= 5; i++ {
		start := time.Now()
		// Expect zero-window probe with a timeout which is a function of the typical
		// first retransmission time. The retransmission times is supposed to
		// exponentially increase.
		if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: probeSeq}, nil, time.Duration(i)*time.Second); err != nil {
			t.Fatalf("%d: expected a probe with sequence number %d: %s", i, probeSeq, err)
		}
		if i == 1 {
			// Skip the first probe as computing transmit time for that is
			// non-deterministic because of the arbitrary time taken for
			// the dut to receive a send command and issue a send.
			continue
		}

		// Check if the time taken to receive the probe from the dut is
		// increasing exponentially. To avoid flakes, use a correction
		// factor for the expected duration which accounts for any
		// scheduling non-determinism.
		const timeCorrection = 200 * time.Millisecond
		got := time.Since(start)
		if want := (2 * prev) - timeCorrection; prev != 0 && got < want {
			t.Errorf("got zero probe %d after %s, want >= %s", i, got, want)
		}
		prev = got
		// Acknowledge the zero-window probes from the dut.
		conn.Send(t, testbench.TCP{AckNum: ackProbe, Flags: testbench.Uint8(header.TCPFlagAck), WindowSize: testbench.Uint16(0)})
	}
	// Advertize non-zero window.
	conn.Send(t, testbench.TCP{AckNum: ackProbe, Flags: testbench.Uint8(header.TCPFlagAck)})
	// Expect the dut to recover and transmit data.
	if _, err := conn.ExpectData(t, &testbench.TCP{SeqNum: ackProbe}, samplePayload, time.Second); err != nil {
		t.Fatalf("expected payload was not received: %s", err)
	}
}
