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

package tcp_send_window_sizes_piggyback_test

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

// TestSendWindowSizesPiggyback tests cases where segment sizes are close to
// sender window size and checks for ACK piggybacking for each of those case.
func TestSendWindowSizesPiggyback(t *testing.T) {
	sampleData := []byte("Sample Data")
	segmentSize := uint16(len(sampleData))
	// Advertise receive window sizes that are lesser, equal to or greater than
	// enqueued segment size and check for segment transmits. The test attempts
	// to enqueue a segment on the dut before acknowledging previous segment and
	// lets the dut piggyback any ACKs along with the enqueued segment.
	for _, tt := range []struct {
		description      string
		windowSize       uint16
		expectedPayload1 []byte
		expectedPayload2 []byte
		enqueue          bool
	}{
		// Expect the first segment to be split as it cannot be accomodated in
		// the sender window. This means we need not enqueue a new segment after
		// the first segment.
		{"WindowSmallerThanSegment", segmentSize - 1, sampleData[:(segmentSize - 1)], sampleData[(segmentSize - 1):], false /* enqueue */},

		{"WindowEqualToSegment", segmentSize, sampleData, sampleData, true /* enqueue */},

		// Expect the second segment to not be split as its size is greater than
		// the available sender window size. The segments should not be split
		// when there is pending unacknowledged data and the segment-size is
		// greater than available sender window.
		{"WindowGreaterThanSegment", segmentSize + 1, sampleData, sampleData, true /* enqueue */},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
			defer dut.Close(t, listenFd)

			conn := dut.Net.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort, WindowSize: testbench.Uint16(tt.windowSize)}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close(t)

			conn.Connect(t)
			acceptFd, _ := dut.Accept(t, listenFd)
			defer dut.Close(t, acceptFd)

			dut.SetSockOptInt(t, acceptFd, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)

			expectedTCP := testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh)}

			dut.Send(t, acceptFd, sampleData, 0)
			expectedPayload := testbench.Payload{Bytes: tt.expectedPayload1}
			if _, err := conn.ExpectData(t, &expectedTCP, &expectedPayload, time.Second); err != nil {
				t.Fatalf("expected payload was not received: %s", err)
			}

			// Expect any enqueued segment to be transmitted by the dut along with
			// piggybacked ACK for our data.

			if tt.enqueue {
				// Enqueue a segment for the dut to transmit.
				dut.Send(t, acceptFd, sampleData, 0)
			}

			// Send ACK for the previous segment along with data for the dut to
			// receive and ACK back. Sending this ACK would make room for the dut
			// to transmit any enqueued segment.
			conn.Send(t, testbench.TCP{Flags: testbench.TCPFlags(header.TCPFlagAck | header.TCPFlagPsh), WindowSize: testbench.Uint16(tt.windowSize)}, &testbench.Payload{Bytes: sampleData})

			// Expect the dut to piggyback the ACK for received data along with
			// the segment enqueued for transmit.
			expectedPayload = testbench.Payload{Bytes: tt.expectedPayload2}
			if _, err := conn.ExpectData(t, &expectedTCP, &expectedPayload, time.Second); err != nil {
				t.Fatalf("expected payload was not received: %s", err)
			}
		})
	}
}
