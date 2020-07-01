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

package tcp_queue_receive_in_syn_sent_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

// TestQueueReceiveInSynSent tests receive behavior when the TCP state
// is SYN-SENT.
// It tests for 2 variants where the receive is blocked and:
// (1) we complete handshake and send sample data.
// (2) we send a TCP RST.
func TestQueueReceiveInSynSent(t *testing.T) {
	for _, tt := range []struct {
		description string
		reset       bool
	}{
		{description: "Send DATA", reset: false},
		{description: "Send RST", reset: true},
	} {
		t.Run(tt.description, func(t *testing.T) {
			dut := testbench.NewDUT(t)
			defer dut.TearDown()

			socket, remotePort := dut.CreateBoundSocket(unix.SOCK_STREAM, unix.IPPROTO_TCP, net.ParseIP(testbench.RemoteIPv4))
			conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
			defer conn.Close()

			sampleData := []byte("Sample Data")

			dut.SetNonBlocking(socket, true)
			if _, err := dut.ConnectWithErrno(context.Background(), socket, conn.LocalAddr()); !errors.Is(err, syscall.EINPROGRESS) {
				t.Fatalf("failed to bring DUT to SYN-SENT, got: %s, want EINPROGRESS", err)
			}
			if _, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagSyn)}, time.Second); err != nil {
				t.Fatalf("expected a SYN from DUT, but got none: %s", err)
			}

			if _, _, err := dut.RecvWithErrno(context.Background(), socket, int32(len(sampleData)), 0); err != syscall.Errno(unix.EWOULDBLOCK) {
				t.Fatalf("expected error %s, got %s", syscall.Errno(unix.EWOULDBLOCK), err)
			}

			// Test blocking read.
			dut.SetNonBlocking(socket, false)

			var wg sync.WaitGroup
			defer wg.Wait()
			wg.Add(1)
			var block sync.WaitGroup
			block.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
				defer cancel()

				block.Done()
				// Issue RECEIVE call in SYN-SENT, this should be queued for
				// process until the connection is established.
				n, buff, err := dut.RecvWithErrno(ctx, socket, int32(len(sampleData)), 0)
				if tt.reset {
					if err != syscall.Errno(unix.ECONNREFUSED) {
						t.Errorf("expected error %s, got %s", syscall.Errno(unix.ECONNREFUSED), err)
					}
					if n != -1 {
						t.Errorf("expected return value %d, got %d", -1, n)
					}
					return
				}
				if n == -1 {
					t.Errorf("failed to recv on DUT: %s", err)
				}
				if got := buff[:n]; !bytes.Equal(got, sampleData) {
					t.Errorf("received data doesn't match, got:\n%s, want:\n%s", hex.Dump(got), hex.Dump(sampleData))
				}
			}()

			// Wait for the goroutine to be scheduled and before it
			// blocks on endpoint receive.
			block.Wait()
			// The following sleep is used to prevent the connection
			// from being established before we are blocked on Recv.
			time.Sleep(100 * time.Millisecond)

			if tt.reset {
				conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagRst | header.TCPFlagAck)})
				return
			}

			// Bring the connection to Established.
			conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagSyn | header.TCPFlagAck)})
			if _, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected an ACK from DUT, but got none: %s", err)
			}

			// Send sample payload and expect an ACK.
			conn.Send(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, &testbench.Payload{Bytes: sampleData})
			if _, err := conn.Expect(testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, time.Second); err != nil {
				t.Fatalf("expected an ACK from DUT, but got none: %s", err)
			}
		})
	}
}
