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

package udp_empty_send_test

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	tb "gvisor.dev/gvisor/test/packetimpact/testbench"
)

func TestUDPEmptySend(t *testing.T) {
	dut := tb.NewDUT(t)
	defer dut.TearDown()

	remoteFD, remotePort := dut.CreateBoundSocket(unix.SOCK_DGRAM, unix.IPPROTO_UDP, net.ParseIP("0.0.0.0"))
	defer dut.Close(remoteFD)

	conn := tb.NewUDPIPv4(t, tb.UDP{DstPort: &remotePort}, tb.UDP{SrcPort: &remotePort})
	defer conn.Close()

	dut.SendTo(remoteFD, nil, 0, conn.LocalAddr())
	if _, err := conn.Expect(tb.UDP{}, time.Second); err != nil {
		t.Fatalf("failed to receive empty UDP packet: %s", err)
	}
}
