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

package icmpv6_param_problem_test

import (
	"encoding/binary"
	"flag"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.Initialize(flag.CommandLine)
}

// TestICMPv6ParamProblemTest sends a packet with a bad next header. The DUT
// should respond with an ICMPv6 Parameter Problem message.
func TestICMPv6ParamProblemTest(t *testing.T) {
	dut := testbench.NewDUT(t)
	conn := dut.Net.NewIPv6Conn(t, testbench.IPv6{}, testbench.IPv6{})
	defer conn.Close(t)
	ipv6 := testbench.IPv6{
		// 254 is reserved and used for experimentation and testing. This should
		// cause an error.
		NextHeader: testbench.Uint8(254),
	}
	icmpv6 := testbench.ICMPv6{
		Type:    testbench.ICMPv6Type(header.ICMPv6EchoRequest),
		Payload: []byte("hello world"),
	}

	toSend := conn.CreateFrame(t, testbench.Layers{&ipv6}, &icmpv6)
	conn.SendFrame(t, toSend)

	// Build the expected ICMPv6 payload, which includes an index to the
	// problematic byte and also the problematic packet as described in
	// https://tools.ietf.org/html/rfc4443#page-12 .
	ipv6Sent := toSend[1:]
	expectedPayload, err := ipv6Sent.ToBytes()
	if err != nil {
		t.Fatalf("can't convert %s to bytes: %s", ipv6Sent, err)
	}

	// The problematic field is the NextHeader.
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, header.IPv6NextHeaderOffset)
	expectedPayload = append(b, expectedPayload...)
	expectedICMPv6 := testbench.ICMPv6{
		Type:    testbench.ICMPv6Type(header.ICMPv6ParamProblem),
		Payload: expectedPayload,
	}

	paramProblem := testbench.Layers{
		&testbench.Ether{},
		&testbench.IPv6{},
		&expectedICMPv6,
	}
	timeout := time.Second
	if _, err := conn.ExpectFrame(t, paramProblem, timeout); err != nil {
		t.Errorf("expected %s within %s but got none: %s", paramProblem, timeout, err)
	}
}
