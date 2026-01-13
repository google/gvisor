// Copyright 2025 The gVisor Authors.
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

package nftables

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/test/netutils"
)

// Add test cases here.
var validationTests = []TestCase{
	&JumpAndDropAll{},
}

func init() {
	for _, test := range validationTests {
		RegisterTestCase(test)
	}
}

// JumpAndDropAll is a test case that verifies that a jump to a chain with a drop rule works.
type JumpAndDropAll struct{ containerCase }

var _ TestCase = (*JumpAndDropAll)(nil)

// Name returns the name of the test case.
func (*JumpAndDropAll) Name() string {
	return "JumpAndDropAll"
}

// ContainerAction are the commands that are ran in the container.
func (*JumpAndDropAll) ContainerAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	tableName := "TABLE"
	cmds := [][]string{
		// Create a table: JUMP_TABLE.
		{"add", "table", "inet", tableName},
		// Create DROPS_ALL_CHAIN with drop rule.
		{"add", "chain", "inet", tableName, "DROPS_ALL_CHAIN", "{ drop; }"},
		// Create FORWARDS_TO_DROP_CHAIN with jump to DROPS_ALL_CHAIN rule.
		{"add", "chain", "inet", tableName, "FORWARDS_TO_DROP_CHAIN", "{ jump DROPS_ALL_CHAIN; }"},
		// Create BASE_CHAIN with accept all policy.
		{"add", "chain", "inet", tableName, "BASE_CHAIN", "{ type filter hook input priority 0; policy accept; }"},
		// Add rule to BASE_CHAIN to jump to FORWARDS_TO_DROP_CHAIN.
		{"add", "rule", "inet", tableName, "BASE_CHAIN", "jump", "FORWARDS_TO_DROP_CHAIN"},
	}
	// Run all the commands.
	for _, cmd := range cmds {
		if err := nftCmd(cmd); err != nil {
			return fmt.Errorf("nft cmd: %v, failed with error: %v", cmd, err)
		}
	}

	// Listen for all packets on dropPort.
	timedCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := netutils.ListenUDP(timedCtx, dropPort, ipv6); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("error reading: %v", err)
	}

	// At this point we know that reading timed out and never received a
	// packet.
	return nil
}

// LocalAction are the commands that are ran on the test runner.
func (*JumpAndDropAll) LocalAction(ctx context.Context, ip net.IP, ipv6 bool) error {
	return netutils.SendUDPLoop(ctx, ip, dropPort, ipv6)
}
