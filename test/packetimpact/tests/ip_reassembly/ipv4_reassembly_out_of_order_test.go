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

package ipv4_reassembly_out_of_order_test

import (
	"flag"
	"testing"

	"gvisor.dev/gvisor/test/packetimpact/testbench"
	"gvisor.dev/gvisor/test/packetimpact/tests/ip_reassembly/common"
	"gvisor.dev/gvisor/test/packetimpact/tests/ip_reassembly/ipv4"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

func TestIPv4FragmentReassembly(t *testing.T) {
	t.Run(common.OutOfOrder.Description, func(t *testing.T) {
		ipv4.Run(t, common.Basic)
	})
}
