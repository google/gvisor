// Copyright 2018 Google LLC
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

package boot

import (
	"fmt"

	rpb "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto"
)

// cmdTracker reports only a single time for each different command argument in
// the syscall. It's used for generic syscalls like ioctl to report once per
// 'cmd'
type cmdTracker struct {
	// argIdx is the syscall argument index where the command is located.
	argIdx int
	cmds   map[uint32]struct{}
}

func newCmdTracker(argIdx int) *cmdTracker {
	return &cmdTracker{argIdx: argIdx, cmds: make(map[uint32]struct{})}
}

// cmd returns the command based on the syscall argument index.
func (c *cmdTracker) cmd(regs *rpb.AMD64Registers) uint32 {
	switch c.argIdx {
	case 0:
		return uint32(regs.Rdi)
	case 1:
		return uint32(regs.Rsi)
	}
	panic(fmt.Sprintf("unsupported syscall argument index %d", c.argIdx))
}

func (c *cmdTracker) shouldReport(regs *rpb.AMD64Registers) bool {
	_, ok := c.cmds[c.cmd(regs)]
	return !ok
}

func (c *cmdTracker) onReported(regs *rpb.AMD64Registers) {
	c.cmds[c.cmd(regs)] = struct{}{}
}
