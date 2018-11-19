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

// reportLimit is the max number of events that should be reported per tracker.
const reportLimit = 100

// argsTracker reports only once for each different combination of arguments.
// It's used for generic syscalls like ioctl to report once per 'cmd'.
type argsTracker struct {
	// argsIdx is the syscall arguments to use as unique ID.
	argsIdx  []int
	reported map[string]struct{}
	count    int
}

func newArgsTracker(argIdx ...int) *argsTracker {
	return &argsTracker{argsIdx: argIdx, reported: make(map[string]struct{})}
}

// cmd returns the command based on the syscall argument index.
func (a *argsTracker) key(regs *rpb.AMD64Registers) string {
	var rv string
	for _, idx := range a.argsIdx {
		rv += fmt.Sprintf("%d|", argVal(idx, regs))
	}
	return rv
}

func argVal(argIdx int, regs *rpb.AMD64Registers) uint32 {
	switch argIdx {
	case 0:
		return uint32(regs.Rdi)
	case 1:
		return uint32(regs.Rsi)
	case 2:
		return uint32(regs.Rdx)
	case 3:
		return uint32(regs.R10)
	case 4:
		return uint32(regs.R8)
	case 5:
		return uint32(regs.R9)
	}
	panic(fmt.Sprintf("invalid syscall argument index %d", argIdx))
}

func (a *argsTracker) shouldReport(regs *rpb.AMD64Registers) bool {
	if a.count >= reportLimit {
		return false
	}
	_, ok := a.reported[a.key(regs)]
	return !ok
}

func (a *argsTracker) onReported(regs *rpb.AMD64Registers) {
	a.count++
	a.reported[a.key(regs)] = struct{}{}
}
