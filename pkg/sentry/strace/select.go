// Copyright 2019 The gVisor Authors.
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

package strace

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/syscalls/linux"

	"gvisor.dev/gvisor/pkg/hostarch"
)

func fdsFromSet(t *kernel.Task, set []byte) []int {
	var fds []int
	// Append n if the n-th bit is 1.
	for i, v := range set {
		for j := 0; j < 8; j++ {
			if (v>>j)&1 == 1 {
				fds = append(fds, i*8+j)
			}
		}
	}
	return fds
}

func fdSet(t *kernel.Task, nfds int, addr hostarch.Addr) string {
	if nfds < 0 {
		return fmt.Sprintf("%#x (negative nfds)", addr)
	}
	if addr == 0 {
		return "null"
	}

	// Calculate the size of the fd set (one bit per fd).
	nBytes := (nfds + 7) / 8
	nBitsInLastPartialByte := nfds % 8

	set, err := linux.CopyInFDSet(t, addr, nBytes, nBitsInLastPartialByte)
	if err != nil {
		return fmt.Sprintf("%#x (error decoding fdset: %s)", addr, err)
	}

	return fmt.Sprintf("%#x %v", addr, fdsFromSet(t, set))
}
