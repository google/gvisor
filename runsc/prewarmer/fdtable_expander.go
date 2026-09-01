// Copyright 2026 The gVisor Authors.
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

// Binary `fdtable_expander` successively forces the kernel to expand this
// process's FD table through the sizes that `gvisor-sentry-prewarmer` is
// meant to have already paid for:
// - 64 slots (the kernel default, should be a no-op but who knows)
// - 128
// - 256
// See `prewarmer.c` for the underlying kernel details that make this worth
// testing.
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func main() {
	for _, target := range []int{63, 127, 255} {
		if err := unix.Dup3(0, target, unix.O_CLOEXEC); err != nil {
			fmt.Fprintf(os.Stderr, "fdtable_expander: dup3(0, %d) failed: %v\n", target, err)
			os.Exit(1)
		}
	}
}
