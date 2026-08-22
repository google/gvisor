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

package pinring

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// NewDisabledIOURing returns a new pin ring for donation to its holder.
// Created with `IORING_SETUP_R_DISABLED` and never enabled.
// It accepts no `io_uring` submissions. Only its FD table is ever used.
func NewDisabledIOURing() (*os.File, error) {
	params := linux.IOUringParams{Flags: linux.IORING_SETUP_R_DISABLED}
	ring, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup: %w", errno)
	}
	return os.NewFile(ring, "pin ring"), nil
}

// registerFiles pins `fds` into `ring`'s fixed-file table.
// Can only be called once per `io_uring` ring.
func registerFiles(ring int, fds []int32) error {
	if _, _, errno := unix.Syscall6(unix.SYS_IO_URING_REGISTER, uintptr(ring), linux.IORING_REGISTER_FILES, uintptr(unsafe.Pointer(&fds[0])), uintptr(len(fds)), 0, 0); errno != 0 {
		return fmt.Errorf("io_uring_register(IORING_REGISTER_FILES): %w", errno)
	}
	return nil
}
