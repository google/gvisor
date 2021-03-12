// Copyright 2021 The gVisor Authors.
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
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// measure prints the hash of path to stdout.
func measure(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var digest digest
	digest.metadata.DigestSize = maxDigestSize
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), uintptr(linux.FS_IOC_MEASURE_VERITY), uintptr(unsafe.Pointer(&digest))); err != 0 {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s\n", hex.EncodeToString(digest.digest[:digest.metadata.DigestSize]))
	return err
}
