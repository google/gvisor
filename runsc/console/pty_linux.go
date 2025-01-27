// Copyright 2023 The gVisor Authors.
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

//go:build linux
// +build linux

package console

import (
	"os"

	"golang.org/x/sys/unix"
)

// StdioIsPty returns true if all stdio FDs are ptys.
func StdioIsPty() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if _, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS); err != nil {
			return false
		}
	}
	return true
}
