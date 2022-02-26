// Copyright 2022 The gVisor Authors.
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

// Package hostos contains utility functions for getting information about the host OS.
package hostos

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// KernelVersion returns the major and minor release version of the kernel using uname().
func KernelVersion() (int, int, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return 0, 0, err
	}

	var sb strings.Builder
	for _, b := range u.Release {
		if b == 0 {
			break
		}
		sb.WriteByte(byte(b))
	}

	s := strings.Split(sb.String(), ".")
	if len(s) < 2 {
		return 0, 0, fmt.Errorf("kernel release missing major and minor component: %s", sb.String())
	}

	major, err := strconv.Atoi(s[0])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing major version %q in %q: %w", s[0], sb.String(), err)
	}

	minor, err := strconv.Atoi(s[1])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing minor version %q in %q: %w", s[1], sb.String(), err)
	}

	return major, minor, nil
}
