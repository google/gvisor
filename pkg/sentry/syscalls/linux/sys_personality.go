// Copyright 2024 The gVisor Authors.
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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

const (
	// getPersonality may be passed to `personality(2)` to get the current
	// personality bits without modifying them.
	getPersonality = 0xffffffff
)

// Personality implements Linux syscall personality(2).
func Personality(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// allowedPersonalityBits are the personality bits that are allowed to be set.
	const allowedPersonalityBits = linux.PER_LINUX | linux.PER_BSD | linux.SHORT_INODE | linux.WHOLE_SECONDS

	personality := args[0].Uint()
	if personality == getPersonality {
		return uintptr(t.Personality()), nil, nil
	}
	if personality&allowedPersonalityBits != personality {
		return 0, nil, linuxerr.EINVAL
	}
	return uintptr(t.SetPersonality(personality)), nil, nil
}
