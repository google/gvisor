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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/landlock"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

const landlockRulesetAttrV1Size = 8

// LandlockCreateRuleset implements Linux syscall landlock_create_ruleset(2).
func LandlockCreateRuleset(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	attrAddr := args[0].Pointer()
	size := args[1].Uint64()
	flags := args[2].Uint()

	if flags&linux.LANDLOCK_CREATE_RULESET_VERSION != 0 {
		if flags != linux.LANDLOCK_CREATE_RULESET_VERSION || attrAddr != 0 || size != 0 {
			return 0, nil, linuxerr.EINVAL
		}
		return linux.LANDLOCK_ABI_VERSION, nil, nil
	}
	if flags != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if attrAddr == 0 || size < landlockRulesetAttrV1Size {
		return 0, nil, linuxerr.EINVAL
	}

	var attr linux.LandlockRulesetAttr
	buf := t.CopyScratchBuffer(attr.SizeBytes())
	copySize := attr.SizeBytes()
	if size < uint64(attr.SizeBytes()) {
		copySize = int(size)
	}
	if _, err := t.CopyInBytes(attrAddr, buf[:copySize]); err != nil {
		return 0, nil, err
	}
	attr.UnmarshalUnsafe(buf)

	if attr.HandledAccessFS == 0 {
		return 0, nil, linuxerr.ENOMSG
	}
	if attr.HandledAccessFS&^linux.LANDLOCK_ACCESS_FS_V1 != 0 ||
		attr.HandledAccessNet != 0 ||
		attr.Scoped != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if size > uint64(attr.SizeBytes()) {
		return 0, nil, linuxerr.E2BIG
	}

	file, err := landlock.NewRulesetFD(t, t.Kernel().VFS(), linux.O_RDWR, attr.HandledAccessFS)
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)

	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{
		CloseOnExec: true,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}
