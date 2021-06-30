// Copyright 2018 The gVisor Authors.
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

// Uname implements linux syscall uname.
func Uname(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	version := t.SyscallTable().Version

	uts := t.UTSNamespace()

	// Fill in structure fields.
	var u linux.UtsName
	copy(u.Sysname[:], version.Sysname)
	copy(u.Nodename[:], uts.HostName())
	copy(u.Release[:], version.Release)
	copy(u.Version[:], version.Version)
	// build tag above.
	switch t.SyscallTable().Arch {
	case arch.AMD64:
		copy(u.Machine[:], "x86_64")
	case arch.ARM64:
		copy(u.Machine[:], "aarch64")
	default:
		copy(u.Machine[:], "unknown")
	}
	copy(u.Domainname[:], uts.DomainName())

	// Copy out the result.
	va := args[0].Pointer()
	_, err := u.CopyOut(t, va)
	return 0, nil, err
}

// Setdomainname implements Linux syscall setdomainname.
func Setdomainname(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nameAddr := args[0].Pointer()
	size := args[1].Int()

	utsns := t.UTSNamespace()
	if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, utsns.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}
	if size < 0 || size > linux.UTSLen {
		return 0, nil, linuxerr.EINVAL
	}

	name, err := t.CopyInString(nameAddr, int(size))
	if err != nil {
		return 0, nil, err
	}

	utsns.SetDomainName(name)
	return 0, nil, nil
}

// Sethostname implements Linux syscall sethostname.
func Sethostname(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nameAddr := args[0].Pointer()
	size := args[1].Int()

	utsns := t.UTSNamespace()
	if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, utsns.UserNamespace()) {
		return 0, nil, linuxerr.EPERM
	}
	if size < 0 || size > linux.UTSLen {
		return 0, nil, linuxerr.EINVAL
	}

	name := make([]byte, size)
	if _, err := t.CopyInBytes(nameAddr, name); err != nil {
		return 0, nil, err
	}

	utsns.SetHostName(string(name))
	return 0, nil, nil
}
