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

// +build amd64

package linux

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
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
	copy(u.Machine[:], "x86_64") // +build tag above.
	copy(u.Domainname[:], uts.DomainName())

	// Copy out the result.
	va := args[0].Pointer()
	_, err := t.CopyOut(va, u)
	return 0, nil, err
}

// Setdomainname implements Linux syscall setdomainname.
func Setdomainname(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	nameAddr := args[0].Pointer()
	size := args[1].Int()

	utsns := t.UTSNamespace()
	if !t.HasCapabilityIn(linux.CAP_SYS_ADMIN, utsns.UserNamespace()) {
		return 0, nil, syserror.EPERM
	}
	if size < 0 || size > linux.UTSLen {
		return 0, nil, syserror.EINVAL
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
		return 0, nil, syserror.EPERM
	}
	if size < 0 || size > linux.UTSLen {
		return 0, nil, syserror.EINVAL
	}

	name, err := t.CopyInString(nameAddr, int(size))
	if err != nil {
		return 0, nil, err
	}

	utsns.SetHostName(name)
	return 0, nil, nil
}
