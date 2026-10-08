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

//go:build amd64
// +build amd64

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// ArchPrctl implements linux syscall arch_prctl(2).
// It sets architecture-specific process or thread state for t.
func ArchPrctl(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	switch args[0].Int() {
	case linux.ARCH_GET_FS:
		addr := args[1].Pointer()
		fsbase := t.Arch().TLS()
		switch t.Arch().Width() {
		case 8:
			if _, err := primitive.CopyUint64Out(t, addr, uint64(fsbase)); err != nil {
				return 0, nil, err
			}
		default:
			return 0, nil, linuxerr.ENOSYS
		}
	case linux.ARCH_SET_FS:
		fsbase := args[1].Uint64()
		if !t.Arch().SetTLS(uintptr(fsbase)) {
			return 0, nil, linuxerr.EPERM
		}
	case linux.ARCH_GET_GS:
		addr := args[1].Pointer()
		gsbase := t.Arch().GS()
		switch t.Arch().Width() {
		case 8:
			if _, err := primitive.CopyUint64Out(t, addr, uint64(gsbase)); err != nil {
				return 0, nil, err
			}
		default:
			return 0, nil, linuxerr.ENOSYS
		}
	case linux.ARCH_SET_GS:
		gsbase := args[1].Uint64()
		if err := t.UserModifiedGS(); err != nil {
			return 0, nil, err
		}
		if !t.Arch().SetGS(uintptr(gsbase)) {
			return 0, nil, linuxerr.EPERM
		}
	case linux.ARCH_GET_XCOMP_SUPP:
		supp := t.Kernel().FeatureSet().ValidXCR0Mask()
		if _, err := primitive.CopyUint64Out(t, args[1].Pointer(), supp); err != nil {
			return 0, nil, err
		}
	case linux.ARCH_GET_XCOMP_PERM:
		// XTILEDATA is the only dynamic feature; all others are always permitted.
		perm := t.Kernel().FeatureSet().ValidXCR0Mask()&^cpuid.XCR0AmxDataMask | t.XcompPerm()
		if _, err := primitive.CopyUint64Out(t, args[1].Pointer(), perm); err != nil {
			return 0, nil, err
		}
	case linux.ARCH_REQ_XCOMP_PERM:
		switch idx := args[1].Uint64(); {
		case idx > linux.XFEATURE_XTILEDATA:
			return 0, nil, linuxerr.EINVAL
		case idx != linux.XFEATURE_XTILEDATA:
			return 0, nil, linuxerr.EOPNOTSUPP
		}
		if t.Kernel().FeatureSet().ValidXCR0Mask()&cpuid.XCR0AmxDataMask == 0 {
			return 0, nil, linuxerr.EOPNOTSUPP
		}
		t.GrantXcompPerm(cpuid.XCR0AmxDataMask)
	default:
		return 0, nil, linuxerr.EINVAL
	}

	return 0, nil, nil
}
