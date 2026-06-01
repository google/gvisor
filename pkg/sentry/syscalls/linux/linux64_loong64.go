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

//go:build loong64
// +build loong64

package linux

import (
	"gvisor.dev/gvisor/pkg/abi"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/version"
)

// LOONG64 is the LoongArch64 syscall table. LoongArch uses the asm-generic
// syscall numbering, which is identical to arm64, so the handler map is
// reused directly from the ARM64 table; only the architecture identity and
// audit number differ. The arch-specific handlers (Clone, ArchPrctl, ...)
// referenced by that map resolve to the *_loong64.go implementations under
// this same build tag.
var LOONG64 = &kernel.SyscallTable{
	OS:   abi.Linux,
	Arch: arch.LOONGARCH64,
	Version: kernel.Version{
		Sysname: version.LinuxSysname,
		Release: version.LinuxRelease,
		Version: version.LinuxVersion,
	},
	AuditNumber: linux.AUDIT_ARCH_LOONGARCH64,
	Table:       ARM64.Table,
	Missing: func(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
		t.Kernel().EmitUnimplementedEvent(t, sysno)
		return 0, linuxerr.ENOSYS
	},
}

func init() {
	kernel.RegisterSyscallTable(LOONG64)
}
