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

// Package filter_bench_test benchmarks the speed of the seccomp-bpf filters.
package filter_bench_test

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/runsc/boot/filter"
	"gvisor.dev/gvisor/test/secbench"
	"gvisor.dev/gvisor/test/secbench/secbenchdef"
)

type Options struct {
	Name    string
	Options filter.Options
}

// BenchmarkSentrySystrap benchmarks the seccomp filters used by the Sentry
// using the Systrap platform.
func BenchmarkSentrySystrap(b *testing.B) {
	rules, denyRules := filter.Rules(filter.Options{
		Platform: &systrap.Systrap{},
	})
	secbench.Run(b, secbench.BenchFromSyscallRules(
		b,
		"Postgres",
		secbenchdef.Profile{
			Arch: linux.AUDIT_ARCH_X86_64,
			Sequences: []secbenchdef.Sequence{
				// Top 10 syscalls captured by running Postgres in a runsc container
				// and running `pgbench` against it. Weights are the number of times
				// each syscall was called.
				{"futex", 870063, secbenchdef.Single(unix.SYS_FUTEX, 0, linux.FUTEX_WAKE)},
				{"nanosleep", 275649, secbenchdef.NanosleepZero.Seq()},
				{"sendmmsg", 160201, secbenchdef.Single(unix.SYS_SENDMMSG, secbenchdef.NonExistentFD, 0, 0, unix.MSG_DONTWAIT)},
				{"fstat", 115769, secbenchdef.Single(unix.SYS_FSTAT, secbenchdef.NonExistentFD)},
				{"ppoll", 69749, secbenchdef.PPollNonExistent.Seq()},
				{"fsync", 23131, secbenchdef.Single(unix.SYS_FSYNC, secbenchdef.NonExistentFD)},
				{"pwrite64", 14096, secbenchdef.Single(unix.SYS_PWRITE64, secbenchdef.NonExistentFD)},
				{"epoll_pwait", 12266, secbenchdef.Single(unix.SYS_EPOLL_PWAIT, secbenchdef.NonExistentFD)},
				{"close", 1991, secbenchdef.Single(unix.SYS_CLOSE, secbenchdef.NonExistentFD)},
				{"getpid", 1413, secbenchdef.Single(unix.SYS_GETPID)},
			},
		},
		rules,
		denyRules,
	))
}

// BenchmarkSentryKVM benchmarks the seccomp filters used by the Sentry
// using the KVM platform.
func BenchmarkSentryKVM(b *testing.B) {
	rules, denyRules := filter.Rules(filter.Options{
		Platform: &kvm.KVM{},
	})
	secbench.Run(b, secbench.BenchFromSyscallRules(
		b,
		"Postgres",
		secbenchdef.Profile{
			Arch: linux.AUDIT_ARCH_X86_64,
			Sequences: []secbenchdef.Sequence{
				// Same procedure, but using the KVM platform instead.
				{"futex", 3180352, secbenchdef.Single(unix.SYS_FUTEX, 0, linux.FUTEX_WAKE)},
				{"ioctl", 2501786, secbenchdef.Single(unix.SYS_IOCTL, secbenchdef.NonExistentFD, kvm.KVM_RUN)},
				{"rt_sigreturn", 2501695, secbenchdef.RTSigreturn.Seq()},
				{"sendmmsg", 1490395, secbenchdef.Single(unix.SYS_SENDMMSG, secbenchdef.NonExistentFD, 0, 0, unix.MSG_DONTWAIT)},
				{"nanosleep", 1217019, secbenchdef.NanosleepZero.Seq()},
				{"fstat", 1068477, secbenchdef.Single(unix.SYS_FSTAT, secbenchdef.NonExistentFD)},
				{"ppoll", 653137, secbenchdef.PPollNonExistent.Seq()},
				{"fsync", 213320, secbenchdef.Single(unix.SYS_FSYNC, secbenchdef.NonExistentFD)},
				{"pwrite64", 107603, secbenchdef.Single(unix.SYS_PWRITE64, secbenchdef.NonExistentFD)},
				{"epoll_pwait", 29909, secbenchdef.Single(unix.SYS_EPOLL_PWAIT, secbenchdef.NonExistentFD)},
			},
		},
		rules,
		denyRules,
	))
}

func BenchmarkNVProxyIoctl(b *testing.B) {
	rules, denyRules := filter.Rules(filter.Options{
		Platform: &systrap.Systrap{},
		NVProxy:  true,
	})
	ioctlsRule := rules.Get(unix.SYS_IOCTL)
	if ioctlsRule == nil {
		b.Fatalf("ioctl rule is not defined")
	}
	ioctlOr, isOr := ioctlsRule.(seccomp.Or)
	if !isOr {
		b.Fatalf("ioctl rule is not an Or rule")
	}
	sequences := make([]secbenchdef.Sequence, 0, len(ioctlOr))
	var processOrRule func(seccomp.Or)
	processOrRule = func(orRule seccomp.Or) {
		for _, ioctlRule := range orRule {
			if orSubRule, isOr := ioctlRule.(seccomp.Or); isOr {
				processOrRule(orSubRule)
				continue
			}
			perArg, isPerArg := ioctlRule.(seccomp.PerArg)
			if !isPerArg {
				b.Fatalf("ioctl sub-rule %v (type: %T) is not a PerArg rule", ioctlRule, ioctlRule)
			}
			if perArg[1] == nil {
				b.Fatalf("ioctl sub-rule %v does not have any rule for arg[1]", perArg)
			}
			arg1Equal, isEqual := perArg[1].(seccomp.EqualTo)
			if !isEqual {
				continue
			}
			sequences = append(sequences, secbenchdef.Sequence{
				Name:     fmt.Sprintf("ioctl_%d", arg1Equal),
				Weight:   1,
				Syscalls: secbenchdef.Single(unix.SYS_IOCTL, 0, uintptr(arg1Equal)),
			})
		}
	}
	processOrRule(ioctlOr)
	secbench.Run(b, secbench.BenchFromSyscallRules(
		b,
		"nvproxy",
		secbenchdef.Profile{
			Arch:      linux.AUDIT_ARCH_X86_64,
			Sequences: sequences,
		},
		rules,
		denyRules,
	))
}
