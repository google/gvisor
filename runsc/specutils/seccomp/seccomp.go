// Copyright 2020 The gVisor Authors.
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

// Package seccomp implements some features of libseccomp in order to support
// OCI.
package seccomp

import (
	"fmt"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
)

var (
	killThreadAction = linux.SECCOMP_RET_KILL_THREAD
	trapAction       = linux.SECCOMP_RET_TRAP
	// runc always returns EPERM as the errorcode for SECCOMP_RET_ERRNO
	errnoAction = linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(syscall.EPERM))
	// runc always returns EPERM as the errorcode for SECCOMP_RET_TRACE
	traceAction = linux.SECCOMP_RET_TRACE.WithReturnCode(uint16(syscall.EPERM))
	allowAction = linux.SECCOMP_RET_ALLOW
)

// BuildProgram generates a bpf program based on the given OCI seccomp
// config.
func BuildProgram(s *specs.LinuxSeccomp) (bpf.Program, error) {
	defaultAction, err := convertAction(s.DefaultAction)
	if err != nil {
		return bpf.Program{}, fmt.Errorf("secomp default action: %w", err)
	}
	ruleset, err := convertRules(s)
	if err != nil {
		return bpf.Program{}, fmt.Errorf("invalid seccomp rules: %w", err)
	}

	instrs, err := seccomp.BuildProgram(ruleset, defaultAction, killThreadAction)
	if err != nil {
		return bpf.Program{}, fmt.Errorf("building seccomp program: %w", err)
	}

	program, err := bpf.Compile(instrs)
	if err != nil {
		return bpf.Program{}, fmt.Errorf("compiling seccomp program: %w", err)
	}

	return program, nil
}

// lookupSyscallNo gets the syscall number for the syscall with the given name
// for the given architecture.
func lookupSyscallNo(arch uint32, name string) (uint32, error) {
	var table *kernel.SyscallTable
	switch arch {
	case linux.AUDIT_ARCH_X86_64:
		table = slinux.AMD64
	case linux.AUDIT_ARCH_AARCH64:
		table = slinux.ARM64
	}
	if table == nil {
		return 0, fmt.Errorf("unsupported architecture: %d", arch)
	}
	n, err := table.LookupNo(name)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// convertAction converts a LinuxSeccompAction to BPFAction
func convertAction(act specs.LinuxSeccompAction) (linux.BPFAction, error) {
	// TODO(gvisor.dev/issue/3124): Update specs package to include ActLog and ActKillProcess.
	switch act {
	case specs.ActKill:
		return killThreadAction, nil
	case specs.ActTrap:
		return trapAction, nil
	case specs.ActErrno:
		return errnoAction, nil
	case specs.ActTrace:
		return traceAction, nil
	case specs.ActAllow:
		return allowAction, nil
	default:
		return 0, fmt.Errorf("invalid action: %v", act)
	}
}

// convertRules converts OCI linux seccomp rules into RuleSets that can be used by
// the seccomp package to build a seccomp program.
func convertRules(s *specs.LinuxSeccomp) ([]seccomp.RuleSet, error) {
	// NOTE: Architectures are only really relevant when calling 32bit syscalls
	// on a 64bit system. Since we don't support that in gVisor anyway, we
	// ignore Architectures and only test against the native architecture.

	ruleset := []seccomp.RuleSet{}

	for _, syscall := range s.Syscalls {
		sysRules := seccomp.NewSyscallRules()

		action, err := convertAction(syscall.Action)
		if err != nil {
			return nil, err
		}

		// Args
		rules, err := convertArgs(syscall.Args)
		if err != nil {
			return nil, err
		}

		for _, name := range syscall.Names {
			syscallNo, err := lookupSyscallNo(nativeArchAuditNo, name)
			if err != nil {
				// If there is an error looking up the syscall number, assume it is
				// not supported on this architecture and ignore it. This is, for
				// better or worse, what runc does.
				log.Warningf("OCI seccomp: ignoring syscall %q", name)
				continue
			}

			for _, rule := range rules {
				sysRules.AddRule(uintptr(syscallNo), rule)
			}
		}

		ruleset = append(ruleset, seccomp.RuleSet{
			Rules:  sysRules,
			Action: action,
		})
	}

	return ruleset, nil
}

// convertArgs converts an OCI seccomp argument rule to a list of seccomp.Rule.
func convertArgs(args []specs.LinuxSeccompArg) ([]seccomp.Rule, error) {
	argCounts := make([]uint, 6)

	for _, arg := range args {
		if arg.Index > 6 {
			return nil, fmt.Errorf("invalid index: %d", arg.Index)
		}

		argCounts[arg.Index]++
	}

	// NOTE: If multiple rules apply to the same argument (same index) the
	// action is triggered if any one of the rules matches (OR). If not, then
	// all rules much match in order to trigger the action (AND). This appears to
	// be some kind of legacy behavior of runc that nevertheless needs to be
	// supported to maintain compatibility.

	hasMultipleArgs := false
	for _, count := range argCounts {
		if count > 1 {
			hasMultipleArgs = true
			break
		}
	}

	if hasMultipleArgs {
		rules := []seccomp.Rule{}

		// Old runc behavior - do this for compatibility.
		// Add rules as ORs by adding separate Rules.
		for _, arg := range args {
			rule := seccomp.Rule{nil, nil, nil, nil, nil, nil}

			if err := convertRule(arg, &rule); err != nil {
				return nil, err
			}

			rules = append(rules, rule)
		}

		return rules, nil
	}

	// Add rules as ANDs by adding to the same Rule.
	rule := seccomp.Rule{nil, nil, nil, nil, nil, nil}
	for _, arg := range args {
		if err := convertRule(arg, &rule); err != nil {
			return nil, err
		}
	}

	return []seccomp.Rule{rule}, nil
}

// convertRule converts and adds the arg to a rule.
func convertRule(arg specs.LinuxSeccompArg, rule *seccomp.Rule) error {
	switch arg.Op {
	case specs.OpEqualTo:
		rule[arg.Index] = seccomp.EqualTo(arg.Value)
	case specs.OpNotEqual:
		rule[arg.Index] = seccomp.NotEqual(arg.Value)
	case specs.OpGreaterThan:
		rule[arg.Index] = seccomp.GreaterThan(arg.Value)
	case specs.OpGreaterEqual:
		rule[arg.Index] = seccomp.GreaterThanOrEqual(arg.Value)
	case specs.OpLessThan:
		rule[arg.Index] = seccomp.LessThan(arg.Value)
	case specs.OpLessEqual:
		rule[arg.Index] = seccomp.LessThanOrEqual(arg.Value)
	case specs.OpMaskedEqual:
		rule[arg.Index] = seccomp.MaskedEqual(uintptr(arg.Value), uintptr(arg.ValueTwo))
	default:
		return fmt.Errorf("unsupported operand: %q", arg.Op)
	}
	return nil
}
