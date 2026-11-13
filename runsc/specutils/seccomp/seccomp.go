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
	"math"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	slinux "gvisor.dev/gvisor/pkg/sentry/syscalls/linux"
)

var (
	killThreadAction = seccomp.KillThread
	trapAction       = seccomp.Trap
	// errnoAction is the default errno returned for SCMP_ACT_ERRNO when the
	// rule (or the profile's defaultErrnoRet) does not request a specific one,
	// matching runc's default.
	errnoAction = seccomp.ReturnError.Code(uint16(unix.EPERM))
	// traceAction is the default code returned for SCMP_ACT_TRACE when the
	// rule (or the profile's defaultErrnoRet) does not request a specific one,
	// matching runc's default.
	traceAction = seccomp.Trace.Code(uint16(unix.EPERM))
	allowAction = seccomp.Allow
	logAction   = seccomp.Log
)

// BuildFilter generates a seccomp filter based on the given OCI seccomp
// config.
func BuildFilter(s *specs.LinuxSeccomp) (kernel.SyscallFilter, error) {
	defaultAction, err := convertAction(s.DefaultAction, s.DefaultErrnoRet)
	if err != nil {
		return kernel.SyscallFilter{}, fmt.Errorf("seccomp default action: %w", err)
	}
	rules, err := convertRules(s)
	if err != nil {
		return kernel.SyscallFilter{}, fmt.Errorf("invalid seccomp rules: %w", err)
	}
	return buildFilter(rules, defaultAction)
}

// buildFilter generates a seccomp filter from the rules.
func buildFilter(rules []ociRule, defaultAction seccomp.Action) (kernel.SyscallFilter, error) {
	defaultBPFAction := defaultAction.BPF(linux.SECCOMP_RET_KILL_PROCESS)
	actions := syscallActions(rules, defaultBPFAction)
	// fixedAction returns the action that the filter holds for a syscall
	// number, if there is one.
	fixedAction := func(sysno uintptr) (linux.BPFAction, bool) {
		if sysno > sentry.MaxSyscallNum {
			return 0, false
		}
		sa, ok := actions[sysno]
		if !ok {
			return defaultBPFAction, true
		}
		return sa.action, sa.fixed
	}
	// The program only has the syscalls for which the filter evaluates it.
	program, err := buildProgram(rules, defaultAction, func(sysno uintptr) bool {
		_, fixed := fixedAction(sysno)
		return !fixed
	})
	if err != nil {
		return kernel.SyscallFilter{}, err
	}
	return kernel.NewSyscallFilterWithFixedActions(nativeArchAuditNo, program, func(sysno int32) (linux.BPFAction, bool) {
		return fixedAction(uintptr(sysno))
	}), nil
}

// buildProgram generates a BPF program from the rules for the syscall numbers
// that `include` selects.
func buildProgram(rules []ociRule, defaultAction seccomp.Action, include func(sysno uintptr) bool) (bpf.Program, error) {
	ruleSets := make([]seccomp.RuleSet, 0, len(rules))
	for _, r := range rules {
		sysRules := seccomp.NewSyscallRules()
		for _, sysno := range r.sysnos {
			if include(sysno) {
				sysRules.Add(sysno, r.rule)
			}
		}
		if sysRules.Size() == 0 {
			continue
		}
		ruleSets = append(ruleSets, seccomp.RuleSet{
			Rules:  sysRules,
			Action: r.action,
		})
	}

	prog := &seccomp.Program{
		RuleSets: ruleSets,
		Options: seccomp.ProgramOptions{
			DefaultAction: defaultAction,
			BadArchAction: killThreadAction,
		},
	}
	instrs, _, err := prog.Build()
	if err != nil {
		return bpf.Program{}, fmt.Errorf("building seccomp program: %w", err)
	}

	program, err := bpf.Compile(instrs, true /* optimize */)
	if err != nil {
		return bpf.Program{}, fmt.Errorf("compiling seccomp program: %w", err)
	}

	return program, nil
}

// syscallAction is the action of the rules for one syscall number.
type syscallAction struct {
	// action is the action of the first rule for the syscall.
	action linux.BPFAction

	// fixed is true if the result of the filter is independent of
	// syscall arguments.
	fixed bool

	// final is true if a rule matches all arguments. The rules after it
	// never match.
	final bool
}

// syscallActions returns the action of each syscall number in `rules`.
// The first matching rule gives the action of a syscall. `defaultAction`
// applies when no rule matches. `seccomp.Program` applies its `RuleSets` in
// the same way.
func syscallActions(rules []ociRule, defaultAction linux.BPFAction) map[uintptr]syscallAction {
	numSysnos := 0
	for _, r := range rules {
		numSysnos += len(r.sysnos)
	}
	actions := make(map[uintptr]syscallAction, numSysnos)
	for _, r := range rules {
		action := r.action.BPF(defaultAction)
		for _, sysno := range r.sysnos {
			sa, ok := actions[sysno]
			switch {
			case !ok:
				sa = syscallAction{action: action, fixed: true}
			case sa.final:
				continue
			case sa.action != action:
				sa.fixed = false
			}
			_, sa.final = r.rule.(seccomp.MatchAll)
			actions[sysno] = sa
		}
	}
	for sysno, sa := range actions {
		if !sa.final && sa.action != defaultAction {
			sa.fixed = false
			actions[sysno] = sa
		}
	}
	return actions
}

// lookupSyscallNo gets the syscall number for the syscall with the given name
// for the given architecture.
func lookupSyscallNo(arch uint32, name string) (uint32, error) {
	var table *kernel.SyscallTable
	// LINT.IfChange
	switch arch {
	case linux.AUDIT_ARCH_X86_64:
		table = slinux.AMD64
	case linux.AUDIT_ARCH_AARCH64:
		table = slinux.ARM64
	}
	// LINT.ThenChange(../seccomp.go:knownSeccompArchs)
	if table == nil {
		return 0, fmt.Errorf("unsupported architecture: %d", arch)
	}
	n, err := table.LookupNo(name)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

// convertAction converts a LinuxSeccompAction to BPFAction. errnoRet is the
// errnoRet (or defaultErrnoRet) requested by the OCI profile for this action,
// or nil if it requested none. It is only meaningful for ActErrno and
// ActTrace and, as in runc, is silently ignored for every other action.
func convertAction(act specs.LinuxSeccompAction, errnoRet *uint) (seccomp.Action, error) {
	// TODO(gvisor.dev/issue/3124): Update specs package to include ActLog and ActKillProcess.
	// LINT.IfChange
	switch act {
	case specs.ActKill:
		return killThreadAction, nil
	case specs.ActTrap:
		return trapAction, nil
	case specs.ActErrno:
		return withErrnoRet(errnoAction, errnoRet)
	case specs.ActTrace:
		return withErrnoRet(traceAction, errnoRet)
	case specs.ActLog:
		return logAction, nil
	case specs.ActAllow:
		return allowAction, nil
	default:
		return seccomp.Default, fmt.Errorf("invalid action: %v", act)
	}
	// LINT.ThenChange(../seccomp.go:knownSeccompActions)
}

// withErrnoRet overrides the return code of act with errnoRet, if set. act
// must be errnoAction or traceAction; callers must not use it for other
// actions, as they carry no return code.
//
// errnoRet is only meaningful for SCMP_ACT_ERRNO and SCMP_ACT_TRACE. OCI
// profiles may nonetheless set it on other actions; runc silently accepts
// that, so runsc must too, and convertAction therefore never calls this for
// those actions.
func withErrnoRet(act seccomp.Action, errnoRet *uint) (seccomp.Action, error) {
	if errnoRet == nil {
		return act, nil
	}
	if *errnoRet > math.MaxUint16 {
		return seccomp.Default, fmt.Errorf("errnoRet %d does not fit in 16 bits", *errnoRet)
	}
	return act.Code(uint16(*errnoRet)), nil
}

// ociRule is one entry of `specs.LinuxSeccomp.Syscalls`.
type ociRule struct {
	// sysnos are the syscall numbers that the rule applies to.
	sysnos []uintptr

	// rule matches the syscall arguments.
	// It is `seccomp.MatchAll` if the entry has no argument conditions.
	rule seccomp.SyscallRule

	// action applies when `rule` matches.
	action seccomp.Action
}

// convertRules converts the OCI seccomp rules of `s` to `ociRule`s. It keeps
// the order of the rules.
func convertRules(s *specs.LinuxSeccomp) ([]ociRule, error) {
	// NOTE: Architectures are only really relevant when calling 32bit syscalls
	// on a 64bit system. Since we don't support that in gVisor anyway, we
	// ignore Architectures and only test against the native architecture.

	rules := make([]ociRule, 0, len(s.Syscalls))

	for _, syscall := range s.Syscalls {
		action, err := convertAction(syscall.Action, syscall.ErrnoRet)
		if err != nil {
			return nil, err
		}

		// Args
		var rule seccomp.SyscallRule = seccomp.MatchAll{}
		if len(syscall.Args) > 0 {
			if rule, err = convertArgs(syscall.Args); err != nil {
				return nil, err
			}
		}

		sysnos := make([]uintptr, 0, len(syscall.Names))
		for _, name := range syscall.Names {
			syscallNo, err := lookupSyscallNo(nativeArchAuditNo, name)
			if err != nil {
				// If there is an error looking up the syscall number, assume it is
				// not supported on this architecture and ignore it. This is, for
				// better or worse, what runc does.
				log.Warningf("OCI seccomp: ignoring syscall %q", name)
				continue
			}

			sysnos = append(sysnos, uintptr(syscallNo))
		}

		rules = append(rules, ociRule{
			sysnos: sysnos,
			rule:   rule,
			action: action,
		})
	}

	return rules, nil
}

// convertArgs converts an OCI seccomp argument rule to a list of seccomp.Rule.
func convertArgs(args []specs.LinuxSeccompArg) (seccomp.SyscallRule, error) {
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
		rules := seccomp.Or{}

		// Old runc behavior - do this for compatibility.
		// Add rules as ORs by adding separate Rules.
		for _, arg := range args {
			rule := seccomp.PerArg{nil, nil, nil, nil, nil, nil}

			if err := convertRule(arg, &rule); err != nil {
				return nil, err
			}

			rules = append(rules, rule)
		}

		return rules, nil
	}

	// Add rules as ANDs by adding to the same Rule.
	rule := seccomp.PerArg{nil, nil, nil, nil, nil, nil}
	for _, arg := range args {
		if err := convertRule(arg, &rule); err != nil {
			return nil, err
		}
	}

	return rule, nil
}

// convertRule converts and adds the arg to a PerArg rule.
func convertRule(arg specs.LinuxSeccompArg, perArg *seccomp.PerArg) error {
	// LINT.IfChange
	switch arg.Op {
	case specs.OpEqualTo:
		perArg[arg.Index] = seccomp.EqualTo(arg.Value)
	case specs.OpNotEqual:
		perArg[arg.Index] = seccomp.NotEqual(arg.Value)
	case specs.OpGreaterThan:
		perArg[arg.Index] = seccomp.GreaterThan(arg.Value)
	case specs.OpGreaterEqual:
		perArg[arg.Index] = seccomp.GreaterThanOrEqual(arg.Value)
	case specs.OpLessThan:
		perArg[arg.Index] = seccomp.LessThan(arg.Value)
	case specs.OpLessEqual:
		perArg[arg.Index] = seccomp.LessThanOrEqual(arg.Value)
	case specs.OpMaskedEqual:
		perArg[arg.Index] = seccomp.MaskedEqual(uintptr(arg.Value), uintptr(arg.ValueTwo))
	default:
		return fmt.Errorf("unsupported operand: %q", arg.Op)
	}
	// LINT.ThenChange(../seccomp.go:knownSeccompOperators)
	return nil
}
