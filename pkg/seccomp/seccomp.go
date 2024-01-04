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

// Package seccomp provides generation of basic seccomp filters. Currently,
// only little endian systems are supported.
package seccomp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	// skipOneInst is the offset to take for skipping one instruction.
	skipOneInst = 1

	// defaultLabel is the label for the default action.
	defaultLabel = label("default_action")

	// vsyscallPageIPMask is the bit we expect to see in the instruction
	// pointer of a vsyscall call.
	vsyscallPageIPMask = 1 << 31
)

// Install generates BPF code based on the set of syscalls provided. It only
// allows syscalls that conform to the specification. Syscalls that violate the
// specification will trigger RET_KILL_PROCESS. If RET_KILL_PROCESS is not
// supported, violations will trigger RET_TRAP instead. RET_KILL_THREAD is not
// used because it only kills the offending thread and often keeps the sentry
// hanging.
//
// denyRules describes forbidden syscalls. rules describes allowed syscalls.
// denyRules is executed before rules.
//
// Be aware that RET_TRAP sends SIGSYS to the process and it may be ignored,
// making it possible for the process to continue running after a violation.
// However, it will leave a SECCOMP audit event trail behind. In any case, the
// syscall is still blocked from executing.
func Install(rules SyscallRules, denyRules SyscallRules, options ProgramOptions) error {
	// ***   DEBUG TIP   ***
	// If you suspect the Sentry is getting killed due to a seccomp violation,
	// look for the `debugFilter` boolean in `//runsc/boot/filter/filter.go`.

	log.Infof("Installing seccomp filters for %d syscalls (action=%v)", rules.Size(), options.DefaultAction)

	instrs, _, err := BuildProgram([]RuleSet{
		{
			Rules:  denyRules,
			Action: options.DefaultAction,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, options)
	if log.IsLogging(log.Debug) {
		programStr, errDecode := bpf.DecodeInstructions(instrs)
		if errDecode != nil {
			programStr = fmt.Sprintf("Error: %v\n%s", errDecode, programStr)
		}
		log.Debugf("Seccomp program dump:\n%s", programStr)
	}
	if err != nil {
		return err
	}

	// Perform the actual installation.
	if err := SetFilter(instrs); err != nil {
		return fmt.Errorf("failed to set filter: %v", err)
	}

	log.Infof("Seccomp filters installed.")
	return nil
}

// DefaultAction returns a sane default for a failure to match
// a seccomp-bpf filter. Either kill the process, or trap.
func DefaultAction() (linux.BPFAction, error) {
	available, err := isKillProcessAvailable()
	if err != nil {
		return 0, err
	}
	if available {
		return linux.SECCOMP_RET_KILL_PROCESS, nil
	}
	return linux.SECCOMP_RET_TRAP, nil
}

// RuleSet is a set of rules and associated action.
type RuleSet struct {
	Rules  SyscallRules
	Action linux.BPFAction

	// Vsyscall indicates that a check is made for a function being called
	// from kernel mappings. This is where the vsyscall page is located
	// (and typically) emulated, so this RuleSet will not match any
	// functions not dispatched from the vsyscall page.
	Vsyscall bool
}

// SyscallName gives names to system calls. It is used purely for debugging purposes.
//
// An alternate namer can be provided to the package at initialization time.
var SyscallName = func(sysno uintptr) string {
	return fmt.Sprintf("syscall_%d", sysno)
}

// syscallProgram builds a BPF program for applying syscall rules.
// It is a stateful struct that is updated as the program is built.
type syscallProgram struct {
	// program is the underlying BPF program being built.
	program *bpf.ProgramBuilder
}

// Stmt adds a statement to the program.
func (s *syscallProgram) Stmt(code uint16, k uint32) {
	s.program.AddStmt(code, k)
}

// label is a custom label type which is returned by `labelSet`.
type label string

// JumpTo adds a jump instruction to the program, jumping to the given label.
func (s *syscallProgram) JumpTo(label label) {
	s.program.AddDirectJumpLabel(string(label))
}

// If checks a condition and jumps to a label if the condition is true.
// If the condition is false, the program continues executing (no jumping).
func (s *syscallProgram) If(code uint16, k uint32, jt label) {
	s.program.AddJump(code, k, 0, skipOneInst)
	s.JumpTo(jt)
}

// IfNot checks a condition and jumps to a label if the condition is false.
// If the condition is true, the program continues executing (no jumping).
func (s *syscallProgram) IfNot(code uint16, k uint32, jf label) {
	s.program.AddJump(code, k, skipOneInst, 0)
	s.JumpTo(jf)
}

// Ret adds a return instruction to the program.
func (s *syscallProgram) Ret(action linux.BPFAction) {
	s.Stmt(bpf.Ret|bpf.K, uint32(action))
}

// Label adds a label to the program.
// It panics if this label has already been added to the program.
func (s *syscallProgram) Label(label label) {
	if err := s.program.AddLabel(string(label)); err != nil {
		panic(fmt.Sprintf("cannot add label %q to program: %v", label, err))
	}
}

// Record starts recording the instructions added to the program from now on.
// It returns a syscallFragment which can be used to perform assertions on the
// possible set of outcomes of the set of instruction that has been added
// since `Record` was called.
func (s *syscallProgram) Record() syscallProgramFragment {
	return syscallProgramFragment{s.program.Record()}
}

// syscallProgramFragment represents a fragment of the syscall program.
type syscallProgramFragment struct {
	getFragment func() bpf.ProgramFragment
}

// MustHaveJumpedTo asserts that the fragment must jump to one of the
// given labels.
// The fragment may not jump to any other label, nor return, nor fall through.
func (f syscallProgramFragment) MustHaveJumpedTo(labels ...label) {
	f.MustHaveJumpedToOrReturned(labels, nil)
}

// MustHaveJumpedToOrReturned asserts that the fragment must jump to one of
// the given labels, or have returned one of the given return values.
// The fragment may not jump to any other label, nor fall through,
// nor return a non-deterministic value.
func (f syscallProgramFragment) MustHaveJumpedToOrReturned(possibleLabels []label, possibleReturnValues map[linux.BPFAction]struct{}) {
	fragment := f.getFragment()
	outcomes := fragment.Outcomes()
	if outcomes.MayFallThrough {
		panic(fmt.Sprintf("fragment %v may fall through", fragment))
	}
	if len(possibleReturnValues) == 0 && outcomes.MayReturn() {
		panic(fmt.Sprintf("fragment %v may return", fragment))
	}
	if outcomes.MayReturnRegisterA {
		panic(fmt.Sprintf("fragment %v may return register A", fragment))
	}
	if outcomes.MayJumpToKnownOffsetBeyondFragment {
		panic(fmt.Sprintf("fragment %v may jump to an offset beyond the fragment", fragment))
	}
	for jumpLabel := range outcomes.MayJumpToUnresolvedLabels {
		found := false
		for _, wantLabel := range possibleLabels {
			if jumpLabel == string(wantLabel) {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("fragment %v may jump to a label %q which is not one of %v", fragment, jumpLabel, possibleLabels))
		}
	}
	for returnValue := range outcomes.MayReturnImmediate {
		if _, found := possibleReturnValues[returnValue]; !found {
			panic(fmt.Sprintf("fragment %v may return a value %q which is not one of %v", fragment, returnValue, possibleReturnValues))
		}
	}
}

// labelSet keeps track of labels that individual rules may jump to if they
// either match or mismatch.
// It can generate unique label names, and can be used recursively within
// rules.
type labelSet struct {
	// prefix is a label prefix used when generating label names.
	prefix string

	// labelCounter is used to generate unique label names.
	labelCounter int

	// ruleMatched is the label that a rule should jump to if it matches.
	ruleMatched label

	// ruleMismatched is the label that a rule should jump to if it doesn't
	// match.
	ruleMismatched label
}

// NewLabel returns a new unique label.
func (l *labelSet) NewLabel() label {
	newLabel := label(fmt.Sprintf("%s#%d", l.prefix, l.labelCounter))
	l.labelCounter++
	return newLabel
}

// Matched returns the label to jump to if the rule matches.
func (l *labelSet) Matched() label {
	return l.ruleMatched
}

// Mismatched returns the label to jump to if the rule does not match.
func (l *labelSet) Mismatched() label {
	return l.ruleMismatched
}

// Push creates a new labelSet meant to be used in a recursive context of the
// rule currently being rendered.
// Labels generated by this new labelSet will have `labelSuffix` appended to
// this labelSet's current prefix, and will have its matched/mismatched labels
// point to the given labels.
func (l *labelSet) Push(labelSuffix string, newRuleMatch, newRuleMismatch label) *labelSet {
	newPrefix := labelSuffix
	if l.prefix != "" {
		newPrefix = fmt.Sprintf("%s_%s", l.prefix, labelSuffix)
	}
	return &labelSet{
		prefix:         newPrefix,
		ruleMatched:    newRuleMatch,
		ruleMismatched: newRuleMismatch,
	}
}

// matchedValue keeps track of BPF instructions needed to load a 64-bit value
// being matched against. Since BPF can only do operations on 32-bit
// instructions, value-matching code needs to selectively load one or the
// other half of the 64-bit value.
type matchedValue struct {
	program        *syscallProgram
	dataOffsetHigh uint32
	dataOffsetLow  uint32
}

// LoadHigh32Bits loads the high 32-bit of the 64-bit value into register A.
func (m matchedValue) LoadHigh32Bits() {
	m.program.Stmt(bpf.Ld|bpf.Abs|bpf.W, m.dataOffsetHigh)
}

// LoadLow32Bits loads the low 32-bit of the 64-bit value into register A.
func (m matchedValue) LoadLow32Bits() {
	m.program.Stmt(bpf.Ld|bpf.Abs|bpf.W, m.dataOffsetLow)
}

// ProgramOptions configure a seccomp program.
type ProgramOptions struct {
	// DefaultAction is the action returned when none of the rules match.
	DefaultAction linux.BPFAction

	// BadArchAction is the action returned when the architecture of the
	// syscall structure input doesn't match the one the program expects.
	BadArchAction linux.BPFAction

	// Optimize specifies whether optimizations should be applied to the
	// syscall rules and generated BPF bytecode.
	Optimize bool

	// HotSyscalls is the set of syscall numbers that are the hottest,
	// where "hotness" refers to frequency (regardless of the amount of
	// computation that the kernel will do handling them, and regardless of
	// the complexity of the syscall rule for this).
	// It should only contain very hot syscalls (i.e. any syscall that is
	// called >10% of the time out of all syscalls made).
	// It is ordered from most frequent to least frequent.
	HotSyscalls []uintptr
}

// DefaultProgramOptions returns the default program options.
func DefaultProgramOptions() ProgramOptions {
	action, err := DefaultAction()
	if err != nil {
		panic(fmt.Sprintf("cannot determine default seccomp action: %v", err))
	}
	return ProgramOptions{
		DefaultAction: action,
		BadArchAction: action,
		Optimize:      true,
	}
}

// BuildStats contains information about seccomp program generation.
type BuildStats struct {
	// SizeBeforeOptimizations and SizeAfterOptimizations correspond to the
	// number of instructions in the program before vs after optimization.
	SizeBeforeOptimizations, SizeAfterOptimizations int

	// BuildDuration is the amount of time it took to build the program (before
	// BPF bytecode optimizations).
	BuildDuration time.Duration

	// RuleOptimizeDuration is the amount of time it took to run SyscallRule
	// optimizations.
	RuleOptimizeDuration time.Duration

	// BPFOptimizeDuration is the amount of time it took to run BPF bytecode
	// optimizations.
	BPFOptimizeDuration time.Duration
}

// BuildProgram builds a BPF program from the given map of actions to matching
// SyscallRules. The single generated program covers all provided RuleSets.
func BuildProgram(rules []RuleSet, options ProgramOptions) ([]bpf.Instruction, BuildStats, error) {
	start := time.Now()
	// Make a copy of the syscall rules and maybe optimize them.
	ors, ruleOptimizeDuration, err := orderRuleSets(rules, options)
	if err != nil {
		return nil, BuildStats{}, err
	}

	possibleActions := make(map[linux.BPFAction]struct{})
	for _, ruleSet := range rules {
		possibleActions[ruleSet.Action] = struct{}{}
	}

	program := &syscallProgram{
		program: bpf.NewProgramBuilder(),
	}

	// Be paranoid and check that syscall is done in the expected architecture.
	//
	// A = seccomp_data.arch
	// if (A != AUDIT_ARCH) goto badArchLabel.
	badArchLabel := label("badarch")
	program.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArch)
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, LINUX_AUDIT_ARCH, badArchLabel)
	orsFrag := program.Record()
	if err := ors.render(program); err != nil {
		return nil, BuildStats{}, err
	}
	orsFrag.MustHaveJumpedToOrReturned([]label{defaultLabel}, possibleActions)

	// Default label if none of the rules matched:
	program.Label(defaultLabel)
	program.Ret(options.DefaultAction)

	// Label if the architecture didn't match:
	program.Label(badArchLabel)
	program.Ret(options.BadArchAction)

	insns, err := program.program.Instructions()
	if err != nil {
		return nil, BuildStats{}, err
	}
	beforeOpt := len(insns)
	buildDuration := time.Since(start) - ruleOptimizeDuration
	var bpfOptimizeDuration time.Duration
	afterOpt := beforeOpt
	if options.Optimize {
		insns = bpf.Optimize(insns)
		bpfOptimizeDuration = time.Since(start) - buildDuration - ruleOptimizeDuration
		afterOpt = len(insns)
		log.Debugf("Seccomp program optimized from %d to %d instructions; took %v to build and %v to optimize", beforeOpt, afterOpt, buildDuration, bpfOptimizeDuration)
	}
	return insns, BuildStats{
		SizeBeforeOptimizations: beforeOpt,
		SizeAfterOptimizations:  afterOpt,
		BuildDuration:           buildDuration,
		RuleOptimizeDuration:    ruleOptimizeDuration,
		BPFOptimizeDuration:     bpfOptimizeDuration,
	}, nil
}

// singleSyscallRuleSet represents what to do for a single syscall.
// It is used inside `orderedRules`.
type singleSyscallRuleSet struct {
	sysno    uintptr
	rules    []syscallRuleAction
	vsyscall bool
}

// Render renders the ruleset for this syscall.
func (ssrs singleSyscallRuleSet) Render(program *syscallProgram, ls *labelSet, noMatch label) {
	frag := program.Record()
	if ssrs.vsyscall {
		// Emit a vsyscall check.
		// This rule ensures that the top bit is set in the
		// instruction pointer, which is where the vsyscall page
		// will be mapped.
		program.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetIPHigh)
		program.IfNot(bpf.Jmp|bpf.Jset|bpf.K, vsyscallPageIPMask, noMatch)
	}
	var nextRule label
	actions := make(map[linux.BPFAction]struct{})
	for i, ra := range ssrs.rules {
		actions[ra.action] = struct{}{}

		// Render the rule.
		nextRule = ls.NewLabel()
		ruleLabels := ls.Push(fmt.Sprintf("sysno%d_rule%d", ssrs.sysno, i), ls.NewLabel(), nextRule)
		ruleFrag := program.Record()
		ra.rule.Render(program, ruleLabels)
		program.Label(ruleLabels.Matched())
		program.Ret(ra.action)
		ruleFrag.MustHaveJumpedToOrReturned(
			[]label{nextRule},
			map[linux.BPFAction]struct{}{
				ra.action: struct{}{},
			})
		program.Label(nextRule)
	}
	program.JumpTo(noMatch)
	frag.MustHaveJumpedToOrReturned([]label{noMatch}, actions)
}

// String returns a human-friendly representation of the
// `singleSyscallRuleSet`.
func (ssrs singleSyscallRuleSet) String() string {
	var sb strings.Builder
	if ssrs.vsyscall {
		sb.WriteString("Vsyscall ")
	} else {
		sb.WriteString("Syscall  ")
	}
	sb.WriteString(fmt.Sprintf("%3d: ", ssrs.sysno))
	switch len(ssrs.rules) {
	case 0:
		sb.WriteString("(no rules)")
	case 1:
		sb.WriteString(ssrs.rules[0].String())
	default:
		sb.WriteRune('{')
		for i, r := range ssrs.rules {
			if i != 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(r.String())
		}
		sb.WriteRune('}')
	}
	return sb.String()
}

// syscallRuleAction groups a `SyscallRule` and an action that should be
// returned if the rule matches.
type syscallRuleAction struct {
	rule   SyscallRule
	action linux.BPFAction
}

// String returns a human-friendly representation of the `syscallRuleAction`.
func (sra syscallRuleAction) String() string {
	if _, isMatchAll := sra.rule.(MatchAll); isMatchAll {
		return sra.action.String()
	}
	return fmt.Sprintf("(%v) => %v", sra.rule.String(), sra.action)
}

// orderedRules contains an ordering of syscall rules used to render a
// program. It is derived from a list of `RuleSet`s and `ProgramOptions`.
// Its fields represent the order in which rulesets are rendered.
// There are three categorization criteria:
//   - "Hot" vs "cold": hot syscalls go first and are checked linearly, cold
//     syscalls go later.
//   - "Trivial" vs "non-trivial": A "trivial" syscall rule means one that
//     does not require checking any argument or RIP data. This basically
//     means a syscall mapped to `MatchAll{}`.
//     If a syscall shows up in multiple RuleSets where any of them is
//     non-trivial, the whole syscall is considered non-trivial.
//   - "vsyscall" vs "non-vsyscall": A syscall that needs vsyscall checking
//     checks that the function is dispatched from the vsyscall page by
//     checking RIP. This inherently makes it non-trivial. All trivial
//     rules are non-vsyscall, but not all non-vsyscall rules are trivial.
type orderedRuleSets struct {
	// hotNonTrivial is the set of hot syscalls that are non-trivial
	// and may or may not require vsyscall checking.
	// They come first and are checked linearly using `hotNonTrivialOrder`.
	hotNonTrivial map[uintptr]singleSyscallRuleSet

	// hotNonTrivial is the set of hot syscalls that are non-trivial
	// and may or may not require vsyscall checking.
	// They come first and are checked linearly using `hotNonTrivialOrder`.
	hotNonTrivialOrder []uintptr

	// coldNonTrivial is the set of non-hot syscalls that are non-trivial.
	// They may or may not require vsyscall checking.
	// They come second.
	coldNonTrivial map[uintptr]singleSyscallRuleSet

	// trivial is the set of syscalls that are trivial. They may or may not be
	// hot, but they may not require vsyscall checking (otherwise they would
	// be non-trivial).
	// They come last. This is because the host kernel will cache the results
	// of these system calls, and will never execute them on the hot path.
	trivial map[uintptr]singleSyscallRuleSet
}

// orderRuleSets converts a set of `RuleSet`s into an `orderedRuleSets`.
// It orders the rulesets, along with the time to optimize the
// rules (if any).
func orderRuleSets(rules []RuleSet, options ProgramOptions) (orderedRuleSets, time.Duration, error) {
	// Do a pass to determine if vsyscall is consistent across syscall numbers.
	vsyscallBySysno := make(map[uintptr]bool)
	for _, rs := range rules {
		for sysno := range rs.Rules.rules {
			if prevVsyscall, ok := vsyscallBySysno[sysno]; ok {
				if prevVsyscall != rs.Vsyscall {
					return orderedRuleSets{}, 0, fmt.Errorf("syscall %d has conflicting vsyscall checking rules", sysno)
				}
			} else {
				vsyscallBySysno[sysno] = rs.Vsyscall
			}
		}
	}

	// Build a single map of per-syscall syscallRuleActions.
	// We will split this map up later.
	allSyscallRuleActions := make(map[uintptr][]syscallRuleAction)
	for _, rs := range rules {
		for sysno, rule := range rs.Rules.rules {
			existing, found := allSyscallRuleActions[sysno]
			if !found {
				allSyscallRuleActions[sysno] = []syscallRuleAction{{
					rule:   rule,
					action: rs.Action,
				}}
				continue
			}
			if existing[len(existing)-1].action == rs.Action {
				// If the last action for this syscall is the same, union the rules.
				existing[len(existing)-1].rule = Or{existing[len(existing)-1].rule, rule}
			} else {
				// Otherwise, add it as a new ruleset.
				existing = append(existing, syscallRuleAction{
					rule:   rule,
					action: rs.Action,
				})
			}
			allSyscallRuleActions[sysno] = existing
		}
	}

	// Optimize all rules.
	var optimizeDuration time.Duration
	if options.Optimize {
		optimizeStart := time.Now()
		for _, ruleActions := range allSyscallRuleActions {
			for i, ra := range ruleActions {
				ra.rule = optimizeSyscallRule(ra.rule)
				ruleActions[i] = ra
			}
		}
		optimizeDuration = time.Since(optimizeStart)
	}

	// Do a pass that checks which syscall numbers are trivial.
	isTrivial := make(map[uintptr]bool)
	for sysno, ruleActions := range allSyscallRuleActions {
		for _, ra := range ruleActions {
			_, isMatchAll := ra.rule.(MatchAll)
			isVsyscall := vsyscallBySysno[sysno]
			trivial := isMatchAll && !isVsyscall
			if prevTrivial, ok := isTrivial[sysno]; ok {
				isTrivial[sysno] = prevTrivial && trivial
			} else {
				isTrivial[sysno] = trivial
			}
		}
	}

	// Compute the set of non-trivial hot syscalls and their order.
	hotNonTrivialSyscallsIndex := make(map[uintptr]int, len(options.HotSyscalls))
	for i, sysno := range options.HotSyscalls {
		if _, hasRule := allSyscallRuleActions[sysno]; !hasRule {
			continue
		}
		if isTrivial[sysno] {
			continue
		}
		if _, ok := hotNonTrivialSyscallsIndex[sysno]; ok {
			continue
		}
		hotNonTrivialSyscallsIndex[sysno] = i
	}
	hotNonTrivialOrder := make([]uintptr, 0, len(hotNonTrivialSyscallsIndex))
	for sysno := range hotNonTrivialSyscallsIndex {
		hotNonTrivialOrder = append(hotNonTrivialOrder, sysno)
	}
	sort.Slice(hotNonTrivialOrder, func(i, j int) bool {
		return hotNonTrivialSyscallsIndex[hotNonTrivialOrder[i]] < hotNonTrivialSyscallsIndex[hotNonTrivialOrder[j]]
	})

	// Now split up the map and build the `orderedRuleSets`.
	ors := orderedRuleSets{
		hotNonTrivial:      make(map[uintptr]singleSyscallRuleSet),
		hotNonTrivialOrder: hotNonTrivialOrder,
		coldNonTrivial:     make(map[uintptr]singleSyscallRuleSet),
		trivial:            make(map[uintptr]singleSyscallRuleSet),
	}
	for sysno, ruleActions := range allSyscallRuleActions {
		_, hot := hotNonTrivialSyscallsIndex[sysno]
		trivial := isTrivial[sysno]
		var subMap map[uintptr]singleSyscallRuleSet
		switch {
		case trivial:
			subMap = ors.trivial
		case hot:
			subMap = ors.hotNonTrivial
		default:
			subMap = ors.coldNonTrivial
		}
		subMap[sysno] = singleSyscallRuleSet{
			sysno:    sysno,
			vsyscall: vsyscallBySysno[sysno],
			rules:    ruleActions,
		}
	}

	// Log our findings.
	if log.IsLogging(log.Debug) {
		ors.log(log.Debugf)
	}

	return ors, optimizeDuration, nil
}

// log logs the set of seccomp rules to the given logger.
func (ors orderedRuleSets) log(logFn func(string, ...any)) {
	logFn("Ordered seccomp rules:")
	for _, sm := range []struct {
		name string
		m    map[uintptr]singleSyscallRuleSet
	}{
		{"Hot non-trivial", ors.hotNonTrivial},
		{"Cold non-trivial", ors.coldNonTrivial},
		{"Trivial", ors.trivial},
	} {
		if len(sm.m) == 0 {
			logFn("  %s syscalls: None.", sm.name)
			continue
		}
		logFn("  %s syscalls:", sm.name)
		orderedSysnos := make([]int, 0, len(sm.m))
		for sysno := range sm.m {
			orderedSysnos = append(orderedSysnos, int(sysno))
		}
		sort.Ints(orderedSysnos)
		for _, sysno := range orderedSysnos {
			logFn("    - %s", sm.m[uintptr(sysno)].String())
		}
	}
	logFn("End of ordered seccomp rules.")
}

// render renders all rulesets in the given program.
func (ors orderedRuleSets) render(program *syscallProgram) error {
	ls := &labelSet{prefix: string("ors")}

	// totalFrag wraps the entire output of the `render` function.
	totalFrag := program.Record()

	// Load syscall number into register A.
	program.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetNR)

	// Keep track of which syscalls we've already looked for.
	sysnosChecked := make(map[uintptr]struct{})

	// First render hot syscalls linearly.
	if len(ors.hotNonTrivialOrder) > 0 {
		notHotLabel := ls.NewLabel()
		// hotFrag wraps the "hot syscalls" part of the program.
		// It must either return one of `hotActions`, or jump to `defaultLabel` if
		// the syscall number matched but the vsyscall match failed, or
		// `notHotLabel` if none of the hot syscall numbers matched.
		hotFrag := program.Record()
		possibleActions := ors.renderLinear(program, ls, sysnosChecked, ors.hotNonTrivial, ors.hotNonTrivialOrder, notHotLabel)
		hotFrag.MustHaveJumpedToOrReturned([]label{notHotLabel, defaultLabel}, possibleActions)
		program.Label(notHotLabel)
	}

	// Now render the cold non-trivial rules as a binary search tree:
	if len(ors.coldNonTrivial) > 0 {
		frag := program.Record()
		noSycallNumberMatch := ls.NewLabel()
		possibleActions, err := ors.renderBST(program, ls, sysnosChecked, ors.coldNonTrivial, noSycallNumberMatch)
		if err != nil {
			return err
		}
		frag.MustHaveJumpedToOrReturned([]label{noSycallNumberMatch, defaultLabel}, possibleActions)
		program.Label(noSycallNumberMatch)
	}

	// Finally render the trivial rules as a binary search tree:
	if len(ors.trivial) > 0 {
		frag := program.Record()
		noSycallNumberMatch := ls.NewLabel()
		possibleActions, err := ors.renderBST(program, ls, sysnosChecked, ors.trivial, noSycallNumberMatch)
		if err != nil {
			return err
		}
		frag.MustHaveJumpedToOrReturned([]label{noSycallNumberMatch, defaultLabel}, possibleActions)
		program.Label(noSycallNumberMatch)
	}
	program.JumpTo(defaultLabel)

	// Reached the end of the program.
	// Independently verify the set of all possible actions.
	allPossibleActions := make(map[linux.BPFAction]struct{})
	for _, mapping := range []map[uintptr]singleSyscallRuleSet{
		ors.hotNonTrivial,
		ors.coldNonTrivial,
		ors.trivial,
	} {
		for _, ssrs := range mapping {
			for _, ra := range ssrs.rules {
				allPossibleActions[ra.action] = struct{}{}
			}
		}
	}
	totalFrag.MustHaveJumpedToOrReturned([]label{defaultLabel}, allPossibleActions)
	return nil
}

// renderLinear renders linear search code that searches for syscall matches
// in the given order. It assumes the syscall number is loaded into register
// A. Rulesets for all syscall numbers in `order` must exist in `syscallMap`.
// It returns the list of possible actions the generated code may return.
// `alreadyChecked` will be updated with the syscalls that have been checked.
func (ors orderedRuleSets) renderLinear(program *syscallProgram, ls *labelSet, alreadyChecked map[uintptr]struct{}, syscallMap map[uintptr]singleSyscallRuleSet, order []uintptr, noSycallNumberMatch label) map[linux.BPFAction]struct{} {
	allActions := make(map[linux.BPFAction]struct{})
	for _, sysno := range order {
		ssrs, found := syscallMap[sysno]
		if !found {
			panic(fmt.Sprintf("syscall %d found in linear order but not map", sysno))
		}
		nextSyscall := ls.NewLabel()
		// sysnoFrag wraps the "statements about this syscall number" part of
		// the program. It must either return one of the actions specified in
		// that syscall number's rules (`sysnoActions`), or jump to
		// `nextSyscall`.
		sysnoFrag := program.Record()
		sysnoActions := make(map[linux.BPFAction]struct{})
		for _, ra := range ssrs.rules {
			sysnoActions[ra.action] = struct{}{}
			allActions[ra.action] = struct{}{}
		}
		program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, uint32(ssrs.sysno), nextSyscall)
		ssrs.Render(program, ls, defaultLabel)
		sysnoFrag.MustHaveJumpedToOrReturned([]label{nextSyscall, defaultLabel}, sysnoActions)
		program.Label(nextSyscall)
	}
	program.JumpTo(noSycallNumberMatch)
	for _, sysno := range order {
		alreadyChecked[sysno] = struct{}{}
	}
	return allActions
}

// renderBST renders a binary search tree that searches the given map of
// syscalls. It assumes the syscall number is loaded into register A.
// It returns the list of possible actions the generated code may return.
// `alreadyChecked` will be updated with the syscalls that the BST has
// searched.
func (ors orderedRuleSets) renderBST(program *syscallProgram, ls *labelSet, alreadyChecked map[uintptr]struct{}, syscallMap map[uintptr]singleSyscallRuleSet, noSycallNumberMatch label) (map[linux.BPFAction]struct{}, error) {
	possibleActions := make(map[linux.BPFAction]struct{})
	orderedSysnos := make([]uintptr, 0, len(syscallMap))
	for sysno, ruleActions := range syscallMap {
		orderedSysnos = append(orderedSysnos, sysno)
		for _, ra := range ruleActions.rules {
			possibleActions[ra.action] = struct{}{}
		}
	}
	sort.Slice(orderedSysnos, func(i, j int) bool {
		return orderedSysnos[i] < orderedSysnos[j]
	})
	frag := program.Record()
	root := createBST(orderedSysnos)
	root.root = true
	knownRng := knownRange{
		lowerBoundExclusive: -1,
		// sysno fits in 32 bits, so this is definitely out of bounds:
		upperBoundExclusive: 1 << 32,
		previouslyChecked:   alreadyChecked,
	}
	if err := root.traverse(renderBSTTraversal, knownRng, syscallMap, program, noSycallNumberMatch); err != nil {
		return nil, err
	}
	if err := root.traverse(renderBSTRules, knownRng, syscallMap, program, noSycallNumberMatch); err != nil {
		return nil, err
	}
	frag.MustHaveJumpedToOrReturned([]label{noSycallNumberMatch, defaultLabel}, possibleActions)
	for sysno := range syscallMap {
		alreadyChecked[sysno] = struct{}{}
	}
	return possibleActions, nil
}

// createBST converts sorted syscall slice into a balanced BST.
// Panics if syscalls is empty.
func createBST(syscalls []uintptr) *node {
	i := len(syscalls) / 2
	parent := node{value: syscalls[i]}
	if i > 0 {
		parent.left = createBST(syscalls[:i])
	}
	if i+1 < len(syscalls) {
		parent.right = createBST(syscalls[i+1:])
	}
	return &parent
}

// renderBSTTraversal renders the traversal bytecode for a binary search tree.
// The outline of the code is as follows, given a BST with:
//
//		     22
//		    /  \
//		   9    24
//		  /    /  \
//	   8   23    50
//
//		index_22: // SYS_PIPE(22), root
//		(A < 22) ? goto index_9  : continue
//		(A > 22) ? goto index_24 : continue
//		goto checkArgs_22
//
//		index_9: // SYS_MMAP(9), single child
//		(A < 9)  ? goto index_8  : continue
//		(A == 9) ? continue : goto defaultLabel
//		goto checkArgs_9
//
//		index_8: // SYS_LSEEK(8), leaf
//		(A == 8) ? continue : goto defaultLabel
//		goto checkArgs_8
//
//		index_24: // SYS_SCHED_YIELD(24)
//		(A < 24) ? goto index_23 : continue
//		(A > 22) ? goto index_50 : continue
//		goto checkArgs_24
//
//		index_23: // SYS_SELECT(23), leaf with parent nodes adjacent in value
//		# Notice that we do not check for equality at all here, since we've
//		# already established that the syscall number is 23 from the
//		# two parent nodes that we've already traversed.
//		# This is tracked in the `rng knownRange` argument during traversal.
//		goto rules_23
//
//		index_50: // SYS_LISTEN(50), leaf
//		(A == 50) ? continue : goto defaultLabel
//		goto checkArgs_50
//
// All of the "checkArgs_XYZ" labels are not defined in this function; they
// are created using the `renderBSTRules` function, which is expected to be
// called after this one on the entire BST.
func renderBSTTraversal(n *node, rng knownRange, syscallMap map[uintptr]singleSyscallRuleSet, program *syscallProgram, searchFailed label) error {
	// Root node is never referenced by label, skip it.
	if !n.root {
		program.Label(n.label())
	}
	sysno := n.value
	nodeFrag := program.Record()
	checkArgsLabel := label(fmt.Sprintf("checkArgs_%d", sysno))
	if n.left != nil {
		program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, uint32(sysno), n.left.label())
		rng.lowerBoundExclusive = int(sysno - 1)
	}
	if n.right != nil {
		program.If(bpf.Jmp|bpf.Jgt|bpf.K, uint32(sysno), n.right.label())
		rng.upperBoundExclusive = int(sysno + 1)
	}
	if rng.lowerBoundExclusive != int(sysno-1) || rng.upperBoundExclusive != int(sysno+1) {
		// If the previous BST nodes we traversed haven't fully established
		// that the current node's syscall value is exactly `sysno`, we still
		// need to verify it.
		program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, uint32(sysno), searchFailed)
	}
	program.JumpTo(checkArgsLabel)
	nodeFrag.MustHaveJumpedTo(n.left.label(), n.right.label(), checkArgsLabel, searchFailed)
	return nil
}

// renderBSTRules renders the `checkArgs_XYZ` labels that `renderBSTTraversal`
// jumps to as part of the BST traversal code. It contains all the
// argument-specific syscall rules for each syscall number.
func renderBSTRules(n *node, rng knownRange, syscallMap map[uintptr]singleSyscallRuleSet, program *syscallProgram, searchFailed label) error {
	sysno := n.value
	checkArgsLabel := label(fmt.Sprintf("checkArgs_%d", sysno))
	program.Label(checkArgsLabel)
	ruleSetsFrag := program.Record()
	possibleActions := make(map[linux.BPFAction]struct{})
	for _, ra := range syscallMap[sysno].rules {
		possibleActions[ra.action] = struct{}{}
	}
	nodeLabelSet := &labelSet{prefix: string(n.label())}
	syscallMap[sysno].Render(program, nodeLabelSet, defaultLabel)
	ruleSetsFrag.MustHaveJumpedToOrReturned(
		[]label{
			defaultLabel, // Either we jumped to the default label (if the rules didn't match)...
		},
		possibleActions, // ... or we returned one of the actions of the rulesets.
	)
	return nil
}

// node represents a tree node.
type node struct {
	value uintptr
	left  *node
	right *node
	root  bool
}

// label returns the label corresponding to this node.
//
// If n is nil, then the defaultLabel is returned.
func (n *node) label() label {
	if n == nil {
		return defaultLabel
	}
	return label(fmt.Sprintf("node_%d", n.value))
}

// knownRange represents the known set of node numbers that we've
// already checked. This is used as part of BST traversal.
type knownRange struct {
	lowerBoundExclusive int
	upperBoundExclusive int

	// alreadyChecked is a set of node values that were already checked
	// earlier in the program (prior to the BST being built).
	// It is *not* updated during BST traversal.
	previouslyChecked map[uintptr]struct{}
}

// withLowerBoundExclusive returns an updated `knownRange` with the given
// new exclusive lower bound. The actual exclusive lower bound of the
// returned `knownRange` may be higher, in case `previouslyChecked` covers
// more numbers.
func (kr knownRange) withLowerBoundExclusive(newLowerBoundExclusive int) knownRange {
	nkr := knownRange{
		lowerBoundExclusive: newLowerBoundExclusive,
		upperBoundExclusive: kr.upperBoundExclusive,
		previouslyChecked:   kr.previouslyChecked,
	}
	for ; nkr.lowerBoundExclusive < nkr.upperBoundExclusive; nkr.lowerBoundExclusive++ {
		if _, ok := nkr.previouslyChecked[uintptr(nkr.lowerBoundExclusive+1)]; !ok {
			break
		}
	}
	return nkr
}

// withUpperBoundExclusive returns an updated `knownRange` with the given
// new exclusive upper bound. The actual exclusive upper bound of the
// returned `knownRange` may be lower, in case `previouslyChecked` covers
// more numbers.
func (kr knownRange) withUpperBoundExclusive(newUpperBoundExclusive int) knownRange {
	nkr := knownRange{
		lowerBoundExclusive: kr.lowerBoundExclusive,
		upperBoundExclusive: newUpperBoundExclusive,
		previouslyChecked:   kr.previouslyChecked,
	}
	for ; nkr.lowerBoundExclusive < nkr.upperBoundExclusive; nkr.upperBoundExclusive-- {
		if _, ok := nkr.previouslyChecked[uintptr(nkr.upperBoundExclusive-1)]; !ok {
			break
		}
	}
	return nkr
}

// traverseFunc is called as the BST is traversed.
type traverseFunc func(*node, knownRange, map[uintptr]singleSyscallRuleSet, *syscallProgram, label) error

func (n *node) traverse(fn traverseFunc, kr knownRange, syscallMap map[uintptr]singleSyscallRuleSet, program *syscallProgram, searchFailed label) error {
	if n == nil {
		return nil
	}
	if err := fn(n, kr, syscallMap, program, searchFailed); err != nil {
		return err
	}
	if err := n.left.traverse(
		fn,
		kr.withUpperBoundExclusive(int(n.value)),
		syscallMap,
		program,
		searchFailed,
	); err != nil {
		return err
	}
	return n.right.traverse(
		fn,
		kr.withLowerBoundExclusive(int(n.value)),
		syscallMap,
		program,
		searchFailed,
	)
}

// DataAsBPFInput converts a linux.SeccompData to a bpf.Input.
// It uses `buf` as scratch buffer; this buffer must be wide enough
// to accommodate a mashaled version of `d`.
func DataAsBPFInput(d *linux.SeccompData, buf []byte) bpf.Input {
	if len(buf) < d.SizeBytes() {
		panic(fmt.Sprintf("buffer must be at least %d bytes long", d.SizeBytes()))
	}
	d.MarshalUnsafe(buf)
	return buf[:d.SizeBytes()]
}
