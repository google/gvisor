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

// NonNegativeFDCheck ensures an FD argument is a non-negative int.
func NonNegativeFDCheck() LessThanOrEqual {
	// Negative int32 has the MSB (31st bit) set. So the raw uint FD value must
	// be less than or equal to 0x7fffffff.
	return LessThanOrEqual(0x7fffffff)
}

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
func Install(rules SyscallRules, denyRules SyscallRules) error {
	defaultAction, err := defaultAction()
	if err != nil {
		return err
	}

	// ***   DEBUG TIP   ***
	// If you suspect the process is getting killed due to a seccomp violation, uncomment the line
	// below to get a panic stack trace when there is a violation.
	// defaultAction = linux.BPFAction(linux.SECCOMP_RET_TRAP)

	log.Infof("Installing seccomp filters for %d syscalls (action=%v)", rules.Size(), defaultAction)

	instrs, _, err := BuildProgram([]RuleSet{
		{
			Rules:  denyRules,
			Action: defaultAction,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, defaultAction, defaultAction)
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

func defaultAction() (linux.BPFAction, error) {
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
	fragment := f.getFragment()
	outcomes := fragment.Outcomes()
	if outcomes.MayFallThrough {
		panic(fmt.Sprintf("fragment %v may fall through", fragment))
	}
	if outcomes.MayReturn {
		panic(fmt.Sprintf("fragment %v may return", fragment))
	}
	if outcomes.MayJumpToKnownOffsetBeyondFragment {
		panic(fmt.Sprintf("fragment %v may jump to an offset beyond the fragment", fragment))
	}
	for jumpLabel := range outcomes.MayJumpToUnresolvedLabels {
		found := false
		for _, wantLabel := range labels {
			if jumpLabel == string(wantLabel) {
				found = true
				break
			}
		}
		if !found {
			panic(fmt.Sprintf("fragment %v may jump to a label %q which is not one of %v", fragment, jumpLabel, labels))
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

// BuildStats contains information about seccomp program generation.
type BuildStats struct {
	// SizeBeforeOptimizations and SizeAfterOptimizations correspond to the
	// number of instructions in the program before vs after optimization.
	SizeBeforeOptimizations, SizeAfterOptimizations int

	// BuildDuration is the amount of time it took to build the program (before
	// BPF bytecode optimizations).
	BuildDuration time.Duration

	// OptimizeDuration is the amount of time it took to run BPF bytecode
	// optimizations.
	OptimizeDuration time.Duration
}

// BuildProgram builds a BPF program from the given map of actions to matching
// SyscallRules. The single generated program covers all provided RuleSets.
func BuildProgram(rules []RuleSet, defaultAction, badArchAction linux.BPFAction) ([]bpf.Instruction, BuildStats, error) {
	start := time.Now()
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
	if err := buildIndex(rules, program); err != nil {
		return nil, BuildStats{}, err
	}

	// Default label if none of the rules matched:
	program.Label(defaultLabel)
	program.Ret(defaultAction)

	// Label if the architecture didn't match:
	program.Label(badArchLabel)
	program.Ret(badArchAction)

	insns, err := program.program.Instructions()
	if err != nil {
		return nil, BuildStats{}, err
	}
	beforeOpt := len(insns)
	buildDuration := time.Since(start)
	insns = bpf.Optimize(insns)
	optimizeDuration := time.Since(start) - buildDuration
	afterOpt := len(insns)
	log.Debugf("Seccomp program optimized from %d to %d instructions; took %v to build and %v to optimize", beforeOpt, afterOpt, buildDuration, optimizeDuration)
	return insns, BuildStats{
		SizeBeforeOptimizations: beforeOpt,
		SizeAfterOptimizations:  afterOpt,
		BuildDuration:           buildDuration,
		OptimizeDuration:        optimizeDuration,
	}, nil
}

// buildIndex builds a BST to quickly search through all syscalls.
func buildIndex(rules []RuleSet, program *syscallProgram) error {
	// Do nothing if rules is empty.
	if len(rules) == 0 {
		return nil
	}

	// Build a list of all application system calls, across all given rule
	// sets. We have a simple BST, but may dispatch individual matchers
	// with different actions. The matchers are evaluated linearly.
	requiredSyscalls := make(map[uintptr]struct{})
	for _, rs := range rules {
		for sysno := range rs.Rules.rules {
			requiredSyscalls[sysno] = struct{}{}
		}
	}
	syscalls := make([]uintptr, 0, len(requiredSyscalls))
	for sysno := range requiredSyscalls {
		syscalls = append(syscalls, sysno)
	}
	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	for _, sysno := range syscalls {
		for _, rs := range rules {
			// Print only if there is a corresponding set of rules.
			if r, ok := rs.Rules.rules[sysno]; ok {
				log.Debugf("syscall filter %v: %s => 0x%x", SyscallName(sysno), r, rs.Action)
			}
		}
	}

	root := createBST(syscalls)
	root.root = true

	// Load syscall number into A and run through BST.
	//
	// A = seccomp_data.nr
	program.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetNR)
	return root.traverse(buildBSTProgram, rules, program)
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

// buildBSTProgram converts a binary tree started in 'root' into BPF code. The outline of the code
// is as follows:
//
// // SYS_PIPE(22), root
//
//	(A == 22) ? goto argument check : continue
//	(A > 22) ? goto index_35 : goto index_9
//
// index_9:  // SYS_MMAP(9), leaf
//
//	A == 9) ? goto argument check : defaultLabel
//
// index_35:  // SYS_NANOSLEEP(35), single child
//
//	(A == 35) ? goto argument check : continue
//	(A > 35) ? goto index_50 : goto defaultLabel
//
// index_50:  // SYS_LISTEN(50), leaf
//
//	(A == 50) ? goto argument check : goto defaultLabel
func buildBSTProgram(n *node, rules []RuleSet, program *syscallProgram) error {
	// Root node is never referenced by label, skip it.
	if !n.root {
		program.Label(n.label())
	}

	nodeLabelSet := &labelSet{prefix: string(n.label())}

	sysno := n.value
	frag := program.Record()
	checkArgsLabel := label(fmt.Sprintf("checkArgs_%d", sysno))
	program.If(bpf.Jmp|bpf.Jeq|bpf.K, uint32(sysno), checkArgsLabel)
	if n.left == nil && n.right == nil {
		// Leaf nodes don't require extra check.
		program.JumpTo(defaultLabel)
	} else {
		// Non-leaf node. Check which turn to take.
		program.If(bpf.Jmp|bpf.Jgt|bpf.K, uint32(sysno), n.right.label())
		program.JumpTo(n.left.label())
	}
	frag.MustHaveJumpedTo(n.left.label(), n.right.label(), checkArgsLabel)
	program.Label(checkArgsLabel)

	for ruleSetIdx, rs := range rules {
		rule, ok := rs.Rules.rules[sysno]
		if !ok {
			continue
		}
		ruleSetLabelSet := nodeLabelSet.Push(fmt.Sprintf("rs[%d]", ruleSetIdx), nodeLabelSet.NewLabel(), nodeLabelSet.NewLabel())
		frag := program.Record()

		// Emit a vsyscall check if this rule requires a
		// Vsyscall match. This rule ensures that the top bit
		// is set in the instruction pointer, which is where
		// the vsyscall page will be mapped.
		if rs.Vsyscall {
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetIPHigh)
			program.IfNot(bpf.Jmp|bpf.Jset|bpf.K, vsyscallPageIPMask, ruleSetLabelSet.Mismatched())
		}

		// Add an argument check for these particular
		// arguments. This will continue execution and
		// check the next rule set. We need to ensure
		// that at the very end, we insert a direct
		// jump label for the unmatched case.
		optimizeSyscallRule(rule).Render(program, ruleSetLabelSet)
		frag.MustHaveJumpedTo(ruleSetLabelSet.Matched(), ruleSetLabelSet.Mismatched())
		program.Label(ruleSetLabelSet.Matched())
		program.Ret(rs.Action)
		program.Label(ruleSetLabelSet.Mismatched())
	}
	program.JumpTo(defaultLabel)
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

type traverseFunc func(*node, []RuleSet, *syscallProgram) error

func (n *node) traverse(fn traverseFunc, rules []RuleSet, program *syscallProgram) error {
	if n == nil {
		return nil
	}
	if err := fn(n, rules, program); err != nil {
		return err
	}
	if err := n.left.traverse(fn, rules, program); err != nil {
		return err
	}
	return n.right.traverse(fn, rules, program)
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
