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

// Package seccomp provides basic seccomp filters for x86_64 (little endian).
package seccomp

import (
	"fmt"
	"reflect"
	"sort"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/bpf"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

const (
	// skipOneInst is the offset to take for skipping one instruction.
	skipOneInst = 1

	// defaultLabel is the label for the default action.
	defaultLabel = "default_action"
)

// Install generates BPF code based on the set of syscalls provided. It only
// allows syscalls that conform to the specification. Syscalls that violate the
// specification will trigger RET_KILL_PROCESS, except for the cases below.
//
// RET_TRAP is used in violations, instead of RET_KILL_PROCESS, in the
// following cases:
//	 1. Kernel doesn't support RET_KILL_PROCESS: RET_KILL_THREAD only kills the
//      offending thread and often keeps the sentry hanging.
//   2. Debug: RET_TRAP generates a panic followed by a stack trace which is
//      much easier to debug then RET_KILL_PROCESS which can't be caught.
//
// Be aware that RET_TRAP sends SIGSYS to the process and it may be ignored,
// making it possible for the process to continue running after a violation.
// However, it will leave a SECCOMP audit event trail behind. In any case, the
// syscall is still blocked from executing.
func Install(rules SyscallRules) error {
	defaultAction, err := defaultAction()
	if err != nil {
		return err
	}

	// Uncomment to get stack trace when there is a violation.
	// defaultAction = linux.BPFAction(linux.SECCOMP_RET_TRAP)

	log.Infof("Installing seccomp filters for %d syscalls (action=%v)", len(rules), defaultAction)

	instrs, err := BuildProgram([]RuleSet{
		RuleSet{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, defaultAction)
	if log.IsLogging(log.Debug) {
		programStr, errDecode := bpf.DecodeProgram(instrs)
		if errDecode != nil {
			programStr = fmt.Sprintf("Error: %v\n%s", errDecode, programStr)
		}
		log.Debugf("Seccomp program dump:\n%s", programStr)
	}
	if err != nil {
		return err
	}

	// Perform the actual installation.
	if errno := SetFilter(instrs); errno != 0 {
		return fmt.Errorf("Failed to set filter: %v", errno)
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

// BuildProgram builds a BPF program from the given map of actions to matching
// SyscallRules. The single generated program covers all provided RuleSets.
func BuildProgram(rules []RuleSet, defaultAction linux.BPFAction) ([]linux.BPFInstruction, error) {
	program := bpf.NewProgramBuilder()

	// Be paranoid and check that syscall is done in the expected architecture.
	//
	// A = seccomp_data.arch
	// if (A != AUDIT_ARCH_X86_64) goto defaultAction.
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArch)
	// defaultLabel is at the bottom of the program. The size of program
	// may exceeds 255 lines, which is the limit of a condition jump.
	program.AddJump(bpf.Jmp|bpf.Jeq|bpf.K, linux.AUDIT_ARCH_X86_64, skipOneInst, 0)
	program.AddDirectJumpLabel(defaultLabel)
	if err := buildIndex(rules, program); err != nil {
		return nil, err
	}

	// Exhausted: return defaultAction.
	if err := program.AddLabel(defaultLabel); err != nil {
		return nil, err
	}
	program.AddStmt(bpf.Ret|bpf.K, uint32(defaultAction))

	return program.Instructions()
}

// buildIndex builds a BST to quickly search through all syscalls.
func buildIndex(rules []RuleSet, program *bpf.ProgramBuilder) error {
	// Build a list of all application system calls, across all given rule
	// sets. We have a simple BST, but may dispatch individual matchers
	// with different actions. The matchers are evaluated linearly.
	requiredSyscalls := make(map[uintptr]struct{})
	for _, rs := range rules {
		for sysno := range rs.Rules {
			requiredSyscalls[sysno] = struct{}{}
		}
	}
	syscalls := make([]uintptr, 0, len(requiredSyscalls))
	for sysno, _ := range requiredSyscalls {
		syscalls = append(syscalls, sysno)
	}
	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	for _, sysno := range syscalls {
		for _, rs := range rules {
			// Print only if there is a corresponding set of rules.
			if _, ok := rs.Rules[sysno]; ok {
				log.Debugf("syscall filter %v: %s => 0x%x", SyscallName(sysno), rs.Rules[sysno], rs.Action)
			}
		}
	}

	root := createBST(syscalls)
	root.root = true

	// Load syscall number into A and run through BST.
	//
	// A = seccomp_data.nr
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetNR)
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

func vsyscallViolationLabel(ruleSetIdx int, sysno uintptr) string {
	return fmt.Sprintf("vsyscallViolation_%v_%v", ruleSetIdx, sysno)
}

func ruleViolationLabel(ruleSetIdx int, sysno uintptr, idx int) string {
	return fmt.Sprintf("ruleViolation_%v_%v_%v", ruleSetIdx, sysno, idx)
}

func checkArgsLabel(sysno uintptr) string {
	return fmt.Sprintf("checkArgs_%v", sysno)
}

// addSyscallArgsCheck adds argument checks for a single system call. It does
// not insert a jump to the default action at the end and it is the
// responsibility of the caller to insert an appropriate jump after calling
// this function.
func addSyscallArgsCheck(p *bpf.ProgramBuilder, rules []Rule, action linux.BPFAction, ruleSetIdx int, sysno uintptr) error {
	for ruleidx, rule := range rules {
		labelled := false
		for i, arg := range rule {
			if arg != nil {
				switch a := arg.(type) {
				case AllowAny:
				case AllowValue:
					high, low := uint32(a>>32), uint32(a)
					// assert arg_low == low
					p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArgLow(i))
					p.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, low, 0, ruleViolationLabel(ruleSetIdx, sysno, ruleidx))
					// assert arg_high == high
					p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArgHigh(i))
					p.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, high, 0, ruleViolationLabel(ruleSetIdx, sysno, ruleidx))
					labelled = true
				default:
					return fmt.Errorf("unknown syscall rule type: %v", reflect.TypeOf(a))
				}
			}
		}

		// Matched, emit the given action.
		p.AddStmt(bpf.Ret|bpf.K, uint32(action))

		// Label the end of the rule if necessary. This is added for
		// the jumps above when the argument check fails.
		if labelled {
			if err := p.AddLabel(ruleViolationLabel(ruleSetIdx, sysno, ruleidx)); err != nil {
				return err
			}
		}
	}

	return nil
}

// buildBSTProgram converts a binary tree started in 'root' into BPF code. The ouline of the code
// is as follows:
//
// // SYS_PIPE(22), root
//   (A == 22) ? goto argument check : continue
//   (A > 22) ? goto index_35 : goto index_9
//
// index_9:  // SYS_MMAP(9), leaf
//   A == 9) ? goto argument check : defaultLabel
//
// index_35:  // SYS_NANOSLEEP(35), single child
//   (A == 35) ? goto argument check : continue
//   (A > 35) ? goto index_50 : goto defaultLabel
//
// index_50:  // SYS_LISTEN(50), leaf
//   (A == 50) ? goto argument check : goto defaultLabel
//
func buildBSTProgram(n *node, rules []RuleSet, program *bpf.ProgramBuilder) error {
	// Root node is never referenced by label, skip it.
	if !n.root {
		if err := program.AddLabel(n.label()); err != nil {
			return err
		}
	}

	sysno := n.value
	program.AddJumpTrueLabel(bpf.Jmp|bpf.Jeq|bpf.K, uint32(sysno), checkArgsLabel(sysno), 0)
	if n.left == nil && n.right == nil {
		// Leaf nodes don't require extra check.
		program.AddDirectJumpLabel(defaultLabel)
	} else {
		// Non-leaf node. Check which turn to take otherwise. Using direct jumps
		// in case that the offset may exceed the limit of a conditional jump (255)
		program.AddJump(bpf.Jmp|bpf.Jgt|bpf.K, uint32(sysno), 0, skipOneInst)
		program.AddDirectJumpLabel(n.right.label())
		program.AddDirectJumpLabel(n.left.label())
	}

	if err := program.AddLabel(checkArgsLabel(sysno)); err != nil {
		return err
	}

	emitted := false
	for ruleSetIdx, rs := range rules {
		if _, ok := rs.Rules[sysno]; ok {
			// If there are no rules, then this will always match.
			// Remember we've done this so that we can emit a
			// sensible error. We can't catch all overlaps, but we
			// can catch this one at least.
			if emitted {
				return fmt.Errorf("unreachable action for %v: 0x%x (rule set %d)", SyscallName(sysno), rs.Action, ruleSetIdx)
			}

			// Emit a vsyscall check if this rule requires a
			// Vsyscall match. This rule ensures that the top bit
			// is set in the instruction pointer, which is where
			// the vsyscall page will be mapped.
			if rs.Vsyscall {
				program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetIPHigh)
				program.AddJumpFalseLabel(bpf.Jmp|bpf.Jset|bpf.K, 0x80000000, 0, vsyscallViolationLabel(ruleSetIdx, sysno))
			}

			// Emit matchers.
			if len(rs.Rules[sysno]) == 0 {
				// This is a blanket action.
				program.AddStmt(bpf.Ret|bpf.K, uint32(rs.Action))
				emitted = true
			} else {
				// Add an argument check for these particular
				// arguments. This will continue execution and
				// check the next rule set. We need to ensure
				// that at the very end, we insert a direct
				// jump label for the unmatched case.
				if err := addSyscallArgsCheck(program, rs.Rules[sysno], rs.Action, ruleSetIdx, sysno); err != nil {
					return err
				}
			}

			// If there was a Vsyscall check for this rule, then we
			// need to add an appropriate label for the jump above.
			if rs.Vsyscall {
				if err := program.AddLabel(vsyscallViolationLabel(ruleSetIdx, sysno)); err != nil {
					return err
				}
			}
		}
	}

	// Not matched? We only need to insert a jump to the default label if
	// not default action has been emitted for this call.
	if !emitted {
		program.AddDirectJumpLabel(defaultLabel)
	}

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
func (n *node) label() string {
	if n == nil {
		return defaultLabel
	}
	return fmt.Sprintf("index_%v", n.value)
}

type traverseFunc func(*node, []RuleSet, *bpf.ProgramBuilder) error

func (n *node) traverse(fn traverseFunc, rules []RuleSet, p *bpf.ProgramBuilder) error {
	if n == nil {
		return nil
	}
	if err := fn(n, rules, p); err != nil {
		return err
	}
	if err := n.left.traverse(fn, rules, p); err != nil {
		return err
	}
	return n.right.traverse(fn, rules, p)
}
