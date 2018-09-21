// Copyright 2018 Google Inc.
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

	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/bpf"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/strace"
)

const (
	// violationLabel is added to the program to take action on a violation.
	violationLabel = "violation"

	// skipOneInst is the offset to take for skipping one instruction.
	skipOneInst = 1
)

// Install generates BPF code based on the set of syscalls provided. It only
// allows syscalls that conform to the specification (*) and generates SIGSYS
// trap unless kill is set.
//
// (*) The current implementation only checks the syscall number. It does NOT
// validate any of the arguments.
func Install(rules SyscallRules, kill bool) error {
	log.Infof("Installing seccomp filters for %d syscalls (kill=%t)", len(rules), kill)
	instrs, err := buildProgram(rules, kill)
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

	if err := seccomp(instrs); err != nil {
		return err
	}

	log.Infof("Seccomp filters installed.")
	return nil
}

// buildProgram builds a BPF program that whitelists all given syscall rules.
func buildProgram(rules SyscallRules, kill bool) ([]linux.BPFInstruction, error) {
	program := bpf.NewProgramBuilder()
	violationAction := uint32(linux.SECCOMP_RET_KILL)
	if !kill {
		violationAction = linux.SECCOMP_RET_TRAP
	}

	// Be paranoid and check that syscall is done in the expected architecture.
	//
	// A = seccomp_data.arch
	// if (A != AUDIT_ARCH_X86_64) goto violation
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArch)
	// violationLabel is at the bottom of the program. The size of program
	// may exceeds 255 lines, which is the limit of a condition jump.
	program.AddJump(bpf.Jmp|bpf.Jeq|bpf.K, linux.AUDIT_ARCH_X86_64, skipOneInst, 0)
	program.AddDirectJumpLabel(violationLabel)

	if err := buildIndex(rules, program); err != nil {
		return nil, err
	}

	// violation: return violationAction
	if err := program.AddLabel(violationLabel); err != nil {
		return nil, err
	}
	program.AddStmt(bpf.Ret|bpf.K, violationAction)

	return program.Instructions()
}

// buildIndex builds a BST to quickly search through all syscalls that are whitelisted.
func buildIndex(rules SyscallRules, program *bpf.ProgramBuilder) error {
	syscalls := []uintptr{}
	for sysno := range rules {
		syscalls = append(syscalls, sysno)
	}

	t, ok := strace.Lookup(abi.Linux, arch.AMD64)
	if !ok {
		panic("Can't find amd64 Linux syscall table")
	}

	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	for _, s := range syscalls {
		log.Infof("syscall filter: %v (%v): %s", s, t.Name(s), rules[s])
	}

	root := createBST(syscalls)
	root.root = true

	// Load syscall number into A and run through BST.
	//
	// A = seccomp_data.nr
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetNR)
	return root.traverse(buildBSTProgram, program, rules)
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

func ruleViolationLabel(sysno uintptr, idx int) string {
	return fmt.Sprintf("ruleViolation_%v_%v", sysno, idx)
}

func checkArgsLabel(sysno uintptr) string {
	return fmt.Sprintf("checkArgs_%v", sysno)
}

func addSyscallArgsCheck(p *bpf.ProgramBuilder, rules []Rule, sysno uintptr) error {
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
					p.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, low, 0, ruleViolationLabel(sysno, ruleidx))
					// assert arg_high == high
					p.AddStmt(bpf.Ld|bpf.Abs|bpf.W, seccompDataOffsetArgHigh(i))
					p.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, high, 0, ruleViolationLabel(sysno, ruleidx))
					labelled = true

				default:
					return fmt.Errorf("unknown syscall rule type: %v", reflect.TypeOf(a))
				}
			}
		}
		// Matched, allow the syscall.
		p.AddStmt(bpf.Ret|bpf.K, linux.SECCOMP_RET_ALLOW)
		// Label the end of the rule if necessary.
		if labelled {
			if err := p.AddLabel(ruleViolationLabel(sysno, ruleidx)); err != nil {
				return err
			}
		}
	}
	// Not matched?
	p.AddDirectJumpLabel(violationLabel)
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
//   A == 9) ? goto argument check : violation
//
// index_35:  // SYS_NANOSLEEP(35), single child
//   (A == 35) ? goto argument check : continue
//   (A > 35) ? goto index_50 : goto violation
//
// index_50:  // SYS_LISTEN(50), leaf
//   (A == 50) ? goto argument check : goto violation
//
func buildBSTProgram(program *bpf.ProgramBuilder, rules SyscallRules, n *node) error {
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
		program.AddDirectJumpLabel(violationLabel)
	} else {
		// Non-leaf node. Check which turn to take otherwise. Using direct jumps
		// in case that the offset may exceed the limit of a conditional jump (255)
		// Note that 'violationLabel' is returned for nil children.
		program.AddJump(bpf.Jmp|bpf.Jgt|bpf.K, uint32(sysno), 0, skipOneInst)
		program.AddDirectJumpLabel(n.right.label())
		program.AddDirectJumpLabel(n.left.label())
	}

	if err := program.AddLabel(checkArgsLabel(sysno)); err != nil {
		return err
	}
	// No rules, just allow it and save one jmp.
	if len(rules[sysno]) == 0 {
		program.AddStmt(bpf.Ret|bpf.K, linux.SECCOMP_RET_ALLOW)
		return nil
	}
	return addSyscallArgsCheck(program, rules[sysno], sysno)
}

// node represents a tree node.
type node struct {
	value uintptr
	left  *node
	right *node
	root  bool
}

// label returns the label corresponding to this node. If node is nil (syscall not present),
// violationLabel is returned for convenience.
func (n *node) label() string {
	if n == nil {
		return violationLabel
	}
	return fmt.Sprintf("index_%v", n.value)
}

type traverseFunc func(*bpf.ProgramBuilder, SyscallRules, *node) error

func (n *node) traverse(fn traverseFunc, p *bpf.ProgramBuilder, rules SyscallRules) error {
	if n == nil {
		return nil
	}
	if err := fn(p, rules, n); err != nil {
		return err
	}
	if err := n.left.traverse(fn, p, rules); err != nil {
		return err
	}
	return n.right.traverse(fn, p, rules)
}
