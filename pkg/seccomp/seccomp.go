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

// Package seccomp provides basic seccomp filters.
package seccomp

import (
	"fmt"
	"sort"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/bpf"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

const (
	// violationLabel is added to the program to take action on a violation.
	violationLabel = "violation"

	// allowLabel is added to the program to allow the syscall to take place.
	allowLabel = "allow"
)

// Install generates BPF code based on the set of syscalls provided. It only
// allows syscalls that conform to the specification (*) and generates SIGSYS
// trap unless kill is set.
//
// (*) The current implementation only checks the syscall number. It does NOT
// validate any of the arguments.
func Install(syscalls []uintptr, kill bool) error {
	// Sort syscalls and remove duplicates to build the BST.
	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	syscalls = filterUnique(syscalls)

	log.Infof("Installing seccomp filters for %d syscalls (kill=%t)", len(syscalls), kill)
	for _, s := range syscalls {
		log.Infof("syscall filter: %v", s)
	}

	instrs, err := buildProgram(syscalls, kill)
	if err != nil {
		return err
	}
	if log.IsLogging(log.Debug) {
		programStr, err := bpf.DecodeProgram(instrs)
		if err != nil {
			programStr = fmt.Sprintf("Error: %v\n%s", err, programStr)
		}
		log.Debugf("Seccomp program dump:\n%s", programStr)
	}

	if err := seccomp(instrs); err != nil {
		return err
	}

	log.Infof("Seccomp filters installed.")
	return nil
}

// buildProgram builds a BPF program that whitelists all given syscalls.
//
// Precondition: syscalls must be sorted and unique.
func buildProgram(syscalls []uintptr, kill bool) ([]linux.BPFInstruction, error) {
	const archOffset = 4 // offsetof(seccomp_data, arch)
	program := bpf.NewProgramBuilder()
	violationAction := uint32(linux.SECCOMP_RET_KILL)
	if !kill {
		violationAction = linux.SECCOMP_RET_TRAP
	}

	// Be paranoid and check that syscall is done in the expected architecture.
	//
	// A = seccomp_data.arch
	// if (A != AUDIT_ARCH_X86_64) goto violation
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, archOffset)
	program.AddJumpFalseLabel(bpf.Jmp|bpf.Jeq|bpf.K, linux.AUDIT_ARCH_X86_64, 0, violationLabel)

	if err := buildIndex(syscalls, program); err != nil {
		return nil, err
	}

	// violation: return violationAction
	if err := program.AddLabel(violationLabel); err != nil {
		return nil, err
	}
	program.AddStmt(bpf.Ret|bpf.K, violationAction)

	// allow: return SECCOMP_RET_ALLOW
	if err := program.AddLabel(allowLabel); err != nil {
		return nil, err
	}
	program.AddStmt(bpf.Ret|bpf.K, linux.SECCOMP_RET_ALLOW)

	return program.Instructions()
}

// filterUnique filters unique system calls.
//
// Precondition: syscalls must be sorted.
func filterUnique(syscalls []uintptr) []uintptr {
	filtered := make([]uintptr, 0, len(syscalls))
	for i := 0; i < len(syscalls); i++ {
		if len(filtered) > 0 && syscalls[i] == filtered[len(filtered)-1] {
			// This call has already been inserted, skip.
			continue
		}
		filtered = append(filtered, syscalls[i])
	}
	return filtered
}

// buildIndex builds a BST to quickly search through all syscalls that are whitelisted.
//
// Precondition: syscalls must be sorted and unique.
func buildIndex(syscalls []uintptr, program *bpf.ProgramBuilder) error {
	root := createBST(syscalls)

	// Load syscall number into A and run through BST.
	//
	// A = seccomp_data.nr
	program.AddStmt(bpf.Ld|bpf.Abs|bpf.W, 0)
	return root.buildBSTProgram(program, true)
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

// node represents a tree node.
type node struct {
	value uintptr
	left  *node
	right *node
}

// label returns the label corresponding to this node. If node is nil (syscall not present),
// violationLabel is returned for convenience.
func (n *node) label() string {
	if n == nil {
		return violationLabel
	}
	return fmt.Sprintf("index_%v", n.value)
}

// buildBSTProgram converts a binary tree started in 'root' into BPF code. The ouline of the code
// is as follows:
//
// // SYS_PIPE(22), root
//   (A == 22) ? goto allow : continue
//   (A > 22) ? goto index_35 : goto index_9
//
// index_9:  // SYS_MMAP(9), leaf
//   (A == 9) ? goto allow : goto violation
//
// index_35:  // SYS_NANOSLEEP(35), single child
//   (A == 35) ? goto allow : continue
//   (A > 35) ? goto index_50 : goto violation
//
// index_50:  // SYS_LISTEN(50), leaf
//   (A == 50) ? goto allow : goto violation
//
func (n *node) buildBSTProgram(program *bpf.ProgramBuilder, root bool) error {
	if n == nil {
		return nil
	}

	// Root node is never referenced by label, skip it.
	if !root {
		if err := program.AddLabel(n.label()); err != nil {
			return err
		}
	}

	// Leaf nodes don't require extra check, they either allow or violate!
	if n.left == nil && n.right == nil {
		program.AddJumpLabels(bpf.Jmp|bpf.Jeq|bpf.K, uint32(n.value), allowLabel, violationLabel)
		return nil
	}

	// Non-leaf node. Allows syscall if it matches, check which turn to take otherwise. Note
	// that 'violationLabel' is returned for nil children.
	program.AddJumpTrueLabel(bpf.Jmp|bpf.Jeq|bpf.K, uint32(n.value), allowLabel, 0)
	program.AddJumpLabels(bpf.Jmp|bpf.Jgt|bpf.K, uint32(n.value), n.right.label(), n.left.label())

	if err := n.left.buildBSTProgram(program, false); err != nil {
		return err
	}
	return n.right.buildBSTProgram(program, false)
}
