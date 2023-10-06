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

package seccomp

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/bpf"
)

// The offsets are based on the following struct in include/linux/seccomp.h.
//
//	struct seccomp_data {
//		int nr;
//		__u32 arch;
//		__u64 instruction_pointer;
//		__u64 args[6];
//	};
const (
	seccompDataOffsetNR     = 0
	seccompDataOffsetArch   = 4
	seccompDataOffsetIPLow  = 8
	seccompDataOffsetIPHigh = 12
	seccompDataOffsetArgs   = 16
)

func seccompDataOffsetArgLow(i int) uint32 {
	return uint32(seccompDataOffsetArgs + i*8)
}

func seccompDataOffsetArgHigh(i int) uint32 {
	return seccompDataOffsetArgLow(i) + 4
}

// AnyValue is marker to indicate any value will be accepted.
type AnyValue struct{}

func (AnyValue) String() string {
	return "*"
}

// EqualTo specifies a value that needs to be strictly matched.
type EqualTo uintptr

func (a EqualTo) String() string {
	return fmt.Sprintf("== %#x", uintptr(a))
}

// NotEqual specifies a value that is strictly not equal.
type NotEqual uintptr

func (a NotEqual) String() string {
	return fmt.Sprintf("!= %#x", uintptr(a))
}

// GreaterThan specifies a value that needs to be strictly smaller.
type GreaterThan uintptr

func (a GreaterThan) String() string {
	return fmt.Sprintf("> %#x", uintptr(a))
}

// GreaterThanOrEqual specifies a value that needs to be smaller or equal.
type GreaterThanOrEqual uintptr

func (a GreaterThanOrEqual) String() string {
	return fmt.Sprintf(">= %#x", uintptr(a))
}

// LessThan specifies a value that needs to be strictly greater.
type LessThan uintptr

func (a LessThan) String() string {
	return fmt.Sprintf("< %#x", uintptr(a))
}

// LessThanOrEqual specifies a value that needs to be greater or equal.
type LessThanOrEqual uintptr

func (a LessThanOrEqual) String() string {
	return fmt.Sprintf("<= %#x", uintptr(a))
}

type maskedEqual struct {
	mask  uintptr
	value uintptr
}

func (a maskedEqual) String() string {
	return fmt.Sprintf("& %#x == %#x", a.mask, a.value)
}

// MaskedEqual specifies a value that matches the input after the input is
// masked (bitwise &) against the given mask. Can be used to verify that input
// only includes certain approved flags.
func MaskedEqual(mask, value uintptr) any {
	return maskedEqual{
		mask:  mask,
		value: value,
	}
}

// SyscallRule expresses a set of rules to verify the arguments of a specific
// syscall.
type SyscallRule interface {
	// Render renders the syscall rule in the given `program`.
	// The emitted instructions **must** end up jumping to either
	// `labelSet.Matched()` or `labelSet.Mismatched()`; they may
	// not "fall through" to whatever instructions will be added
	// next into the program.
	Render(program *syscallProgram, labelSet *labelSet)

	// String returns a human-readable string representing what the rule does.
	String() string
}

// MatchAll implements `SyscallRule` and matches everything.
type MatchAll struct{}

// Render implements `SyscallRule.Render`.
func (MatchAll) Render(program *syscallProgram, labelSet *labelSet) {
	program.JumpTo(labelSet.Matched())
}

// String implements `SyscallRule.String`.
func (MatchAll) String() string { return "true" }

// Or expresses an "OR" (a disjunction) over a set of `SyscallRule`s.
// If an Or is empty, it will not match anything.
type Or []SyscallRule

// Render implements `SyscallRule.Render`.
func (or Or) Render(program *syscallProgram, labelSet *labelSet) {
	// If `len(or) == 1`, this will be optimized away to be the same as
	// rendering the single rule in the disjunction.
	for i, rule := range or {
		frag := program.Record()
		nextRuleLabel := labelSet.NewLabel()
		rule.Render(program, labelSet.Push(fmt.Sprintf("or[%d]", i), labelSet.Matched(), nextRuleLabel))
		frag.MustHaveJumpedTo(labelSet.Matched(), nextRuleLabel)
		program.Label(nextRuleLabel)
	}
	program.JumpTo(labelSet.Mismatched())
}

// String implements `SyscallRule.String`.
func (or Or) String() string {
	switch len(or) {
	case 0:
		return "false"
	case 1:
		return or[0].String()
	default:
		var sb strings.Builder
		sb.WriteRune('(')
		for i, rule := range or {
			if i != 0 {
				sb.WriteString(" || ")
			}
			sb.WriteString(rule.String())
		}
		sb.WriteRune(')')
		return sb.String()
	}
}

// merge merges `rule1` and `rule2`, simplifying `MatchAll` and `Or` rules.
func merge(rule1, rule2 SyscallRule) SyscallRule {
	_, rule1IsMatchAll := rule1.(MatchAll)
	_, rule2IsMatchAll := rule2.(MatchAll)
	if rule1IsMatchAll || rule2IsMatchAll {
		return MatchAll{}
	}
	rule1Or, rule1IsOr := rule1.(Or)
	rule2Or, rule2IsOr := rule2.(Or)
	if rule1IsOr && rule2IsOr {
		return append(rule1Or, rule2Or...)
	}
	if rule1IsOr {
		return append(rule1Or, rule2)
	}
	if rule2IsOr {
		return append(rule2Or, rule1)
	}
	return Or{rule1, rule2}
}

// PerArg implements SyscallRule and verifies the syscall arguments and RIP.
//
// For example:
//
//	rule := PerArg{
//		EqualTo(linux.ARCH_GET_FS | linux.ARCH_SET_FS), // arg0
//	}
type PerArg [7]any // 6 arguments + RIP

// RuleIP indicates what rules in the Rule array have to be applied to
// instruction pointer.
const RuleIP = 6

// Render implements `SyscallRule.Render`.
func (pa PerArg) Render(program *syscallProgram, labelSet *labelSet) {
	for i, arg := range pa {
		if arg == nil {
			continue
		}

		frag := program.Record()
		nextArgLabel := labelSet.NewLabel()
		labelSuffix := fmt.Sprintf("arg[%d]", i)
		// Determine the data offset for low and high bits of input.
		dataOffsetLow := seccompDataOffsetArgLow(i)
		dataOffsetHigh := seccompDataOffsetArgHigh(i)
		if i == RuleIP {
			dataOffsetLow = seccompDataOffsetIPLow
			dataOffsetHigh = seccompDataOffsetIPHigh
			labelSuffix = "rip"
		}
		ls := labelSet.Push(labelSuffix, nextArgLabel, labelSet.Mismatched())

		// Add the conditional operation. Input values to the BPF
		// program are 64bit values.  However, comparisons in BPF can
		// only be done on 32bit values. This means that we need to
		// operate on each 32bit half in order to do one logical 64bit
		// comparison.
		switch a := arg.(type) {
		case AnyValue:
			program.JumpTo(ls.Matched())
		case EqualTo:
			// EqualTo checks that both the higher and lower 32bits are equal.
			high, low := uint32(a>>32), uint32(a)

			// Assert that the lower 32bits are equal.
			// arg_low == low ? continue : violation
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, low, ls.Mismatched())

			// Assert that the higher 32bits are also equal.
			// arg_high == high ? continue/success : violation
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Mismatched())
			program.JumpTo(ls.Matched())
		case NotEqual:
			// NotEqual checks that either the higher or lower 32bits
			// are *not* equal.
			high, low := uint32(a>>32), uint32(a)

			// Check if the higher 32bits are (not) equal.
			// arg_low != low ? success : continue
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, low, ls.Matched())

			// Assert that the lower 32bits are not equal (assuming
			// higher bits are equal).
			// arg_high != high ? success : violation
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Matched())
			program.JumpTo(ls.Mismatched())
		case GreaterThan:
			// GreaterThan checks that the higher 32bits is greater
			// *or* that the higher 32bits are equal and the lower
			// 32bits are greater.
			high, low := uint32(a>>32), uint32(a)

			// Assert the higher 32bits are greater than or equal.
			// arg_high >= high ? continue : violation (arg_high < high)
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, high, ls.Mismatched())

			// Assert that the lower 32bits are greater.
			// arg_high == high ? continue : success (arg_high > high)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Matched())
			// arg_low > low ? continue/success : violation (arg_high == high and arg_low <= low)
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.IfNot(bpf.Jmp|bpf.Jgt|bpf.K, low, ls.Mismatched())
			program.JumpTo(ls.Matched())
		case GreaterThanOrEqual:
			// GreaterThanOrEqual checks that the higher 32bits is
			// greater *or* that the higher 32bits are equal and the
			// lower 32bits are greater than or equal.
			high, low := uint32(a>>32), uint32(a)

			// Assert the higher 32bits are greater than or equal.
			// arg_high >= high ? continue : violation (arg_high < high)
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, high, ls.Mismatched())
			// arg_high == high ? continue : success (arg_high > high)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Matched())

			// Assert that the lower 32bits are greater (assuming the
			// higher bits are equal).
			// arg_low >= low ? continue/success : violation (arg_high == high and arg_low < low)
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, low, ls.Mismatched())
			program.JumpTo(ls.Matched())
		case LessThan:
			// LessThan checks that the higher 32bits is less *or* that
			// the higher 32bits are equal and the lower 32bits are
			// less.
			high, low := uint32(a>>32), uint32(a)

			// Assert the higher 32bits are less than or equal.
			// arg_high > high ? violation : continue
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.If(bpf.Jmp|bpf.Jgt|bpf.K, high, ls.Mismatched())
			// arg_high == high ? continue : success (arg_high < high)
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Matched())

			// Assert that the lower 32bits are less (assuming the
			// higher bits are equal).
			// arg_low >= low ? violation : continue
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.If(bpf.Jmp|bpf.Jge|bpf.K, low, ls.Mismatched())
			program.JumpTo(ls.Matched())
		case LessThanOrEqual:
			// LessThan checks that the higher 32bits is less *or* that
			// the higher 32bits are equal and the lower 32bits are
			// less than or equal.
			high, low := uint32(a>>32), uint32(a)

			// Assert the higher 32bits are less than or equal.
			// assert arg_high > high ? violation : continue
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			program.If(bpf.Jmp|bpf.Jgt|bpf.K, high, ls.Mismatched())
			// arg_high == high ? continue : success
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Matched())

			// Assert the lower bits are less than or equal (assuming
			// the higher bits are equal).
			// arg_low > low ? violation : success
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			program.If(bpf.Jmp|bpf.Jgt|bpf.K, low, ls.Mismatched())
			program.JumpTo(ls.Matched())
		case maskedEqual:
			// MaskedEqual checks that the bitwise AND of the value and
			// mask are equal for both the higher and lower 32bits.
			high, low := uint32(a.value>>32), uint32(a.value)
			maskHigh, maskLow := uint32(a.mask>>32), uint32(a.mask)

			// Assert that the lower 32bits are equal when masked.
			// A <- arg_low.
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetLow)
			// A <- arg_low & maskLow
			program.Stmt(bpf.Alu|bpf.And|bpf.K, maskLow)
			// Assert that arg_low & maskLow == low.
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, low, ls.Mismatched())

			// Assert that the higher 32bits are equal when masked.
			// A <- arg_high
			program.Stmt(bpf.Ld|bpf.Abs|bpf.W, dataOffsetHigh)
			// A <- arg_high & maskHigh
			program.Stmt(bpf.Alu|bpf.And|bpf.K, maskHigh)
			// Assert that arg_high & maskHigh == high.
			program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, ls.Mismatched())
			program.JumpTo(ls.Matched())
		default:
			panic(fmt.Sprintf("unknown syscall rule type: %v", reflect.TypeOf(a)))
		}
		frag.MustHaveJumpedTo(ls.Matched(), ls.Mismatched())
		program.Label(nextArgLabel)
	}

	// Matched all argument-wise rules, jump to the final rule matched label.
	program.JumpTo(labelSet.Matched())
}

// String implements `SyscallRule.String`.
func (pa PerArg) String() (s string) {
	if len(pa) == 0 {
		return
	}
	s += "( "
	for _, arg := range pa {
		if arg != nil {
			s += fmt.Sprintf("%v ", arg)
		}
	}
	s += ")"
	return
}

// SyscallRules maps syscall numbers to their corresponding rules.
//
// For example:
//
//	rules := SyscallRules{
//	       syscall.SYS_FUTEX: Or{
//	               PerArg{
//	                       AnyValue{},
//	                       EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
//	               },
//	               PerArg{
//	                       AnyValue{},
//	                       EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
//	               },
//	       },
//	       syscall.SYS_GETPID: MatchAll{},
//
// }
type SyscallRules map[uintptr]SyscallRule

// NewSyscallRules returns a new SyscallRules.
func NewSyscallRules() SyscallRules {
	return make(map[uintptr]SyscallRule)
}

// String returns a string representation of the syscall rules, one syscall
// per line.
func (sr SyscallRules) String() string {
	if len(sr) == 0 {
		return "(no rules)"
	}
	sysnums := make([]uintptr, 0, len(sr))
	for sysno := range sr {
		sysnums = append(sysnums, sysno)
	}
	sort.Slice(sysnums, func(i, j int) bool {
		return sysnums[i] < sysnums[j]
	})
	var sb strings.Builder
	for _, sysno := range sysnums {
		sb.WriteString(fmt.Sprintf("syscall %d: %v\n", sysno, sr[sysno]))
	}
	return strings.TrimSpace(sb.String())
}

// AddRule adds the given rule. It will create a new entry for a new syscall, otherwise
// it will append to the existing rules.
func (sr SyscallRules) AddRule(sysno uintptr, r SyscallRule) {
	if cur, ok := sr[sysno]; ok {
		sr[sysno] = merge(cur, r)
	} else {
		sr[sysno] = r
	}
}

// Merge merges the given SyscallRules.
func (sr SyscallRules) Merge(other SyscallRules) {
	for sysno, r := range other {
		if cur, ok := sr[sysno]; ok {
			sr[sysno] = merge(cur, r)
		} else {
			sr[sysno] = r
		}
	}
}

// DenyNewExecMappings is a set of rules that denies creating new executable
// mappings and converting existing ones.
var DenyNewExecMappings = SyscallRules{
	unix.SYS_MMAP: PerArg{
		AnyValue{},
		AnyValue{},
		MaskedEqual(unix.PROT_EXEC, unix.PROT_EXEC),
	},
	unix.SYS_MPROTECT: PerArg{
		AnyValue{},
		AnyValue{},
		MaskedEqual(unix.PROT_EXEC, unix.PROT_EXEC),
	},
}
