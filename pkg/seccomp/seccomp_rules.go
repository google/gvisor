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

// ValueMatcher verifies a numerical value, typically a syscall argument
// or RIP value.
type ValueMatcher interface {
	// String returns a human-readable representation of the match rule.
	// If the returned string contains "VAL", it will be replaced with
	// the symbolic name of the value being matched against.
	String() string

	// Repr returns a string that will be used for asserting equality between
	// two `ValueMatcher` instances. It must therefore be unique to the
	// `ValueMatcher` implementation and to its parameters.
	// It must not contain the character ";".
	Repr() string

	// Render should add rules to the given program that verify the value
	// loadable from `value` matches this rule or not.
	// The rules should indicate this by either jumping to `labelSet.Matched()`
	// or `labelSet.Mismatched()`. They may not fall through.
	Render(program *syscallProgram, labelSet *labelSet, value matchedValue)

	// InterestingValues returns a list of values that may be interesting to
	// test this `ValueMatcher` against.
	InterestingValues() []uint64
}

// halfValueMatcher verifies a 32-bit value.
type halfValueMatcher interface {
	// String returns a human-friendly representation of the check being done
	// against the 32-bit value.
	// The string "x.(high|low) {{halfValueMatcher.String()}}" should read well,
	// e.g. "x.low == 0xffff".
	String() string

	// Repr returns a string that will be used for asserting equality between
	// two `halfValueMatcher` instances. It must therefore be unique to the
	// `halfValueMatcher` implementation and to its parameters.
	// It must not contain the character ";".
	Repr() string

	// HalfRender should add rules to the given program that verify the value
	// loaded into the "A" register matches this 32-bit value or not.
	// The rules should indicate this by either jumping to `labelSet.Matched()`
	// or `labelSet.Mismatched()`. They may not fall through.
	HalfRender(program *syscallProgram, labelSet *labelSet)

	// InterestingValues returns a list of values that may be interesting to
	// test this `halfValueMatcher` against.
	InterestingValues() []uint32
}

// halfAnyValue implements `halfValueMatcher` and matches any value.
type halfAnyValue struct{}

// String implements `halfValueMatcher.String`.
func (halfAnyValue) String() string {
	return "== *"
}

// Repr implements `halfValueMatcher.Repr`.
func (halfAnyValue) Repr() string {
	return "halfAnyValue"
}

// HalfRender implements `halfValueMatcher.HalfRender`.
func (halfAnyValue) HalfRender(program *syscallProgram, labelSet *labelSet) {
	program.JumpTo(labelSet.Matched())
}

// halfEqualTo implements `halfValueMatcher` and matches a specific 32-bit value.
type halfEqualTo uint32

// String implements `halfValueMatcher.String`.
func (heq halfEqualTo) String() string {
	if heq == 0 {
		return "== 0"
	}
	return fmt.Sprintf("== %#x", uint32(heq))
}

// Repr implements `halfValueMatcher.Repr`.
func (heq halfEqualTo) Repr() string {
	return fmt.Sprintf("halfEq(%#x)", uint32(heq))
}

// HalfRender implements `halfValueMatcher.HalfRender`.
func (heq halfEqualTo) HalfRender(program *syscallProgram, labelSet *labelSet) {
	program.If(bpf.Jmp|bpf.Jeq|bpf.K, uint32(heq), labelSet.Matched())
	program.JumpTo(labelSet.Mismatched())
}

// halfNotSet implements `halfValueMatcher` and matches using the "set"
// bitwise operation.
type halfNotSet uint32

// String implements `halfValueMatcher.String`.
func (hns halfNotSet) String() string {
	return fmt.Sprintf("& %#x == 0", uint32(hns))
}

// Repr implements `halfValueMatcher.Repr`.
func (hns halfNotSet) Repr() string {
	return fmt.Sprintf("halfNotSet(%#x)", uint32(hns))
}

// HalfRender implements `halfValueMatcher.HalfRender`.
func (hns halfNotSet) HalfRender(program *syscallProgram, labelSet *labelSet) {
	program.If(bpf.Jmp|bpf.Jset|bpf.K, uint32(hns), labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// halfMaskedEqual implements `halfValueMatcher` and verifies that the value
// is equal after applying a bit mask.
type halfMaskedEqual struct {
	mask  uint32
	value uint32
}

// String implements `halfValueMatcher.String`.
func (hmeq halfMaskedEqual) String() string {
	if hmeq.value == 0 {
		return fmt.Sprintf("& %#x == 0", hmeq.mask)
	}
	return fmt.Sprintf("& %#x == %#x", hmeq.mask, hmeq.value)
}

// Repr implements `halfValueMatcher.Repr`.
func (hmeq halfMaskedEqual) Repr() string {
	return fmt.Sprintf("halfMaskedEqual(%#x, %#x)", hmeq.mask, hmeq.value)
}

// HalfRender implements `halfValueMatcher.HalfRender`.
func (hmeq halfMaskedEqual) HalfRender(program *syscallProgram, labelSet *labelSet) {
	program.Stmt(bpf.Alu|bpf.And|bpf.K, hmeq.mask)
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, hmeq.value, labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// splitMatcher implements `ValueMatcher` and verifies each half of the 64-bit
// value independently (with AND semantics).
// It implements `ValueMatcher`, but is never used directly in seccomp filter
// rules. Rather, it acts as an intermediate representation for the rules that
// can be expressed as an AND of two 32-bit values.
type splitMatcher struct {
	// repr is the `Repr()` of the original `ValueMatcher` (pre-split).
	repr string
	// highMatcher is the half-value matcher to verify the high 32 bits.
	highMatcher halfValueMatcher
	// lowMatcher is the half-value matcher to verify the low 32 bits.
	lowMatcher halfValueMatcher
}

// String implements `ValueMatcher.String`.
func (sm splitMatcher) String() string {
	if sm.repr == "" {
		_, highIsAnyValue := sm.highMatcher.(halfAnyValue)
		_, lowIsAnyValue := sm.lowMatcher.(halfAnyValue)
		if highIsAnyValue && lowIsAnyValue {
			return "== *"
		}
		if highIsAnyValue {
			return fmt.Sprintf("VAL.low %s", sm.lowMatcher.String())
		}
		if lowIsAnyValue {
			return fmt.Sprintf("VAL.high %s", sm.highMatcher.String())
		}
		return fmt.Sprintf("(VAL.high %s && VAL.low %s)", sm.highMatcher.String(), sm.lowMatcher.String())
	}
	return sm.repr
}

// Repr implements `ValueMatcher.Repr`.
func (sm splitMatcher) Repr() string {
	if sm.repr == "" {
		_, highIsAnyValue := sm.highMatcher.(halfAnyValue)
		_, lowIsAnyValue := sm.lowMatcher.(halfAnyValue)
		if highIsAnyValue && lowIsAnyValue {
			return "split(*)"
		}
		if highIsAnyValue {
			return fmt.Sprintf("low=%s", sm.lowMatcher.Repr())
		}
		if lowIsAnyValue {
			return fmt.Sprintf("high=%s", sm.highMatcher.Repr())
		}
		return fmt.Sprintf("(high=%s && low=%s)", sm.highMatcher.Repr(), sm.lowMatcher.Repr())
	}
	return sm.repr
}

// Render implements `ValueMatcher.Render`.
func (sm splitMatcher) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	_, highIsAny := sm.highMatcher.(halfAnyValue)
	_, lowIsAny := sm.lowMatcher.(halfAnyValue)
	if highIsAny && lowIsAny {
		program.JumpTo(labelSet.Matched())
		return
	}
	if highIsAny {
		value.LoadLow32Bits()
		sm.lowMatcher.HalfRender(program, labelSet)
		return
	}
	if lowIsAny {
		value.LoadHigh32Bits()
		sm.highMatcher.HalfRender(program, labelSet)
		return
	}
	// We render the "low" bits first on the assumption that most syscall
	// arguments fit within 32-bits, and those rules actually only care
	// about the value of the low 32 bits. This way, we only check the
	// high 32 bits if the low 32 bits have already matched.
	lowLabels := labelSet.Push("low", labelSet.NewLabel(), labelSet.Mismatched())
	lowFrag := program.Record()
	value.LoadLow32Bits()
	sm.lowMatcher.HalfRender(program, lowLabels)
	lowFrag.MustHaveJumpedTo(lowLabels.Matched(), labelSet.Mismatched())

	program.Label(lowLabels.Matched())
	highFrag := program.Record()
	value.LoadHigh32Bits()
	sm.highMatcher.HalfRender(program, labelSet.Push("high", labelSet.Matched(), labelSet.Mismatched()))
	highFrag.MustHaveJumpedTo(labelSet.Matched(), labelSet.Mismatched())
}

// high32BitsMatch returns a `splitMatcher` that only matches the high 32 bits
// of a 64-bit value.
func high32BitsMatch(hvm halfValueMatcher) splitMatcher {
	return splitMatcher{
		highMatcher: hvm,
		lowMatcher:  halfAnyValue{},
	}
}

// low32BitsMatch returns a `splitMatcher` that only matches the low 32 bits
// of a 64-bit value.
func low32BitsMatch(hvm halfValueMatcher) splitMatcher {
	return splitMatcher{
		highMatcher: halfAnyValue{},
		lowMatcher:  hvm,
	}
}

// splittableValueMatcher should be implemented by `ValueMatcher` that can
// be expressed as a `splitMatcher`.
type splittableValueMatcher interface {
	// split converts this `ValueMatcher` into a `splitMatcher`.
	split() splitMatcher
}

// renderSplittable is a helper function for the `ValueMatcher.Render`
// implementation of `splittableValueMatcher`s.
func renderSplittable(sm splittableValueMatcher, program *syscallProgram, labelSet *labelSet, value matchedValue) {
	sm.split().Render(program, labelSet, value)
}

// high32Bits returns the higher 32-bits of the given value.
func high32Bits(val uintptr) uint32 {
	return uint32(val >> 32)
}

// low32Bits returns the lower 32-bits of the given value.
func low32Bits(val uintptr) uint32 {
	return uint32(val)
}

// AnyValue is marker to indicate any value will be accepted.
// It implements ValueMatcher.
type AnyValue struct{}

// String implements `ValueMatcher.String`.
func (AnyValue) String() string {
	return "== *"
}

// Repr implements `ValueMatcher.Repr`.
func (av AnyValue) Repr() string {
	return av.String()
}

// Render implements `ValueMatcher.Render`.
func (av AnyValue) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	program.JumpTo(labelSet.Matched())
}

// EqualTo specifies a value that needs to be strictly matched.
// It implements ValueMatcher.
type EqualTo uintptr

// String implements `ValueMatcher.String`.
func (eq EqualTo) String() string {
	if eq == 0 {
		return "== 0"
	}
	return fmt.Sprintf("== %#x", uintptr(eq))
}

// Repr implements `ValueMatcher.Repr`.
func (eq EqualTo) Repr() string {
	return eq.String()
}

// Render implements `ValueMatcher.Render`.
func (eq EqualTo) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	renderSplittable(eq, program, labelSet, value)
}

// split implements `splittableValueMatcher.split`.
func (eq EqualTo) split() splitMatcher {
	return splitMatcher{
		repr:        eq.Repr(),
		highMatcher: halfEqualTo(high32Bits(uintptr(eq))),
		lowMatcher:  halfEqualTo(low32Bits(uintptr(eq))),
	}
}

// NotEqual specifies a value that is strictly not equal.
type NotEqual uintptr

// String implements `ValueMatcher.String`.
func (ne NotEqual) String() string {
	return fmt.Sprintf("!= %#x", uintptr(ne))
}

// Repr implements `ValueMatcher.Repr`.
func (ne NotEqual) Repr() string {
	return ne.String()
}

// Render implements `ValueMatcher.Render`.
func (ne NotEqual) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	// Note that `NotEqual` is *not* a splittable rule by itself, because it is not the
	// conjunction of two `halfValueMatchers` (it is the *disjunction* of them).
	// However, it is also the exact inverse of `EqualTo`.
	// Therefore, we can use `EqualTo` here, and simply invert the
	// matched/mismatched labels.
	EqualTo(ne).Render(program, labelSet.Push("inverted", labelSet.Mismatched(), labelSet.Matched()), value)
}

// GreaterThan specifies a value that needs to be strictly smaller.
type GreaterThan uintptr

// String implements `ValueMatcher.String`.
func (gt GreaterThan) String() string {
	return fmt.Sprintf("> %#x", uintptr(gt))
}

// Repr implements `ValueMatcher.Repr`.
func (gt GreaterThan) Repr() string {
	return gt.String()
}

// Render implements `ValueMatcher.Render`.
func (gt GreaterThan) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	high := high32Bits(uintptr(gt))
	// Assert the higher 32bits are greater than or equal.
	// arg_high >= high ? continue : violation (arg_high < high)
	value.LoadHigh32Bits()
	program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, high, labelSet.Mismatched())
	// arg_high == high ? continue : success (arg_high > high)
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, labelSet.Matched())
	// Assert that the lower 32bits are greater.
	// arg_low > low ? continue/success : violation (arg_high == high and arg_low <= low)
	value.LoadLow32Bits()
	program.IfNot(bpf.Jmp|bpf.Jgt|bpf.K, low32Bits(uintptr(gt)), labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// GreaterThanOrEqual specifies a value that needs to be smaller or equal.
type GreaterThanOrEqual uintptr

// String implements `ValueMatcher.String`.
func (ge GreaterThanOrEqual) String() string {
	return fmt.Sprintf(">= %#x", uintptr(ge))
}

// Repr implements `ValueMatcher.Repr`.
func (ge GreaterThanOrEqual) Repr() string {
	return ge.String()
}

// Render implements `ValueMatcher.Render`.
func (ge GreaterThanOrEqual) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	high := high32Bits(uintptr(ge))
	// Assert the higher 32bits are greater than or equal.
	// arg_high >= high ? continue : violation (arg_high < high)
	value.LoadHigh32Bits()
	program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, high, labelSet.Mismatched())
	// arg_high == high ? continue : success (arg_high > high)
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, labelSet.Matched())
	// Assert that the lower 32bits are greater or equal (assuming the
	// higher bits are equal).
	// arg_low >= low ? continue/success : violation (arg_high == high and arg_low < low)
	value.LoadLow32Bits()
	program.IfNot(bpf.Jmp|bpf.Jge|bpf.K, low32Bits(uintptr(ge)), labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// LessThan specifies a value that needs to be strictly greater.
type LessThan uintptr

// String implements `ValueMatcher.String`.
func (lt LessThan) String() string {
	return fmt.Sprintf("< %#x", uintptr(lt))
}

// Repr implements `ValueMatcher.Repr`.
func (lt LessThan) Repr() string {
	return lt.String()
}

// Render implements `ValueMatcher.Render`.
func (lt LessThan) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	high := high32Bits(uintptr(lt))
	// Assert the higher 32bits are less than or equal.
	// arg_high > high ? violation : continue
	value.LoadHigh32Bits()
	program.If(bpf.Jmp|bpf.Jgt|bpf.K, high, labelSet.Mismatched())
	// arg_high == high ? continue : success (arg_high < high)
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, labelSet.Matched())
	// Assert that the lower 32bits are less (assuming the
	// higher bits are equal).
	// arg_low >= low ? violation : continue
	value.LoadLow32Bits()
	program.If(bpf.Jmp|bpf.Jge|bpf.K, low32Bits(uintptr(lt)), labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// LessThanOrEqual specifies a value that needs to be greater or equal.
type LessThanOrEqual uintptr

// String implements `ValueMatcher.String`.
func (le LessThanOrEqual) String() string {
	return fmt.Sprintf("<= %#x", uintptr(le))
}

// Repr implements `ValueMatcher.Repr`.
func (le LessThanOrEqual) Repr() string {
	return le.String()
}

// Render implements `ValueMatcher.Render`.
func (le LessThanOrEqual) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	high := high32Bits(uintptr(le))
	// Assert the higher 32bits are less than or equal.
	// assert arg_high > high ? violation : continue
	value.LoadHigh32Bits()
	program.If(bpf.Jmp|bpf.Jgt|bpf.K, high, labelSet.Mismatched())
	// arg_high == high ? continue : success
	program.IfNot(bpf.Jmp|bpf.Jeq|bpf.K, high, labelSet.Matched())
	// Assert the lower bits are less than or equal (assuming
	// the higher bits are equal).
	// arg_low > low ? violation : success
	value.LoadLow32Bits()
	program.If(bpf.Jmp|bpf.Jgt|bpf.K, low32Bits(uintptr(le)), labelSet.Mismatched())
	program.JumpTo(labelSet.Matched())
}

// NonNegativeFD ensures that an FD argument is a non-negative int32.
type NonNegativeFD struct{}

// String implements `ValueMatcher.String`.
func (NonNegativeFD) String() string {
	return "is non-negative FD"
}

// Repr implements `ValueMatcher.Repr`.
func (NonNegativeFD) Repr() string {
	return "NonNegativeFD"
}

// Render implements `ValueMatcher.Render`.
func (nnfd NonNegativeFD) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	renderSplittable(nnfd, program, labelSet, value)
}

// split implements `splittableValueMatcher.split`.
func (nnfd NonNegativeFD) split() splitMatcher {
	return splitMatcher{
		repr: nnfd.Repr(),
		// FDs are 32 bits, so the high 32 bits must all be zero.
		// Negative int32 has the MSB (31st bit) set.
		// So the low 32bits of the FD value must not have the 31st bit set.
		highMatcher: halfEqualTo(0),
		lowMatcher:  halfNotSet(1 << 31),
	}
}

// MaskedEqual specifies a value that matches the input after the input is
// masked (bitwise &) against the given mask. It implements `ValueMatcher`.
type maskedEqual struct {
	mask  uintptr
	value uintptr
}

// String implements `ValueMatcher.String`.
func (me maskedEqual) String() string {
	return fmt.Sprintf("& %#x == %#x", me.mask, me.value)
}

// Repr implements `ValueMatcher.Repr`.
func (me maskedEqual) Repr() string {
	return me.String()
}

// Render implements `ValueMatcher.Render`.
func (me maskedEqual) Render(program *syscallProgram, labelSet *labelSet, value matchedValue) {
	renderSplittable(me, program, labelSet, value)
}

// split implements `splittableValueMatcher.Split`.
func (me maskedEqual) split() splitMatcher {
	return splitMatcher{
		repr:        me.Repr(),
		highMatcher: halfMaskedEqual{high32Bits(me.mask), high32Bits(me.value)},
		lowMatcher:  halfMaskedEqual{low32Bits(me.mask), low32Bits(me.value)},
	}
}

// MaskedEqual specifies a value that matches the input after the input is
// masked (bitwise &) against the given mask. Can be used to verify that input
// only includes certain approved flags.
func MaskedEqual(mask, value uintptr) ValueMatcher {
	return maskedEqual{
		mask:  mask,
		value: value,
	}
}

// BitsAllowlist specifies that a value can only have non-zero bits within
// the mask specified in `allowlist`. It implements `ValueMatcher`.
func BitsAllowlist(allowlist uintptr) ValueMatcher {
	return MaskedEqual(^allowlist, 0)
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

	// Copy returns a copy of this `SyscallRule`.
	Copy() SyscallRule

	// Recurse should call the given function on all `SyscallRule`s that are
	// part of this `SyscallRule`, and should replace them with the returned
	// `SyscallRule`. For example, conjunctive rules should call the given
	// function on each of the `SyscallRule`s that they are ANDing, replacing
	// them with the rule returned by the function.
	Recurse(func(SyscallRule) SyscallRule)

	// String returns a human-readable string representing what the rule does.
	String() string
}

// MatchAll implements `SyscallRule` and matches everything.
type MatchAll struct{}

// Render implements `SyscallRule.Render`.
func (MatchAll) Render(program *syscallProgram, labelSet *labelSet) {
	program.JumpTo(labelSet.Matched())
}

// Copy implements `SyscallRule.Copy`.
func (MatchAll) Copy() SyscallRule {
	return MatchAll{}
}

// Recurse implements `SyscallRule.Recurse`.
func (MatchAll) Recurse(func(SyscallRule) SyscallRule) {}

// String implements `SyscallRule.String`.
func (MatchAll) String() string { return "true" }

// Or expresses an "OR" (a disjunction) over a set of `SyscallRule`s.
// An `Or` may not be empty.
type Or []SyscallRule

// Render implements `SyscallRule.Render`.
func (or Or) Render(program *syscallProgram, labelSet *labelSet) {
	if len(or) == 0 {
		panic("Or expression cannot be empty")
	}
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

// Copy implements `SyscallRule.Copy`.
func (or Or) Copy() SyscallRule {
	orCopy := make([]SyscallRule, len(or))
	for i, rule := range or {
		orCopy[i] = rule.Copy()
	}
	return Or(orCopy)
}

// Recurse implements `SyscallRule.Recurse`.
func (or Or) Recurse(fn func(SyscallRule) SyscallRule) {
	for i, rule := range or {
		or[i] = fn(rule)
	}
}

// String implements `SyscallRule.String`.
func (or Or) String() string {
	switch len(or) {
	case 0:
		return "invalid"
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

// And expresses an "AND" (a conjunction) over a set of `SyscallRule`s.
// An `And` may not be empty.
type And []SyscallRule

// Render implements `SyscallRule.Render`.
func (and And) Render(program *syscallProgram, labelSet *labelSet) {
	if len(and) == 0 {
		panic("And expression cannot be empty")
	}
	// If `len(and) == 1`, this will be optimized away to be the same as
	// rendering the single rule in the conjunction.
	for i, rule := range and {
		frag := program.Record()
		nextRuleLabel := labelSet.NewLabel()
		rule.Render(program, labelSet.Push(fmt.Sprintf("and[%d]", i), nextRuleLabel, labelSet.Mismatched()))
		frag.MustHaveJumpedTo(nextRuleLabel, labelSet.Mismatched())
		program.Label(nextRuleLabel)
	}
	program.JumpTo(labelSet.Matched())
}

// Copy implements `SyscallRule.Copy`.
func (and And) Copy() SyscallRule {
	andCopy := make([]SyscallRule, len(and))
	for i, rule := range and {
		andCopy[i] = rule.Copy()
	}
	return And(andCopy)
}

// Recurse implements `SyscallRule.Recurse`.
func (and And) Recurse(fn func(SyscallRule) SyscallRule) {
	for i, rule := range and {
		and[i] = fn(rule)
	}
}

// String implements `SyscallRule.String`.
func (and And) String() string {
	switch len(and) {
	case 0:
		return "invalid"
	case 1:
		return and[0].String()
	default:
		var sb strings.Builder
		sb.WriteRune('(')
		for i, rule := range and {
			if i != 0 {
				sb.WriteString(" && ")
			}
			sb.WriteString(rule.String())
		}
		sb.WriteRune(')')
		return sb.String()
	}
}

// PerArg implements SyscallRule and verifies the syscall arguments and RIP.
//
// For example:
//
//	rule := PerArg{
//		EqualTo(linux.ARCH_GET_FS | linux.ARCH_SET_FS), // arg0
//	}
type PerArg [7]ValueMatcher // 6 arguments + RIP

// RuleIP indicates what rules in the Rule array have to be applied to
// instruction pointer.
const RuleIP = 6

// clone returns a copy of this `PerArg`.
// It is more efficient than `Copy` because it returns a `PerArg`
// directly, rather than a `SyscallRule` interface.
func (pa PerArg) clone() PerArg {
	return PerArg{
		pa[0],
		pa[1],
		pa[2],
		pa[3],
		pa[4],
		pa[5],
		pa[6],
	}
}

// Copy implements `SyscallRule.Copy`.
func (pa PerArg) Copy() SyscallRule {
	return pa.clone()
}

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
		arg.Render(program, ls, matchedValue{
			program:        program,
			dataOffsetHigh: dataOffsetHigh,
			dataOffsetLow:  dataOffsetLow,
		})
		frag.MustHaveJumpedTo(ls.Matched(), ls.Mismatched())
		program.Label(nextArgLabel)
	}
	// Matched all argument-wise rules, jump to the final rule matched label.
	program.JumpTo(labelSet.Matched())
}

// Recurse implements `SyscallRule.Recurse`.
func (PerArg) Recurse(fn func(SyscallRule) SyscallRule) {}

// String implements `SyscallRule.String`.
func (pa PerArg) String() string {
	var sb strings.Builder
	writtenArgs := 0
	for i, arg := range pa {
		if arg == nil {
			continue
		}
		if _, isAny := arg.(AnyValue); isAny {
			continue
		}
		if writtenArgs != 0 {
			sb.WriteString(" && ")
		}
		str := arg.String()
		var varName string
		if i == RuleIP {
			varName = "rip"
		} else {
			varName = fmt.Sprintf("arg[%d]", i)
		}
		if strings.Contains(str, "VAL") {
			sb.WriteString(strings.ReplaceAll(str, "VAL", varName))
		} else {
			sb.WriteString(varName)
			sb.WriteRune(' ')
			sb.WriteString(str)
		}
		writtenArgs++
	}
	if writtenArgs == 0 {
		return "true"
	}
	if writtenArgs == 1 {
		return sb.String()
	}
	return "(" + sb.String() + ")"
}

// SyscallRules maps syscall numbers to their corresponding rules.
//
// For example:
//
//	rules := MakeSyscallRules(map[uintptr]SyscallRule{
//		syscall.SYS_FUTEX: Or{
//			PerArg{
//				AnyValue{},
//				EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
//			},
//			PerArg{
//				AnyValue{},
//				EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
//			},
//		},
//		syscall.SYS_GETPID: MatchAll{},
//	})
type SyscallRules struct {
	rules map[uintptr]SyscallRule
}

// NewSyscallRules returns a new SyscallRules.
func NewSyscallRules() SyscallRules {
	return MakeSyscallRules(nil)
}

// MakeSyscallRules returns a new SyscallRules with the given set of rules.
func MakeSyscallRules(rules map[uintptr]SyscallRule) SyscallRules {
	if rules == nil {
		rules = make(map[uintptr]SyscallRule)
	}
	return SyscallRules{rules: rules}
}

// String returns a string representation of the syscall rules, one syscall
// per line.
func (sr SyscallRules) String() string {
	if len(sr.rules) == 0 {
		return "(no rules)"
	}
	sysnums := make([]uintptr, 0, len(sr.rules))
	for sysno := range sr.rules {
		sysnums = append(sysnums, sysno)
	}
	sort.Slice(sysnums, func(i, j int) bool {
		return sysnums[i] < sysnums[j]
	})
	var sb strings.Builder
	for _, sysno := range sysnums {
		sb.WriteString(fmt.Sprintf("syscall %d: %v\n", sysno, sr.rules[sysno]))
	}
	return strings.TrimSpace(sb.String())
}

// Size returns the number of syscall numbers for which a rule is defined.
func (sr SyscallRules) Size() int {
	return len(sr.rules)
}

// Get returns the rule defined for the given syscall number.
func (sr SyscallRules) Get(sysno uintptr) SyscallRule {
	return sr.rules[sysno]
}

// Has returns whether there is a rule defined for the given syscall number.
func (sr SyscallRules) Has(sysno uintptr) bool {
	_, has := sr.rules[sysno]
	return has
}

// Add adds the given rule. It will create a new entry for a new syscall, otherwise
// it will append to the existing rules.
// Returns itself for chainability.
func (sr SyscallRules) Add(sysno uintptr, r SyscallRule) SyscallRules {
	if cur, ok := sr.rules[sysno]; ok {
		sr.rules[sysno] = Or{cur, r}
	} else {
		sr.rules[sysno] = r
	}
	return sr
}

// Set sets the rule for the given syscall number.
// Panics if there is already a rule for this syscall number.
// This is useful for deterministic rules where the set of syscall rules is
// added in multiple chunks but is known to never overlap by syscall number.
// Returns itself for chainability.
func (sr SyscallRules) Set(sysno uintptr, r SyscallRule) SyscallRules {
	if cur, ok := sr.rules[sysno]; ok {
		panic(fmt.Sprintf("tried to set syscall rule for sysno=%d to %v but it is already set to %v", sysno, r, cur))
	}
	sr.rules[sysno] = r
	return sr
}

// Remove clears the syscall rule for the given syscall number.
// It will panic if there is no syscall rule for this syscall number.
func (sr SyscallRules) Remove(sysno uintptr) {
	if !sr.Has(sysno) {
		panic(fmt.Sprintf("tried to remove syscall rule for sysno=%d but it is not set", sysno))
	}
	delete(sr.rules, sysno)
}

// Merge merges the given SyscallRules.
// Returns itself for chainability.
func (sr SyscallRules) Merge(other SyscallRules) SyscallRules {
	for sysno, r := range other.rules {
		sr.Add(sysno, r)
	}
	return sr
}

// Copy returns a deep copy of these SyscallRules.
func (sr SyscallRules) Copy() SyscallRules {
	rulesCopy := make(map[uintptr]SyscallRule, len(sr.rules))
	for sysno, r := range sr.rules {
		rulesCopy[sysno] = r.Copy()
	}
	return MakeSyscallRules(rulesCopy)
}

// ForSingleArgument runs the given function on the `ValueMatcher` rules
// for a single specific syscall argument of the given syscall number.
// If the function returns an error, it will be propagated along with some
// details as to which rule caused the error to be returned.
// ForSingleArgument also returns an error if there are no rules defined for
// the given syscall number, or if at least one rule for this syscall number
// is not either a `PerArg` rule or a rule with children rules (as this would
// indicate that the `PerArg` rules alone may not be a good representation of
// the entire set of rules for this system call).
func (sr SyscallRules) ForSingleArgument(sysno uintptr, argNum int, fn func(ValueMatcher) error) error {
	if argNum < 0 || argNum >= len(PerArg{}) {
		return fmt.Errorf("invalid argument number %d", argNum)
	}
	if !sr.Has(sysno) {
		return fmt.Errorf("syscall %d has no rules defined", sysno)
	}
	var err error
	var process func(SyscallRule) SyscallRule
	var callCount int
	process = func(r SyscallRule) SyscallRule {
		callCount++
		pa, isPerArg := r.(PerArg)
		if isPerArg {
			if gotErr := fn(pa[argNum]); gotErr != nil && err == nil {
				err = fmt.Errorf("PerArg rule %v: arg[%d] = %v (type %T): %v", pa, argNum, pa[argNum], pa[argNum], gotErr)
			}
		} else {
			beforeRecurse := callCount
			r.Recurse(process)
			if callCount == beforeRecurse {
				err = fmt.Errorf("rule %v (type: %T) is not a PerArg or a recursive rule", r, r)
			}
		}
		return r
	}
	process(sr.rules[sysno])
	return err
}

// DenyNewExecMappings is a set of rules that denies creating new executable
// mappings and converting existing ones.
var DenyNewExecMappings = MakeSyscallRules(map[uintptr]SyscallRule{
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
})
