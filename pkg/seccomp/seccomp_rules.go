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

import "fmt"

// The offsets are based on the following struct in include/linux/seccomp.h.
// struct seccomp_data {
//	int nr;
//	__u32 arch;
//	__u64 instruction_pointer;
//	__u64 args[6];
// };
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

// MatchAny is marker to indicate any value will be accepted.
type MatchAny struct{}

func (a MatchAny) String() (s string) {
	return "*"
}

// EqualTo specifies a value that needs to be strictly matched.
type EqualTo uintptr

func (a EqualTo) String() (s string) {
	return fmt.Sprintf("== %#x", uintptr(a))
}

// NotEqual specifies a value that is strictly not equal.
type NotEqual uintptr

func (a NotEqual) String() (s string) {
	return fmt.Sprintf("!= %#x", uintptr(a))
}

// GreaterThan specifies a value that needs to be strictly smaller.
type GreaterThan uintptr

func (a GreaterThan) String() (s string) {
	return fmt.Sprintf("> %#x", uintptr(a))
}

// GreaterThanOrEqual specifies a value that needs to be smaller or equal.
type GreaterThanOrEqual uintptr

func (a GreaterThanOrEqual) String() (s string) {
	return fmt.Sprintf(">= %#x", uintptr(a))
}

// LessThan specifies a value that needs to be strictly greater.
type LessThan uintptr

func (a LessThan) String() (s string) {
	return fmt.Sprintf("< %#x", uintptr(a))
}

// LessThanOrEqual specifies a value that needs to be greater or equal.
type LessThanOrEqual uintptr

func (a LessThanOrEqual) String() (s string) {
	return fmt.Sprintf("<= %#x", uintptr(a))
}

type maskedEqual struct {
	mask  uintptr
	value uintptr
}

func (a maskedEqual) String() (s string) {
	return fmt.Sprintf("& %#x == %#x", a.mask, a.value)
}

// MaskedEqual specifies a value that matches the input after the input is
// masked (bitwise &) against the given mask. Can be used to verify that input
// only includes certain approved flags.
func MaskedEqual(mask, value uintptr) interface{} {
	return maskedEqual{
		mask:  mask,
		value: value,
	}
}

// Rule stores the allowed syscall arguments.
//
// For example:
// rule := Rule {
//       EqualTo(linux.ARCH_GET_FS | linux.ARCH_SET_FS), // arg0
// }
type Rule [7]interface{} // 6 arguments + RIP

// RuleIP indicates what rules in the Rule array have to be applied to
// instruction pointer.
const RuleIP = 6

func (r Rule) String() (s string) {
	if len(r) == 0 {
		return
	}
	s += "( "
	for _, arg := range r {
		if arg != nil {
			s += fmt.Sprintf("%v ", arg)
		}
	}
	s += ")"
	return
}

// SyscallRules stores a map of OR'ed argument rules indexed by the syscall number.
// If the 'Rules' is empty, we treat it as any argument is allowed.
//
// For example:
//  rules := SyscallRules{
//         syscall.SYS_FUTEX: []Rule{
//                 {
//                         MatchAny{},
//                         EqualTo(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
//                 }, // OR
//                 {
//                         MatchAny{},
//                         EqualTo(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
//                 },
//         },
//         syscall.SYS_GETPID: []Rule{},
// }
type SyscallRules map[uintptr][]Rule

// NewSyscallRules returns a new SyscallRules.
func NewSyscallRules() SyscallRules {
	return make(map[uintptr][]Rule)
}

// AddRule adds the given rule. It will create a new entry for a new syscall, otherwise
// it will append to the existing rules.
func (sr SyscallRules) AddRule(sysno uintptr, r Rule) {
	if cur, ok := sr[sysno]; ok {
		// An empty rules means allow all. Honor it when more rules are added.
		if len(cur) == 0 {
			sr[sysno] = append(sr[sysno], Rule{})
		}
		sr[sysno] = append(sr[sysno], r)
	} else {
		sr[sysno] = []Rule{r}
	}
}

// Merge merges the given SyscallRules.
func (sr SyscallRules) Merge(rules SyscallRules) {
	for sysno, rs := range rules {
		if cur, ok := sr[sysno]; ok {
			// An empty rules means allow all. Honor it when more rules are added.
			if len(cur) == 0 {
				sr[sysno] = append(sr[sysno], Rule{})
			}
			if len(rs) == 0 {
				rs = []Rule{{}}
			}
			sr[sysno] = append(sr[sysno], rs...)
		} else {
			sr[sysno] = rs
		}
	}
}
