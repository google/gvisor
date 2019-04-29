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

// AllowAny is marker to indicate any value will be accepted.
type AllowAny struct{}

func (a AllowAny) String() (s string) {
	return "*"
}

// AllowValue specifies a value that needs to be strictly matched.
type AllowValue uintptr

func (a AllowValue) String() (s string) {
	return fmt.Sprintf("%#x ", uintptr(a))
}

// Rule stores the whitelist of syscall arguments.
//
// For example:
// rule := Rule {
//       AllowValue(linux.ARCH_GET_FS | linux.ARCH_SET_FS), // arg0
// }
type Rule [6]interface{}

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

// SyscallRules stores a map of OR'ed whitelist rules indexed by the syscall number.
// If the 'Rules' is empty, we treat it as any argument is allowed.
//
// For example:
//  rules := SyscallRules{
//         syscall.SYS_FUTEX: []Rule{
//                 {
//                         AllowAny{},
//                         AllowValue(linux.FUTEX_WAIT | linux.FUTEX_PRIVATE_FLAG),
//                 }, // OR
//                 {
//                         AllowAny{},
//                         AllowValue(linux.FUTEX_WAKE | linux.FUTEX_PRIVATE_FLAG),
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
