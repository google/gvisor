// Copyright 2023 The gVisor Authors.
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

package precompiledseccomp

import (
	"fmt"
	"math"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// TestPrecompile verifies that precompilation works and verifies that variable
// offsets are verified across compilation attempts.
func TestPrecompile(t *testing.T) {
	// Used in some tests below that need statefulness in order to return
	// purposefully-inconsistent results across calls.
	counter := 0

	for _, test := range []struct {
		name    string
		vars    []string
		fn      func(Values) ProgramDesc
		wantErr bool
	}{
		{
			name: "simple case",
			fn: func(Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.MatchAll{},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
		},
		{
			name: "one variable",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.PerArg{
								seccomp.EqualTo(values["var1"]),
							},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
		},
		{
			name: "duplicate variable name",
			vars: []string{"var1", "var1"},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{}
			},
			wantErr: true,
		},
		{
			name: "multiple variables showing up multiple times",
			vars: []string{"var1", "var2"},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.Or{
								seccomp.PerArg{seccomp.EqualTo(values["var1"])},
								seccomp.PerArg{seccomp.EqualTo(values["var2"])},
							},
						).Add(
							unix.SYS_WRITE,
							seccomp.PerArg{seccomp.EqualTo(values["var1"])},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
		},
		{
			name: "unused variable",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.MatchAll{},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
			wantErr: true,
		},
		{
			name: "variable that can be optimized away",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.Or{
								seccomp.PerArg{
									seccomp.EqualTo(values["var1"]),
								},
								seccomp.MatchAll{},
							},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
		},
		{
			name: "64-bit variable",
			vars: []string{"var1" + uint64VarSuffixHigh, "var1" + uint64VarSuffixLow},
			fn: func(values Values) ProgramDesc {
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							seccomp.PerArg{
								seccomp.EqualTo(values.GetUint64("var1")),
							},
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
		},
		{
			name: "inconsistent offsets",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				var pa seccomp.PerArg
				if counter == 0 {
					pa[0] = seccomp.EqualTo(values["var1"])
				}
				if counter == 1 {
					pa[0] = seccomp.EqualTo(values["var1"])
					pa[1] = seccomp.EqualTo(values["var1"])
				}
				counter++
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							pa,
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
			wantErr: true,
		},
		{
			name: "inconsistent program size",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				pa := seccomp.PerArg{seccomp.EqualTo(values["var1"])}
				if counter == 1 {
					pa[1] = seccomp.EqualTo(123)
				}
				counter++
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							pa,
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
			wantErr: true,
		},
		{
			name: "inconsistent program bytecode",
			vars: []string{"var1"},
			fn: func(values Values) ProgramDesc {
				pa := seccomp.PerArg{seccomp.EqualTo(values["var1"])}
				if counter == 0 {
					pa[1] = seccomp.EqualTo(1337)
				}
				if counter == 1 {
					pa[1] = seccomp.EqualTo(42)
				}
				counter++
				return ProgramDesc{
					Rules: []seccomp.RuleSet{{
						Rules: seccomp.NewSyscallRules().Add(
							unix.SYS_READ,
							pa,
						),
						Action: linux.SECCOMP_RET_ALLOW,
					}},
					SeccompOptions: seccomp.DefaultProgramOptions(),
				}
			},
			wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter = 0
			_, err := Precompile("", test.vars, test.fn)
			if err != nil && !test.wantErr {
				t.Fatalf("Precompile failed: %v", err)
			}
			if err == nil && test.wantErr {
				t.Fatal("Precompile succeeded but want error")
			}
		})
	}
}

func TestUint64Var(t *testing.T) {
	vars := Values{}
	for _, v := range []uint64{
		0, 1,
		math.MaxInt,
		math.MaxInt16,
		math.MaxInt32,
		math.MaxInt64,
		math.MaxUint64,
	} {
		vars.SetUint64(fmt.Sprintf("var%d", v), v)
		if vars.GetUint64(fmt.Sprintf("var%d", v)) != v {
			t.Errorf("GetUint64(%q) = %d, want %d", fmt.Sprintf("var%d", v), v, v)
		}
	}
}
