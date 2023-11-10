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

// This file contains helpers to generate fuzz tests for seccomp rules.
// It contains the `InterestingValues` implementations for all matchers,
// and a helper function to generate test cases based on `RuleSet`s.

import (
	"sort"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// UsefulTestCases returns a best-effort list of test cases that may be
// useful in fuzzing this set of rules.
func (sr SyscallRules) UsefulTestCases() []linux.SeccompData {
	var testCases []linux.SeccompData
	for sysno, r := range sr.rules {

		// valueMatchers maps argument indexes to value matchers
		// seen for that argument index.
		// valueMatchersRepr tracks the `Repr()` of those
		// `ValueMatcher`s in order to avoid inserting duplicates.
		valueMatchers := make(map[int][]ValueMatcher)
		valueMatchersRepr := make(map[int]map[string]struct{})

		// Find all unique `ValueMatcher`s for each argument.
		var processRule func(SyscallRule) SyscallRule
		processRule = func(r SyscallRule) SyscallRule {
			r.Recurse(processRule)
			pa, isPerArg := r.(PerArg)
			if !isPerArg {
				return r
			}
			for argNum, arg := range pa {
				if arg == nil {
					arg = AnyValue{}
				}
				valueMatchersReprMap, ok := valueMatchersRepr[argNum]
				if !ok {
					valueMatchersReprMap = make(map[string]struct{})
					valueMatchersRepr[argNum] = valueMatchersReprMap
				}
				repr := arg.Repr()
				if _, seen := valueMatchersReprMap[repr]; seen {
					continue
				}
				valueMatchersReprMap[repr] = struct{}{}
				valueMatchers[argNum] = append(valueMatchers[argNum], arg)
			}
			return r
		}
		processRule(r)

		// Now compute the combination of all interesting values for them.
		sysnoCases := []linux.SeccompData{{
			Nr:   int32(sysno),
			Arch: LINUX_AUDIT_ARCH,
		}}
		for argNum, vms := range valueMatchers {
			// Deduplicate interesting values across value matchers.
			interestingValuesMap := make(map[uint64]struct{})
			interestingValuesMap[0] = struct{}{} // The zero value is always interesting.
			for _, vm := range vms {
				for _, interestingValue := range vm.InterestingValues() {
					interestingValuesMap[interestingValue] = struct{}{}
				}
			}

			// Convert to sorted slice of integers.
			interestingValues := make([]uint64, 0, len(interestingValuesMap))
			for interestingValue := range interestingValuesMap {
				interestingValues = append(interestingValues, interestingValue)
			}
			sort.Slice(interestingValues, func(i, j int) bool {
				return interestingValues[i] < interestingValues[j]
			})

			// Generate test cases.
			newSysnoCases := make([]linux.SeccompData, 0, len(sysnoCases)*len(interestingValues))
			for _, sysnoCase := range sysnoCases {
				for _, interestingValue := range interestingValues {
					if argNum == RuleIP {
						sysnoCase.InstructionPointer = interestingValue
					} else {
						sysnoCase.Args[argNum] = interestingValue
					}
					newSysnoCases = append(newSysnoCases, sysnoCase)
				}
			}
			sysnoCases = newSysnoCases
		}
		testCases = append(testCases, sysnoCases...)
	}
	return testCases
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (halfAnyValue) InterestingValues() []uint32 {
	return []uint32{0}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (heq halfEqualTo) InterestingValues() []uint32 {
	return []uint32{uint32(heq), uint32(heq + 1)}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (hns halfNotSet) InterestingValues() []uint32 {
	return []uint32{uint32(hns), uint32(hns + 1)}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (hmeq halfMaskedEqual) InterestingValues() []uint32 {
	return []uint32{uint32(hmeq.mask), uint32(hmeq.mask + 1)}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (sm splitMatcher) InterestingValues() []uint64 {
	interestingHigh := sm.highMatcher.InterestingValues()
	interestingLow := sm.lowMatcher.InterestingValues()
	interesting := make([]uint64, 0, len(interestingHigh)*len(interestingLow))
	for _, high := range interestingHigh {
		for _, low := range interestingLow {
			interesting = append(interesting, (uint64(high)<<32)|uint64(low))
		}
	}
	return interesting
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (av AnyValue) InterestingValues() []uint64 {
	return []uint64{0}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (eq EqualTo) InterestingValues() []uint64 {
	return eq.split().InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (ne NotEqual) InterestingValues() []uint64 {
	return EqualTo(ne).InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (gt GreaterThan) InterestingValues() []uint64 {
	return []uint64{
		uint64(high32Bits(uintptr(gt))+1) << 32,
		uint64(high32Bits(uintptr(gt))-1) << 32,
		uint64(high32Bits(uintptr(gt))) << 32,
		(uint64(high32Bits(uintptr(gt))) << 32) + uint64(low32Bits(uintptr(gt))),
		(uint64(high32Bits(uintptr(gt))) << 32) + uint64(low32Bits(uintptr(gt))) + 1,
		(uint64(high32Bits(uintptr(gt))) << 32) + uint64(low32Bits(uintptr(gt))) - 1,
	}
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (ge GreaterThanOrEqual) InterestingValues() []uint64 {
	return GreaterThan(ge).InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (lt LessThan) InterestingValues() []uint64 {
	return GreaterThan(lt).InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (le LessThanOrEqual) InterestingValues() []uint64 {
	return GreaterThan(le).InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (nnfd NonNegativeFD) InterestingValues() []uint64 {
	return nnfd.split().InterestingValues()
}

// InterestingValues implements `halfValueMatcher.InterestingValues`.
func (me maskedEqual) InterestingValues() []uint64 {
	return me.split().InterestingValues()
}
