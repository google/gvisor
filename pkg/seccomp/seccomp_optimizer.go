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

package seccomp

import (
	"fmt"
	"strings"
)

// ruleOptimizerFunc is a function type that can optimize a SyscallRule.
// It returns the updated SyscallRule, along with whether any modification
// was made.
type ruleOptimizerFunc func(SyscallRule) (SyscallRule, bool)

// convertSingleCompoundRuleToThatRule replaces `Or` or `And` rules with a
// single branch to just that branch.
func convertSingleCompoundRuleToThatRule[T Or | And](rule SyscallRule) (SyscallRule, bool) {
	if tRule, isT := rule.(T); isT && len(tRule) == 1 {
		return tRule[0], true
	}
	return rule, false
}

// flattenCompoundRules turns compound rules (Or or And) embedded inside
// compound rules of the same type into a flat rule of that type.
func flattenCompoundRules[T Or | And](rule SyscallRule) (SyscallRule, bool) {
	tRule, isT := rule.(T)
	if !isT {
		return rule, false
	}
	anySubT := false
	for _, subRule := range tRule {
		if _, subIsT := subRule.(T); subIsT {
			anySubT = true
			break
		}
	}
	if !anySubT {
		return rule, false
	}
	var newRules []SyscallRule
	for _, subRule := range tRule {
		if subT, subIsT := subRule.(T); subIsT {
			newRules = append(newRules, subT...)
		} else {
			newRules = append(newRules, subRule)
		}
	}
	return SyscallRule(T(newRules)), true
}

// convertMatchAllOrXToMatchAll an Or rule that contains MatchAll to MatchAll.
func convertMatchAllOrXToMatchAll(rule SyscallRule) (SyscallRule, bool) {
	orRule, isOr := rule.(Or)
	if !isOr {
		return rule, false
	}
	for _, subRule := range orRule {
		if _, subIsMatchAll := subRule.(MatchAll); subIsMatchAll {
			return MatchAll{}, true
		}
	}
	return orRule, false
}

// convertMatchAllAndXToX removes MatchAll clauses from And rules.
func convertMatchAllAndXToX(rule SyscallRule) (SyscallRule, bool) {
	andRule, isAnd := rule.(And)
	if !isAnd {
		return rule, false
	}
	hasMatchAll := false
	for _, subRule := range andRule {
		if _, subIsMatchAll := subRule.(MatchAll); subIsMatchAll {
			hasMatchAll = true
			break
		}
	}
	if !hasMatchAll {
		return rule, false
	}
	var newRules []SyscallRule
	for _, subRule := range andRule {
		if _, subIsAny := subRule.(MatchAll); !subIsAny {
			newRules = append(newRules, subRule)
		}
	}
	if len(newRules) == 0 {
		// An `And` rule with zero rules inside is invalid.
		return MatchAll{}, true
	}
	return And(newRules), true
}

// nilInPerArgToAnyValue replaces `nil` values in `PerArg` rules with
// `AnyValue`. This isn't really an optimization, but it simplifies the
// logic of other `PerArg` optimizers to not have to handle the `nil` case
// separately from the `AnyValue` case.
func nilInPerArgToAnyValue(rule SyscallRule) (SyscallRule, bool) {
	perArg, isPerArg := rule.(PerArg)
	if !isPerArg {
		return rule, false
	}
	changed := false
	for argNum, valueMatcher := range perArg {
		if valueMatcher == nil {
			perArg[argNum] = AnyValue{}
			changed = true
		}
	}
	return perArg, changed
}

// convertUselessPerArgToMatchAll looks for `PerArg` rules that match
// anything and replaces them with `MatchAll`.
func convertUselessPerArgToMatchAll(rule SyscallRule) (SyscallRule, bool) {
	perArg, isPerArg := rule.(PerArg)
	if !isPerArg {
		return rule, false
	}
	for _, valueMatcher := range perArg {
		if _, isAnyValue := valueMatcher.(AnyValue); !isAnyValue {
			return rule, false
		}
	}
	return MatchAll{}, true
}

// signature returns a string signature of this `PerArg`.
// This string can be used to identify the behavior of this `PerArg` rule.
func (pa PerArg) signature() string {
	var sb strings.Builder
	for _, valueMatcher := range pa {
		repr := valueMatcher.Repr()
		if strings.ContainsRune(repr, ';') {
			panic(fmt.Sprintf("ValueMatcher %v (type %T) returned representation %q containing illegal character ';'", valueMatcher, valueMatcher, repr))
		}
		sb.WriteString(repr)
		sb.WriteRune(';')
	}
	return sb.String()
}

// deduplicatePerArgs deduplicates PerArg rules with identical matchers.
// This can happen during filter construction, when rules are added across
// multiple files.
func deduplicatePerArgs[T Or | And](rule SyscallRule) (SyscallRule, bool) {
	tRule, isT := rule.(T)
	if !isT || len(tRule) < 2 {
		return rule, false
	}
	knownPerArgs := make(map[string]struct{}, len(tRule))
	newRules := make([]SyscallRule, 0, len(tRule))
	changed := false
	for _, subRule := range tRule {
		subPerArg, subIsPerArg := subRule.(PerArg)
		if !subIsPerArg {
			newRules = append(newRules, subRule)
			continue
		}
		sig := subPerArg.signature()
		if _, isDupe := knownPerArgs[sig]; isDupe {
			changed = true
			continue
		}
		knownPerArgs[sig] = struct{}{}
		newRules = append(newRules, subPerArg)
	}
	if !changed {
		return rule, false
	}
	return SyscallRule(T(newRules)), true
}

// invalidValueMatcher is a stand-in `ValueMatcher` with a unique
// representation that doesn't look like any legitimate `ValueMatcher`.
// Calling any method other than `Repr` will fail.
type invalidValueMatcher struct {
	ValueMatcher
}

// Repr implements `ValueMatcher.Repr`.
func (m invalidValueMatcher) Repr() string {
	return "invalidValueMatcher"
}

// extractRepeatedMatchers looks for common argument matchers that are
// repeated across all combinations of *other* argument matchers in branches
// of an `Or` rule that contains only `PerArg` rules.
// It removes them from these `PerArg` rules, creates an `Or` of the
// matchers that are repeated across all combinations, and `And`s that
// rule to the rewritten `Or` rule.
// In other words (simplifying `PerArg` to 4 items for simplicity):
//
//	Or{
//		PerArg{A1, B1, C1, D},
//		PerArg{A2, B1, C1, D},
//		PerArg{A1, B2, C2, D},
//		PerArg{A2, B2, C2, D},
//		PerArg{A1, B3, C3, D},
//		PerArg{A2, B3, C3, D},
//	}
//
// becomes (after one pass):
//
//	And{
//		Or{
//			# Note: These will get deduplicated by deduplicatePerArgs
//			PerArg{A1, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A2, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A1, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A2, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A1, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A2, AnyValue{}, AnyValue{}, AnyValue{}},
//		},
//		Or{
//			# Note: These will also get deduplicated by deduplicatePerArgs
//			PerArg{AnyValue{}, B1, C1, D},
//			PerArg{AnyValue{}, B1, C1, D},
//			PerArg{AnyValue{}, B2, C2, D},
//			PerArg{AnyValue{}, B2, C2, D},
//			PerArg{AnyValue{}, B3, C3, D},
//			PerArg{AnyValue{}, B3, C3, D},
//		},
//	}
//
// ... then, on the second pass (after deduplication),
// the second inner `Or` rule gets recursively optimized to:
//
//	And{
//		Or{
//			PerArg{A1, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A2, AnyValue{}, AnyValue{}, AnyValue{}},
//		},
//		And{
//			Or{
//				PerArg{AnyValue{}, AnyValue{}, AnyValue{}, D},
//				PerArg{AnyValue{}, AnyValue{}, AnyValue{}, D},
//				PerArg{AnyValue{}, AnyValue{}, AnyValue{}, D},
//			},
//			Or{
//				PerArg{AnyValue{}, B1, C1, AnyValue{}},
//				PerArg{AnyValue{}, B2, C2, AnyValue{}},
//				PerArg{AnyValue{}, B3, C3, AnyValue{}},
//			},
//		},
//	}
//
// ... which (after other optimizers clean this all up), finally becomes:
//
//	And{
//		Or{
//			PerArg{A1, AnyValue{}, AnyValue{}, AnyValue{}},
//			PerArg{A2, AnyValue{}, AnyValue{}, AnyValue{}},
//		},
//		PerArg{AnyValue{}, AnyValue{}, AnyValue{}, D},
//		Or{
//			PerArg{AnyValue{}, B1, C1, AnyValue{}},
//			PerArg{AnyValue{}, B2, C2, AnyValue{}},
//			PerArg{AnyValue{}, B3, C3, AnyValue{}},
//		},
//	}
//
// ... Turning 24 comparisons into just 9.
func extractRepeatedMatchers(rule SyscallRule) (SyscallRule, bool) {
	orRule, isOr := rule.(Or)
	if !isOr || len(orRule) < 2 {
		return rule, false
	}
	for _, subRule := range orRule {
		if _, subIsPerArg := subRule.(PerArg); !subIsPerArg {
			return rule, false
		}
	}

	// copyOnlyArg creates a new `PerArg` that only checks the value of
	// the `argNum` argument, using the `ValueMatcher` from `src`.
	copyOnlyArg := func(src PerArg, argNum int) PerArg {
		var dst PerArg
		for i, valueMatcher := range src {
			if i == argNum {
				dst[i] = valueMatcher
			} else {
				dst[i] = AnyValue{}
			}
		}
		return dst
	}

	// copyExceptArg creates a new `PerArg` that copies the behavior of `src`,
	// except the `argNum` argument which is replaced by `replaceWith`.
	copyExceptArg := func(src PerArg, argNum int, replaceWith ValueMatcher) PerArg {
		var dst PerArg
		for i, valueMatcher := range src {
			if i == argNum {
				dst[i] = replaceWith
			} else {
				dst[i] = valueMatcher
			}
		}
		return dst
	}

	// sameStringSet returns whether the given string sets are equal.
	sameStringSet := func(m1, m2 map[string]struct{}) bool {
		if len(m1) != len(m2) {
			return false
		}
		for k := range m1 {
			if _, found := m2[k]; !found {
				return false
			}
		}
		return true
	}

	for argNum := 0; argNum < len(orRule[0].(PerArg)); argNum++ {
		// Check if `argNum` takes on a set of matchers common for all
		// combinations of all other matchers.
		allOtherMatchersSigs := make(map[string]struct{}, len(orRule))
		argExprToOtherMatchersSigs := make(map[string]map[string]struct{}, len(orRule))
		allArgNumMatchersAreAnyValue := true
		allOtherMatchersAreAnyValue := true
		for _, subRule := range orRule {
			perArg := subRule.(PerArg)
			for i, valueMatcher := range perArg {
				_, isAnyValue := valueMatcher.(AnyValue)
				if i == argNum {
					allArgNumMatchersAreAnyValue = allArgNumMatchersAreAnyValue && isAnyValue
				} else {
					allOtherMatchersAreAnyValue = allOtherMatchersAreAnyValue && isAnyValue
				}
			}
			repr := perArg[argNum].Repr()
			otherMatchersSig := copyExceptArg(perArg, argNum, invalidValueMatcher{}).signature()
			allOtherMatchersSigs[otherMatchersSig] = struct{}{}
			if _, reprSeen := argExprToOtherMatchersSigs[repr]; !reprSeen {
				argExprToOtherMatchersSigs[repr] = make(map[string]struct{}, len(orRule))
			}
			argExprToOtherMatchersSigs[repr][otherMatchersSig] = struct{}{}
		}
		if allArgNumMatchersAreAnyValue || allOtherMatchersAreAnyValue {
			// Cannot optimize.
			continue
		}
		// Now check if each possible repr of `argNum` got the same set of
		// signatures for other matchers as `allOtherMatchersSigs`.
		sameOtherMarchers := true
		for _, omsigs := range argExprToOtherMatchersSigs {
			if !sameStringSet(omsigs, allOtherMatchersSigs) {
				sameOtherMarchers = false
				break
			}
		}
		if !sameOtherMarchers {
			continue
		}
		// We can simplify the rule by extracting `argNum` out.
		// Create two copies of `orRule`: One with only `argNum`,
		// and the other one with all arguments except `argNum`.
		// This will likely contain many duplicates but that's OK,
		// they'll be optimized out by `deduplicatePerArgs`.
		argNumMatch := Or(make([]SyscallRule, len(orRule)))
		otherArgsMatch := Or(make([]SyscallRule, len(orRule)))
		for i, subRule := range orRule {
			perArg := subRule.(PerArg)
			argNumMatch[i] = copyOnlyArg(perArg, argNum)
			otherArgsMatch[i] = copyExceptArg(perArg, argNum, AnyValue{})
		}
		// Do not attempt to see if other arguments are also eligible for the
		// same optimization, as this would complicate the logic of this
		// already-complicated function further, and will be caught in future
		// iterations of the optimizer anyway.
		// Additionally, `argNumMatch` and `otherArgsMatch` may well be
		// single-item, so the other (simpler) optimizers should run on them
		// first.
		return And{argNumMatch, otherArgsMatch}, true
	}
	return rule, false
}

// optimizeSyscallRuleFuncs losslessly optimizes a SyscallRule using the given
// optimization functions.
// Optimizers should be ranked in order of importance, with the most
// important first.
// An optimizer will be exhausted before the next one is ever run.
// Earlier optimizers are re-exhausted if later optimizers cause change.
func optimizeSyscallRuleFuncs(rule SyscallRule, funcs []ruleOptimizerFunc) SyscallRule {
	for changed := true; changed; {
		for _, fn := range funcs {
			rule.Recurse(func(subRule SyscallRule) SyscallRule {
				return optimizeSyscallRuleFuncs(subRule, funcs)
			})
			if rule, changed = fn(rule); changed {
				break
			}
		}
	}
	return rule
}

// optimizeSyscallRule losslessly optimizes a `SyscallRule`.
func optimizeSyscallRule(rule SyscallRule) SyscallRule {
	return optimizeSyscallRuleFuncs(rule, []ruleOptimizerFunc{
		// Convert Or / And rules with a single rule into that single rule.
		convertSingleCompoundRuleToThatRule[Or],
		convertSingleCompoundRuleToThatRule[And],

		// Flatten Or/And rules.
		flattenCompoundRules[Or],
		flattenCompoundRules[And],

		// Handle MatchAll. This is best done after flattening so that we
		// effectively traverse the whole tree to find a MatchAll by just
		// linearly scanning through the first (and only) level of rules.
		convertMatchAllOrXToMatchAll,
		convertMatchAllAndXToX,

		// Replace all `nil` values in `PerArg` to `AnyValue`, to simplify
		// the `PerArg` matchers below.
		nilInPerArgToAnyValue,

		// Deduplicate redundant `PerArg`s in Or and And.
		// This must come after `nilInPerArgToAnyValue` because it does not
		// handle the nil case.
		deduplicatePerArgs[Or],
		deduplicatePerArgs[And],

		// Remove useless `PerArg` matchers.
		// This must come after `nilInPerArgToAnyValue` because it does not
		// handle the nil case.
		convertUselessPerArgToMatchAll,

		// Extract repeated argument matchers out of `Or` expressions.
		// This must come after `nilInPerArgToAnyValue` because it does not
		// handle the nil case.
		// This should ideally run late in the list because it does a bunch
		// of memory allocations (even in the non-optimizable case), which
		// should be avoided unless there is nothing else left to optimize.
		extractRepeatedMatchers,
	})
}
