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

// splitMatchers replaces every `splittableValueMatcher` with a
// `splitMatcher` value matcher instead.
// This enables optimizations that are split-aware to run without
// the need to have logic handling this conversion.
func splitMatchers(rule SyscallRule) (SyscallRule, bool) {
	perArg, isPerArg := rule.(PerArg)
	if !isPerArg {
		return rule, false
	}
	changed := false
	for argNum, valueMatcher := range perArg {
		if _, isAlreadySplit := valueMatcher.(splitMatcher); isAlreadySplit {
			continue
		}
		splittableMatcher, isSplittableMatcher := valueMatcher.(splittableValueMatcher)
		if !isSplittableMatcher {
			continue
		}
		perArg[argNum] = splittableMatcher.split()
		changed = true
	}
	return perArg, changed
}

// simplifyHalfValueMatcher may convert a `halfValueMatcher` to a simpler
// (and potentially faster) representation.
func simplifyHalfValueMatcher(hvm halfValueMatcher) halfValueMatcher {
	switch v := hvm.(type) {
	case halfNotSet:
		if v == 0 {
			return halfAnyValue{}
		}
	case halfMaskedEqual:
		if v.mask == 0 && v.value == 0 {
			return halfAnyValue{}
		}
		if v.mask == 0xffffffff {
			return halfEqualTo(v.value)
		}
	}
	return hvm
}

// simplifyHalfValueMatchers replace `halfValueMatcher`s with their simplified
// version.
func simplifyHalfValueMatchers(rule SyscallRule) (SyscallRule, bool) {
	perArg, isPerArg := rule.(PerArg)
	if !isPerArg {
		return rule, false
	}
	changed := false
	for i, valueMatcher := range perArg {
		sm, isSplitMatcher := valueMatcher.(splitMatcher)
		if !isSplitMatcher {
			continue
		}
		if newHigh := simplifyHalfValueMatcher(sm.highMatcher); newHigh.Repr() != sm.highMatcher.Repr() {
			sm.highMatcher = newHigh
			perArg[i] = sm
			changed = true
		}
		if newLow := simplifyHalfValueMatcher(sm.lowMatcher); newLow.Repr() != sm.lowMatcher.Repr() {
			sm.lowMatcher = newLow
			perArg[i] = sm
			changed = true
		}
	}
	return perArg, changed
}

// anySplitMatchersToAnyValue converts `splitMatcher`s where both halves
// match any value to a single AnyValue{} rule.
func anySplitMatchersToAnyValue(rule SyscallRule) (SyscallRule, bool) {
	perArg, isPerArg := rule.(PerArg)
	if !isPerArg {
		return rule, false
	}
	changed := false
	for argNum, valueMatcher := range perArg {
		sm, isSplitMatcher := valueMatcher.(splitMatcher)
		if !isSplitMatcher {
			continue
		}
		_, highIsAny := sm.highMatcher.(halfAnyValue)
		_, lowIsAny := sm.lowMatcher.(halfAnyValue)
		if highIsAny && lowIsAny {
			perArg[argNum] = AnyValue{}
			changed = true
		}
	}
	return perArg, changed
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

// sameStringSet returns whether the given string sets are equal.
func sameStringSet(m1, m2 map[string]struct{}) bool {
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

	allOtherMatchersSigs := make(map[string]struct{}, len(orRule))
	argExprToOtherMatchersSigs := make(map[string]map[string]struct{}, len(orRule))
	for argNum := 0; argNum < len(orRule[0].(PerArg)); argNum++ {
		// Check if this argNum is always AnyValue,
		// or if all other arguments are always AnyValue.
		// If either of that is true, there is nothing for this filter to do.
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
		}
		if allArgNumMatchersAreAnyValue || allOtherMatchersAreAnyValue {
			// Cannot optimize.
			continue
		}
		// Check if `argNum` takes on a set of matchers common for all
		// combinations of all other matchers.
		clear(allOtherMatchersSigs)
		clear(argExprToOtherMatchersSigs)
		for _, subRule := range orRule {
			perArg := subRule.(PerArg)
			repr := perArg[argNum].Repr()
			otherMatchers := perArg.clone()
			otherMatchers[argNum] = invalidValueMatcher{}
			otherMatchersSig := otherMatchers.signature()
			allOtherMatchersSigs[otherMatchersSig] = struct{}{}
			if _, reprSeen := argExprToOtherMatchersSigs[repr]; !reprSeen {
				argExprToOtherMatchersSigs[repr] = make(map[string]struct{}, len(orRule))
			}
			argExprToOtherMatchersSigs[repr][otherMatchersSig] = struct{}{}
		}
		// Now check if each possible repr of `argNum` got the same set of
		// signatures for other matchers as `allOtherMatchersSigs`.
		sameOtherMatchers := true
		for _, omsigs := range argExprToOtherMatchersSigs {
			if !sameStringSet(omsigs, allOtherMatchersSigs) {
				sameOtherMatchers = false
				break
			}
		}
		if !sameOtherMatchers {
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
			onlyArg := PerArg{AnyValue{}, AnyValue{}, AnyValue{}, AnyValue{}, AnyValue{}, AnyValue{}, AnyValue{}}
			onlyArg[argNum] = perArg[argNum]
			allExceptArg := perArg.clone()
			allExceptArg[argNum] = AnyValue{}
			argNumMatch[i] = onlyArg
			otherArgsMatch[i] = allExceptArg
		}
		// Attempt to optimize the "other" arguments:
		otherArgsMatchOpt, _ := extractRepeatedMatchers(otherArgsMatch)
		return And{argNumMatch, otherArgsMatchOpt}, true
	}
	return rule, false
}

// optimizationRun is a stateful struct tracking the state of an optimization
// over a rule. It may not be used concurrently.
type optimizationRun struct {
	// funcs is the list of optimizer functions to run on the rules.
	// Optimizers should be ranked in order of importance, with the most
	// important first.
	// An optimizer will be exhausted before the next one is ever run.
	// Earlier optimizers are re-exhausted if later optimizers cause change.
	funcs []ruleOptimizerFunc

	// recurseFuncs is a list of closures that correspond one-to-one to `funcs`
	// and are suitable for passing to `SyscallRule.Recurse`. They are stored
	// here in order to be allocated once, as opposed to escaping if they were
	// specified directly as argument to `SyscallRule.Recurse`.
	recurseFuncs []func(subRule SyscallRule) SyscallRule

	// changed tracks whether any change has been made in the current pass.
	// It is updated as the optimizer runs.
	changed bool
}

// apply recursively applies `opt.funcs[funcIndex]` to the given `rule`.
// It sets `opt.changed` to true if there has been any change.
func (opt *optimizationRun) apply(rule SyscallRule, funcIndex int) SyscallRule {
	rule.Recurse(opt.recurseFuncs[funcIndex])
	if opt.changed {
		return rule
	}
	rule, opt.changed = opt.funcs[funcIndex](rule)
	return rule
}

// optimize losslessly optimizes a SyscallRule using the `optimizationRun`'s
// optimizer functions.
// It may not be called concurrently.
func (opt *optimizationRun) optimize(rule SyscallRule) SyscallRule {
	opt.recurseFuncs = make([]func(SyscallRule) SyscallRule, len(opt.funcs))
	for i := range opt.funcs {
		funcIndex := i
		opt.recurseFuncs[funcIndex] = func(subRule SyscallRule) SyscallRule {
			return opt.apply(subRule, funcIndex)
		}
	}
	for opt.changed = true; opt.changed; {
		for i := range opt.funcs {
			opt.changed = false
			rule = opt.apply(rule, i)
			if opt.changed {
				break
			}
		}
	}
	return rule
}

// optimizeSyscallRule losslessly optimizes a `SyscallRule`.
func optimizeSyscallRule(rule SyscallRule) SyscallRule {
	return (&optimizationRun{
		funcs: []ruleOptimizerFunc{
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

			// Replace `ValueMatcher`s that are splittable into their split version.
			splitMatchers,

			// Replace `halfValueMatcher`s with their simplified version.
			simplifyHalfValueMatchers,

			// Replace `splitMatchers` that match any value with `AnyValue`.
			anySplitMatchersToAnyValue,

			// Extract repeated argument matchers out of `Or` expressions.
			// This must come after `nilInPerArgToAnyValue` because it does not
			// handle the nil case.
			// This should ideally run late in the list because it does a bunch
			// of memory allocations (even in the non-optimizable case), which
			// should be avoided unless there is nothing else left to optimize.
			extractRepeatedMatchers,
		},
	}).optimize(rule)
}
