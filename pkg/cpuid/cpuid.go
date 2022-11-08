// Copyright 2019 The gVisor Authors.
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

// Package cpuid provides basic functionality for creating and adjusting CPU
// feature sets.
//
// Each architecture should define its own FeatureSet type, that must be
// savable, along with an allFeatures map, appropriate arch hooks and a
// HostFeatureSet function. This file contains common functionality to all
// architectures, which is essentially string munging and some errors.
//
// Individual architectures may export methods on FeatureSet that are relevant,
// e.g. FeatureSet.Vendor(). Common to all architectures, FeatureSets include
// HasFeature, which provides a trivial mechanism to test for the presence of
// specific hardware features. The hardware features are also defined on a
// per-architecture basis.
package cpuid

import (
	"fmt"
	"strings"
)

// contextID is the package for context.Context.Value keys.
type contextID int

const (
	// CtxFeatureSet is the FeatureSet for the context.
	CtxFeatureSet contextID = iota
)

// context represents context.Context.
type context interface {
	Value(key any) any
}

// FromContext returns the FeatureSet from the context, if available.
func FromContext(ctx context) FeatureSet {
	v := ctx.Value(CtxFeatureSet)
	if v == nil {
		return FeatureSet{} // Panics if used.
	}
	return v.(FeatureSet)
}

// Feature is a unique identifier for a particular cpu feature. We just use an
// int as a feature number on x86 and arm64.
//
// On x86, features are numbered according to "blocks". Each block is 32 bits, and
// feature bits from the same source (cpuid leaf/level) are in the same block.
//
// On arm64, features are numbered according to the ELF HWCAP definition, from
// arch/arm64/include/uapi/asm/hwcap.h.
type Feature int

// allFeatureInfo is the value for allFeatures.
type allFeatureInfo struct {
	// displayName is the short display name for the feature.
	displayName string

	// shouldAppear indicates whether the feature normally appears in
	// cpuinfo. This affects FlagString only.
	shouldAppear bool
}

// String implements fmt.Stringer.String.
func (f Feature) String() string {
	info, ok := allFeatures[f]
	if ok {
		return info.displayName
	}
	return fmt.Sprintf("[0x%x?]", int(f)) // No given name.
}

// reverseMap is a map from displayName to Feature.
var reverseMap = func() map[string]Feature {
	m := make(map[string]Feature)
	for feature, info := range allFeatures {
		if info.displayName != "" {
			// Sanity check that the name is unique.
			if old, ok := m[info.displayName]; ok {
				panic(fmt.Sprintf("feature %v has conflicting values (0x%x vs 0x%x)", info.displayName, old, feature))
			}
			m[info.displayName] = feature
		}
	}
	return m
}()

// FeatureFromString returns the Feature associated with the given feature
// string plus a bool to indicate if it could find the feature.
func FeatureFromString(s string) (Feature, bool) {
	feature, ok := reverseMap[s]
	return feature, ok
}

// AllFeatures returns the full set of all possible features.
func AllFeatures() (features []Feature) {
	archFlagOrder(func(f Feature) {
		features = append(features, f)
	})
	return
}

// Subtract returns the features present in fs that are not present in other.
// If all features in fs are present in other, Subtract returns nil.
//
// This does not check for any kinds of incompatibility.
func (fs FeatureSet) Subtract(other FeatureSet) (left map[Feature]struct{}) {
	for feature := range allFeatures {
		thisHas := fs.HasFeature(feature)
		otherHas := other.HasFeature(feature)
		if thisHas && !otherHas {
			if left == nil {
				left = make(map[Feature]struct{})
			}
			left[feature] = struct{}{}
		}
	}
	return
}

// FlagString prints out supported CPU flags.
func (fs FeatureSet) FlagString() string {
	var s []string
	archFlagOrder(func(feature Feature) {
		if !fs.HasFeature(feature) {
			return
		}
		info := allFeatures[feature]
		if !info.shouldAppear {
			return
		}
		s = append(s, info.displayName)
	})
	return strings.Join(s, " ")
}

// ErrIncompatible is returned for incompatible feature sets.
type ErrIncompatible struct {
	reason string
}

// Error implements error.Error.
func (e *ErrIncompatible) Error() string {
	return fmt.Sprintf("incompatible FeatureSet: %v", e.reason)
}

// CheckHostCompatible returns nil if fs is a subset of the host feature set.
func (fs FeatureSet) CheckHostCompatible() error {
	hfs := HostFeatureSet()

	// Check that hfs is a superset of fs.
	if diff := fs.Subtract(hfs); len(diff) > 0 {
		return &ErrIncompatible{
			reason: fmt.Sprintf("missing features: %v", diff),
		}
	}

	// Make arch-specific checks.
	return fs.archCheckHostCompatible(hfs)
}
