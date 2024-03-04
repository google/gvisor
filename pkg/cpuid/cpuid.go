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
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// contextID is the package for anyContext.Context.Value keys.
type contextID int

const (
	// CtxFeatureSet is the FeatureSet for the context.
	CtxFeatureSet contextID = iota

	// hardware capability bit vector.
	_AT_HWCAP = 16
	// hardware capability bit vector 2.
	_AT_HWCAP2 = 26
)

// anyContext represents context.Context.
type anyContext interface {
	Value(key any) any
}

// FromContext returns the FeatureSet from the context, if available.
func FromContext(ctx anyContext) FeatureSet {
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

// +stateify savable
type hwCap struct {
	// hwCap1 stores HWCAP bits exposed through the elf auxiliary vector.
	hwCap1 uint64
	// hwCap2 stores HWCAP2 bits exposed through the elf auxiliary vector.
	hwCap2 uint64
}

// The auxiliary vector of a process on the Linux system can be read
// from /proc/self/auxv, and tags and values are stored as 8-bytes
// decimal key-value pairs on the 64-bit system.
//
// $ od -t d8 /proc/self/auxv
//
//	0000000                   33      140734615224320
//	0000020                   16           3219913727
//	0000040                    6                 4096
//	0000060                   17                  100
//	0000100                    3       94665627353152
//	0000120                    4                   56
//	0000140                    5                    9
//	0000160                    7      140425502162944
//	0000200                    8                    0
//	0000220                    9       94665627365760
//	0000240                   11                 1000
//	0000260                   12                 1000
//	0000300                   13                 1000
//	0000320                   14                 1000
//	0000340                   23                    0
//	0000360                   25      140734614619513
//	0000400                   26                    0
//	0000420                   31      140734614626284
//	0000440                   15      140734614619529
//	0000460                    0                    0
func readHWCap(auxvFilepath string) (hwCap, error) {
	c := hwCap{}
	if runtime.GOOS != "linux" {
		// Don't try to read Linux-specific /proc files.
		return c, fmt.Errorf("readHwCap only supported on linux, not %s", runtime.GOOS)
	}

	auxv, err := os.ReadFile(auxvFilepath)
	if err != nil {
		return c, fmt.Errorf("failed to read file %s: %w", auxvFilepath, err)
	}

	l := len(auxv) / 16
	for i := 0; i < l; i++ {
		tag := binary.LittleEndian.Uint64(auxv[i*16:])
		val := binary.LittleEndian.Uint64(auxv[i*16+8:])
		if tag == _AT_HWCAP {
			c.hwCap1 = val
		} else if tag == _AT_HWCAP2 {
			c.hwCap2 = val
		}

		if (c.hwCap1 != 0) && (c.hwCap2 != 0) {
			break
		}
	}
	return c, nil
}

func initHWCap() {
	c, err := readHWCap("/proc/self/auxv")
	if err != nil {
		log.Warningf("cpuid HWCap not initialized: %w", err)
	} else {
		hostFeatureSet.hwCap = c
	}
}

var initOnce sync.Once

// Initialize initializes the global data structures used by this package.
// Must be called prior to using anything else in this package.
func Initialize() {
	initOnce.Do(archInitialize)
}
