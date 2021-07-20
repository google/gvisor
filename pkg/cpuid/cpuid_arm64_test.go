// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package cpuid

import (
	"testing"
)

var justFP = &FeatureSet{
	Set: map[Feature]bool{
		ARM64FeatureFP: true,
	}}

func TestHostFeatureSet(t *testing.T) {
	hostFeatures := HostFeatureSet()
	if len(hostFeatures.Set) == 0 {
		t.Errorf("Got invalid feature set %v from HostFeatureSet()", hostFeatures)
	}
}

func TestHasFeature(t *testing.T) {
	if !justFP.HasFeature(ARM64FeatureFP) {
		t.Errorf("HasFeature failed, %v should contain %v", justFP, ARM64FeatureFP)
	}

	if justFP.HasFeature(ARM64FeatureSM3) {
		t.Errorf("HasFeature failed, %v should not contain %v", justFP, ARM64FeatureSM3)
	}
}

func TestFeatureFromString(t *testing.T) {
	f, ok := FeatureFromString("asimd")
	if f != ARM64FeatureASIMD || !ok {
		t.Errorf("got %v want asimd", f)
	}

	f, ok = FeatureFromString("bad")
	if ok {
		t.Errorf("got %v want nothing", f)
	}
}
