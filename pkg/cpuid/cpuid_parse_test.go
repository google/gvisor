// Copyright 2018 Google LLC
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

package cpuid

import (
	"io/ioutil"
	"strings"
	"testing"
)

// TestHostFeatureFlags ensures that package cpuid recognizes all features
// present on this host.
func TestHostFeatureFlags(t *testing.T) {
	cpuinfoBytes, _ := ioutil.ReadFile("/proc/cpuinfo")
	cpuinfo := string(cpuinfoBytes)
	t.Logf("Host cpu info:\n%s", cpuinfo)

	for f := range HostFeatureSet().Set {
		if f.flagString(false) == "" {
			t.Errorf("Non-parsable feature: %v", f)
		}
		if s := f.flagString(true); !strings.Contains(cpuinfo, s) {
			t.Errorf("Non-native flag: %v", f)
		}
	}
}
