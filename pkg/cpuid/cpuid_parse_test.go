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

package cpuid

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func kernelVersion() (int, int, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return 0, 0, err
	}

	var sb strings.Builder
	for _, b := range u.Release {
		if b == 0 {
			break
		}
		sb.WriteByte(byte(b))
	}

	s := strings.Split(sb.String(), ".")
	if len(s) < 2 {
		return 0, 0, fmt.Errorf("kernel release missing major and minor component: %s", sb.String())
	}

	major, err := strconv.Atoi(s[0])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing major version %q in %q: %w", s[0], sb.String(), err)
	}

	minor, err := strconv.Atoi(s[1])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing minor version %q in %q: %w", s[1], sb.String(), err)
	}

	return major, minor, nil
}

// TestHostFeatureFlags tests that all features detected by HostFeatureSet are
// on the host.
//
// It does *not* verify that all features reported by the host are detected by
// HostFeatureSet. Linux has synthetic Linux-specific features that have no
// analog in the actual CPUID feature set.
func TestHostFeatureFlags(t *testing.T) {
	// Extract the kernel version.
	major, minor, err := kernelVersion()
	if err != nil {
		t.Fatalf("Unable to parse kernel version: %v", err)
	}

	// Extract all cpuinfo flags.
	cpuinfoBytes, _ := ioutil.ReadFile("/proc/cpuinfo")
	cpuinfo := string(cpuinfoBytes)
	re := regexp.MustCompile(`(?m)^flags\s+: (.*)$`)
	m := re.FindStringSubmatch(cpuinfo)
	if len(m) != 2 {
		t.Fatalf("Unable to extract flags from %q", cpuinfo)
	}
	cpuinfoFlags := make(map[string]struct{})
	for _, f := range strings.Split(m[1], " ") {
		cpuinfoFlags[f] = struct{}{}
	}

	// Check against host flags.
	fs := HostFeatureSet()
	for feature, info := range allFeatures {
		// Special cases not consistently visible. We don't mind if
		// they are exposed in earlier versions.
		if archSkipFeature(feature, major, minor) {
			continue
		}

		// Check against the flags.
		_, ok := cpuinfoFlags[feature.String()]
		if !info.shouldAppear && ok {
			t.Errorf("Unexpected flag: %v", feature)
		} else if info.shouldAppear && fs.HasFeature(feature) && !ok {
			t.Errorf("Missing flag: %v", feature)
		}
	}
}
