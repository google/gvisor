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

	var r string
	for _, b := range u.Release {
		if b == 0 {
			break
		}
		r += string(b)
	}

	s := strings.Split(r, ".")
	if len(s) < 2 {
		return 0, 0, fmt.Errorf("kernel release missing major and minor component: %s", r)
	}

	major, err := strconv.Atoi(s[0])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing major version %q in %q: %v", s[0], r, err)
	}

	minor, err := strconv.Atoi(s[1])
	if err != nil {
		return 0, 0, fmt.Errorf("error parsing minor version %q in %q: %v", s[1], r, err)
	}

	return major, minor, nil
}

// TestHostFeatureFlags tests that all features detected by HostFeatureSet are
// on the host.
//
// It does *not* verify that all features reported by the host are detected by
// HostFeatureSet.
//
// i.e., test that HostFeatureSet is a subset of the host features.
func TestHostFeatureFlags(t *testing.T) {
	cpuinfoBytes, _ := ioutil.ReadFile("/proc/cpuinfo")
	cpuinfo := string(cpuinfoBytes)
	t.Logf("Host cpu info:\n%s", cpuinfo)

	major, minor, err := kernelVersion()
	if err != nil {
		t.Fatalf("Unable to parse kernel version: %v", err)
	}

	re := regexp.MustCompile(`(?m)^flags\s+: (.*)$`)
	m := re.FindStringSubmatch(cpuinfo)
	if len(m) != 2 {
		t.Fatalf("Unable to extract flags from %q", cpuinfo)
	}

	cpuinfoFlags := make(map[string]struct{})
	for _, f := range strings.Split(m[1], " ") {
		cpuinfoFlags[f] = struct{}{}
	}

	fs := HostFeatureSet()

	// All features have a string and appear in host cpuinfo.
	for f := range fs.Set {
		name := f.flagString(false)
		if name == "" {
			t.Errorf("Non-parsable feature: %v", f)
		}

		// Special cases not consistently visible. We don't mind if
		// they are exposed in earlier versions.
		switch {
		// Block 0.
		case f == X86FeatureSDBG && (major < 4 || major == 4 && minor < 3):
			// SDBG only exposed in
			// b1c599b8ff80ea79b9f8277a3f9f36a7b0cfedce (4.3).
			continue
		// Block 2.
		case f == X86FeatureRDT && (major < 4 || major == 4 && minor < 10):
			// RDT only exposed in
			// 4ab1586488cb56ed8728e54c4157cc38646874d9 (4.10).
			continue
		// Block 3.
		case f == X86FeatureAVX512VBMI && (major < 4 || major == 4 && minor < 10):
			// AVX512VBMI only exposed in
			// a8d9df5a509a232a959e4ef2e281f7ecd77810d6 (4.10).
			continue
		case f == X86FeatureUMIP && (major < 4 || major == 4 && minor < 15):
			// UMIP only exposed in
			// 3522c2a6a4f341058b8291326a945e2a2d2aaf55 (4.15).
			continue
		case f == X86FeaturePKU && (major < 4 || major == 4 && minor < 9):
			// PKU only exposed in
			// dfb4a70f20c5b3880da56ee4c9484bdb4e8f1e65 (4.9).
			continue
		// Block 4.
		case f == X86FeatureXSAVES && (major < 4 || major == 4 && minor < 8):
			// XSAVES only exposed in
			// b8be15d588060a03569ac85dc4a0247460988f5b (4.8).
			continue
		}

		hidden := f.flagString(true) == ""
		_, ok := cpuinfoFlags[name]
		if hidden && ok {
			t.Errorf("Unexpectedly hidden flag: %v", f)
		} else if !hidden && !ok {
			t.Errorf("Non-native flag: %v", f)
		}
	}
}
