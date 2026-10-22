// Copyright 2026 The gVisor Authors.
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
	"bytes"
	"strings"
	"testing"
)

// cpuInfoFeatures returns the names on the Features line written by
// WriteCPUInfoTo for a feature set with the given host HWCAP words.
func cpuInfoFeatures(t *testing.T, hwCap1, hwCap2 uint64) string {
	t.Helper()
	fs := FeatureSet{hwCap: hwCap{hwCap1: hwCap1, hwCap2: hwCap2}}
	var buf bytes.Buffer
	fs.WriteCPUInfoTo(0, 1, &buf)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "Features") {
			_, names, ok := strings.Cut(line, ":")
			if !ok {
				t.Fatalf("Features line %q has no colon", line)
			}
			return strings.TrimSpace(names)
		}
	}
	t.Fatalf("no Features line in cpuinfo:\n%s", buf.String())
	return ""
}

// TestCPUInfoFeaturesMatchAllowedHWCap checks that /proc/cpuinfo lists exactly
// the HWCAP bits that apps receive in AT_HWCAP, in bit order.
func TestCPUInfoFeaturesMatchAllowedHWCap(t *testing.T) {
	for _, tc := range []struct {
		name           string
		hwCap1, hwCap2 uint64
		want           string
	}{
		{
			name: "none",
		},
		{
			name:   "all host bits",
			hwCap1: ^uint64(0),
			hwCap2: ^uint64(0),
			want: "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp " +
				"asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm " +
				"dit uscat ilrcpc flagm",
		},
		{
			// cpuid, sve, ssbs, sb, paca and pacg are never given to apps.
			// HWCAP2 has no named features yet; its bits must stay hidden
			// once it does.
			name:   "hidden bits only",
			hwCap1: HWCAP_CPUID | HWCAP_SVE | HWCAP_SSBS | HWCAP_SB | HWCAP_PACA | HWCAP_PACG,
			hwCap2: HWCAP2_SVE2 | HWCAP2_DCPODP,
		},
		{
			name:   "allowed and hidden bits",
			hwCap1: HWCAP_FP | HWCAP_CPUID | HWCAP_SVE | HWCAP_DIT | HWCAP_ILRCPC | HWCAP_SSBS,
			want:   "fp dit ilrcpc",
		},
		{
			name:   "new bits only",
			hwCap1: HWCAP_FLAGM | HWCAP_USCAT,
			want:   "uscat flagm",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cpuInfoFeatures(t, tc.hwCap1, tc.hwCap2); got != tc.want {
				t.Errorf("Features = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestArchFlagOrderIncreasing checks that every defined feature is visited once,
// in increasing bit order, whatever gaps there are in the numbering.
func TestArchFlagOrderIncreasing(t *testing.T) {
	var prev Feature = -1
	count := 0
	archFlagOrder(func(f Feature) {
		if _, ok := allFeatures[f]; !ok {
			t.Errorf("archFlagOrder visited undefined feature %d", f)
		}
		if f <= prev {
			t.Errorf("archFlagOrder visited %v after %v, want increasing order", f, prev)
		}
		prev = f
		count++
	})
	if count != len(allFeatures) {
		t.Errorf("archFlagOrder visited %d features, want %d", count, len(allFeatures))
	}
}
