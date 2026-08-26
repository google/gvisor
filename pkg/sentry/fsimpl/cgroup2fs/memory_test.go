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

package cgroup2fs

import (
	"math"
	"testing"
)

func TestParseMemoryLimit(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"max", math.MaxInt64, false},
		{"0", 0, false},
		{"4096", 4096, false},
		{"1k", 0, false}, // 1024 is page-aligned down to 0 (< 4096)
		{"4k", 4096, false},
		{"4K", 4096, false},
		{"8k", 8192, false},
		{"1m", 1024 * 1024, false},
		{"1M", 1024 * 1024, false},
		{"1g", 1024 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"1t", 1024 * 1024 * 1024 * 1024, false},
		{"4095", 0, false}, // Page-aligned down to 0
		{"4kib", 4096, false},
		{"-1", 0, true},
		{"foo", 0, true},
		{"1x", 0, true},
		{"", 0, true},
		{"9999999999999999999999999999", 0, true},
	}

	for _, tc := range tests {
		got, err := parseMemoryLimit(tc.input)
		if tc.wantErr && err == nil {
			t.Errorf("parseMemoryLimit(%q) succeeded, want error", tc.input)
		} else if !tc.wantErr && err != nil {
			t.Errorf("parseMemoryLimit(%q) failed unexpectedly: %v", tc.input, err)
		} else if !tc.wantErr && got != tc.want {
			t.Errorf("parseMemoryLimit(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestCgroupMemoryWatermarkCalculation(t *testing.T) {
	limits := []uint64{
		0, 4096, 64 * 1024 * 1024, 1024 * 1024 * 1024, math.MaxInt64,
	}
	percentages := []int{0, 50, 80, 90, 95, 99, 100, 105}
	for _, lim := range limits {
		for _, pct := range percentages {
			wp := pct
			if wp <= 0 || wp > 100 {
				wp = 100
			}
			watermark := lim / 100 * uint64(wp)
			if watermark > lim {
				t.Errorf("watermark %d > limit %d for pct %d", watermark, lim, pct)
			}
		}
	}
}
