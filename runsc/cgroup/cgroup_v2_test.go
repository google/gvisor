// Copyright The runc Authors.
// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cgroup

import (
	"strings"
	"testing"
)

var cgroupv2MountInfo = `29 22 0:26 / /sys/fs/cgroup rw shared:4 - cgroup2 cgroup2 rw,seclabel,nsdelegate`

func TestLoadPathsCgroupv2(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cgroups   string
		mountinfo string
		want      map[string]string
		err       string
	}{
		{
			name:      "cgroupv2",
			cgroups:   "0::/docker/123",
			mountinfo: cgroupv2MountInfo,
			want: map[string]string{
				"cgroup2": "docker/123",
			},
		},

		{
			name:      "cgroupv2-nested",
			cgroups:   "0::/",
			mountinfo: cgroupv2MountInfo,
			want: map[string]string{
				"cgroup2": ".",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.cgroups)
			mountinfo := strings.NewReader(tc.mountinfo)
			got, err := loadPathsHelper(r, mountinfo, true)
			if len(tc.err) == 0 {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			} else if !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("Wrong error message, want: *%s*, got: %v", tc.err, err)
			}
			for key, vWant := range tc.want {
				vGot, ok := got[key]
				if !ok {
					t.Errorf("Missing controller %q", key)
				}
				if vWant != vGot {
					t.Errorf("Wrong controller %q value, want: %q, got: %q", key, vWant, vGot)
				}
				delete(got, key)
			}
			for k, v := range got {
				t.Errorf("Unexpected controller %q: %q", k, v)
			}
		})
	}
}

func TestNumToStr(t *testing.T) {
	cases := map[int64]string{
		0:  "",
		-1: "max",
		10: "10",
	}
	for i, expected := range cases {
		got := numToStr(i)
		if got != expected {
			t.Errorf("expected numToStr(%d) to be %q, got %q", i, expected, got)
		}
	}
}

func TestConvertBlkIOToIOWeightValue(t *testing.T) {
	cases := map[uint16]uint64{
		0:    0,
		10:   1,
		1000: 10000,
	}
	for i, expected := range cases {
		got := convertBlkIOToIOWeightValue(i)
		if got != expected {
			t.Errorf("expected ConvertBlkIOToIOWeightValue(%d) to be %d, got %d", i, expected, got)
		}
	}
}

func TestConvertCPUSharesToCgroupV2Value(t *testing.T) {
	cases := map[uint64]uint64{
		0:      0,
		2:      1,
		262144: 10000,
	}
	for i, expected := range cases {
		got := convertCPUSharesToCgroupV2Value(i)
		if got != expected {
			t.Errorf("expected ConvertCPUSharesToCgroupV2Value(%d) to be %d, got %d", i, expected, got)
		}
	}
}

func TestConvertMemorySwapToCgroupV2Value(t *testing.T) {
	cases := []struct {
		memswap, memory int64
		expected        int64
		expErr          bool
	}{
		{
			memswap:  0,
			memory:   0,
			expected: 0,
		},
		{
			memswap:  -1,
			memory:   0,
			expected: -1,
		},
		{
			memswap:  -1,
			memory:   -1,
			expected: -1,
		},
		{
			memswap: -2,
			memory:  0,
			expErr:  true,
		},
		{
			memswap:  -1,
			memory:   1000,
			expected: -1,
		},
		{
			memswap:  1000,
			memory:   1000,
			expected: 0,
		},
		{
			memswap:  500,
			memory:   200,
			expected: 300,
		},
		{
			memswap: 300,
			memory:  400,
			expErr:  true,
		},
		{
			memswap: 300,
			memory:  0,
			expErr:  true,
		},
		{
			memswap: 300,
			memory:  -300,
			expErr:  true,
		},
		{
			memswap: 300,
			memory:  -1,
			expErr:  true,
		},
	}

	for _, c := range cases {
		swap, err := convertMemorySwapToCgroupV2Value(c.memswap, c.memory)
		if c.expErr {
			if err == nil {
				t.Errorf("memswap: %d, memory %d, expected error, got %d, nil", c.memswap, c.memory, swap)
			}
			// no more checks
			continue
		}
		if err != nil {
			t.Errorf("memswap: %d, memory %d, expected success, got error %s", c.memswap, c.memory, err)
		}
		if swap != c.expected {
			t.Errorf("memswap: %d, memory %d, expected %d, got %d", c.memswap, c.memory, c.expected, swap)
		}
	}
}

func TestParseCPUQuota(t *testing.T) {
	cases := []struct {
		quota    string
		expected float64
		expErr   bool
	}{
		{
			quota:    "max 100000\n",
			expected: -1,
		},
		{
			quota:    "10000 100000",
			expected: 0.1,
		},
		{
			quota:    "20000 100000\n",
			expected: 0.2,
		},

		{
			quota:    "-1",
			expected: -1,
			expErr:   true,
		},
	}

	for _, c := range cases {
		res, err := parseCPUQuota(c.quota)
		if c.expErr {
			if err == nil {
				t.Errorf("quota: %q, expected error, got %.2f, nil", c.quota, res)
			}
			continue
		}
		if err != nil {
			t.Errorf("quota: %q, expected success, got error %s", c.quota, err)
		}
		if res != c.expected {
			t.Errorf("quota: %q, expected %.2f, got error %.2f", c.quota, c.expected, res)
		}
	}
}
