// Copyright 2021 The gVisor Authors.
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

//go:build amd64
// +build amd64

package mitigate

import (
	"io/ioutil"
	"strings"
	"testing"
)

// TestMockCPUSet tests mock cpu test cases against the cpuSet functions.
func TestMockCPUSet(t *testing.T) {
	for _, tc := range []struct {
		testCase     MockCPU
		isVulnerable bool
	}{
		{
			testCase:     AMD8,
			isVulnerable: false,
		},
		{
			testCase:     Haswell2,
			isVulnerable: true,
		},
		{
			testCase:     Haswell2core,
			isVulnerable: true,
		},
		{
			testCase:     CascadeLake2,
			isVulnerable: true,
		},
		{
			testCase:     CascadeLake4,
			isVulnerable: true,
		},
	} {
		t.Run(tc.testCase.Name, func(t *testing.T) {
			data := tc.testCase.MakeCPUSet().String()
			set, err := NewCPUSet(data)
			if err != nil {
				t.Fatalf("Failed to create cpuSet: %v", err)
			}

			if tc.testCase.NumCPUs() != len(set) {
				t.Fatalf("Got wrong number of CPUs: want: %d got: %d", tc.testCase.NumCPUs(), len(set))
			}

			if set.IsVulnerable() != tc.isVulnerable {
				t.Fatalf("incorrect vulnerable value: got: %t want: %t", set.IsVulnerable(), tc.isVulnerable)
			}
			t.Logf("data: %s", data)
		})
	}
}

// TestGetCPU tests basic parsing of single CPU strings from reading
// /proc/cpuinfo.
func TestGetCPU(t *testing.T) {
	data := `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
physical id: 0
core id		: 0
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit
`
	want := CPU{
		processorNumber: 0,
		vendorID:        "GenuineIntel",
		cpuFamily:       6,
		model:           85,
		physicalID:      0,
		coreID:          0,
		bugs: map[string]struct{}{
			"cpu_meltdown":      {},
			"spectre_v1":        {},
			"spectre_v2":        {},
			"spec_store_bypass": {},
			"l1tf":              {},
			"mds":               {},
			"swapgs":            {},
			"taa":               {},
			"itlb_multihit":     {},
		},
	}

	got, err := newCPU(data)
	if err != nil {
		t.Fatalf("getCpu failed with error: %v", err)
	}

	if !want.SimilarTo(got) {
		t.Fatalf("Failed cpus not similar: got: %+v, want: %+v", got, want)
	}

	if !got.IsVulnerable() {
		t.Fatalf("Failed: cpu should be vulnerable.")
	}
}

func TestInvalid(t *testing.T) {
	result, err := newCPU(`something not a processor`)
	if err == nil {
		t.Fatalf("getCPU set didn't return an error: %+v", result)
	}

	if !strings.Contains(err.Error(), "failed to match key \"processor\"") {
		t.Fatalf("Incorrect error returned: %v", err)
	}
}

// TestCPUSet tests getting the right number of CPUs from
// parsing full output of /proc/cpuinfo.
func TestCPUSet(t *testing.T) {
	data := `processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 63
model name	: Intel(R) Xeon(R) CPU @ 2.30GHz
stepping	: 0
microcode	: 0x1
cpu MHz		: 2299.998
cache size	: 46080 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid xsaveopt arat md_clear arch_capabilities
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs
bogomips	: 4599.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 63
model name	: Intel(R) Xeon(R) CPU @ 2.30GHz
stepping	: 0
microcode	: 0x1
cpu MHz		: 2299.998
cache size	: 46080 KB
physical id	: 0
siblings	: 2
core id		: 0
cpu cores	: 1
apicid		: 1
initial apicid	: 1
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid xsaveopt arat md_clear arch_capabilities
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs
bogomips	: 4599.99
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:
`
	cpuSet, err := NewCPUSet(data)
	if err != nil {
		t.Fatalf("getCPUSet failed: %v", err)
	}

	wantCPULen := 2
	if len(cpuSet) != wantCPULen {
		t.Fatalf("Num CPU mismatch: want: %d, got: %d", wantCPULen, len(cpuSet))
	}

	wantCPU := CPU{
		vendorID:  "GenuineIntel",
		cpuFamily: 6,
		model:     63,
		bugs: map[string]struct{}{
			"cpu_meltdown":      {},
			"spectre_v1":        {},
			"spectre_v2":        {},
			"spec_store_bypass": {},
			"l1tf":              {},
			"mds":               {},
			"swapgs":            {},
		},
	}

	for _, c := range cpuSet {
		if !wantCPU.SimilarTo(c) {
			t.Fatalf("Failed cpus not equal: got: %+v, want: %+v", c, wantCPU)
		}
	}
}

// TestReadFile is a smoke test for parsing methods.
func TestReadFile(t *testing.T) {
	data, err := ioutil.ReadFile("/proc/cpuinfo")
	if err != nil {
		t.Fatalf("Failed to read cpuinfo: %v", err)
	}

	set, err := NewCPUSet(string(data))
	if err != nil {
		t.Fatalf("Failed to parse CPU data %v\n%s", err, data)
	}

	if len(set) < 1 {
		t.Fatalf("Failed to parse any CPUs: %d", len(set))
	}

	t.Log(set)
}

// TestVulnerable tests if the isVulnerable method is correct
// among known CPUs in GCP.
func TestVulnerable(t *testing.T) {
	const haswell = `processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 63
model name      : Intel(R) Xeon(R) CPU @ 2.30GHz
stepping        : 0
microcode       : 0x1
cpu MHz         : 2299.998
cache size      : 46080 KB
physical id     : 0
siblings        : 4
core id         : 0
cpu cores       : 2
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid xsaveopt arat md_clear arch_capabilities
bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs
bogomips        : 4599.99
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:`

	const skylake = `processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 85
model name      : Intel(R) Xeon(R) CPU @ 2.00GHz
stepping        : 3
microcode       : 0x1
cpu MHz         : 2000.180
cache size      : 39424 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat md_clear arch_capabilities
bugs            : cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa
bogomips        : 4000.36
clflush size    : 64
cache_alignment : 64
address sizes   : 46 bits physical, 48 bits virtual
power management:`

	const amd = `processor       : 0
vendor_id       : AuthenticAMD
cpu family      : 23
model           : 49
model name      : AMD EPYC 7B12
stepping        : 0
microcode       : 0x1000065
cpu MHz         : 2250.000
cache size      : 512 KB
physical id     : 0
siblings        : 2
core id         : 0
cpu cores       : 1
apicid          : 0
initial apicid  : 0
fpu             : yes
fpu_exception   : yes
cpuid level     : 13
wp              : yes
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid extd_apicid tsc_known_freq pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a misalignsse 3dnowprefetch osvw topoext ssbd ibrs ibpb stibp vmmcall fsgsbase tsc_adjust bmi1 avx2 smep bmi2 rdseed adx smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 clzero xsaveerptr arat npt nrip_save umip rdpid
bugs            : sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass
bogomips        : 4500.00
TLB size        : 3072 4K pages
clflush size    : 64
cache_alignment : 64
address sizes   : 48 bits physical, 48 bits virtual
power management:`

	for _, tc := range []struct {
		name       string
		cpuString  string
		vulnerable bool
	}{
		{
			name:       "haswell",
			cpuString:  haswell,
			vulnerable: true,
		}, {
			name:       "skylake",
			cpuString:  skylake,
			vulnerable: true,
		}, {
			name:       "amd",
			cpuString:  amd,
			vulnerable: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := NewCPUSet(tc.cpuString)
			if err != nil {
				t.Fatalf("Failed to getCPUSet:%v\n %s", err, tc.cpuString)
			}

			if len(set) < 1 {
				t.Fatalf("Returned empty cpu set: %v", set)
			}

			for _, c := range set {
				got := func() bool {
					return c.IsVulnerable()
				}()

				if got != tc.vulnerable {
					t.Fatalf("Mismatch vulnerable for cpu %s: got %t want: %t", tc.name, tc.vulnerable, got)
				}
			}
		})
	}
}
