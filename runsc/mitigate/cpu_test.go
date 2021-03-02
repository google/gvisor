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

package mitigate

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

// mockCPU represents data from CPUs that will be mitigated.
type mockCPU struct {
	name           string
	vendorID       string
	family         int
	model          int
	modelName      string
	bugs           string
	physicalCores  int
	cores          int
	threadsPerCore int
}

var cascadeLake4 = mockCPU{
	name:           "CascadeLake",
	vendorID:       "GenuineIntel",
	family:         6,
	model:          85,
	modelName:      "Intel(R) Xeon(R) CPU",
	bugs:           "spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa",
	physicalCores:  1,
	cores:          2,
	threadsPerCore: 2,
}

var haswell2 = mockCPU{
	name:           "Haswell",
	vendorID:       "GenuineIntel",
	family:         6,
	model:          63,
	modelName:      "Intel(R) Xeon(R) CPU",
	bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	physicalCores:  1,
	cores:          1,
	threadsPerCore: 2,
}

var haswell2core = mockCPU{
	name:           "Haswell2Physical",
	vendorID:       "GenuineIntel",
	family:         6,
	model:          63,
	modelName:      "Intel(R) Xeon(R) CPU",
	bugs:           "cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs",
	physicalCores:  2,
	cores:          1,
	threadsPerCore: 1,
}

var amd8 = mockCPU{
	name:           "AMD",
	vendorID:       "AuthenticAMD",
	family:         23,
	model:          49,
	modelName:      "AMD EPYC 7B12",
	bugs:           "sysret_ss_attrs spectre_v1 spectre_v2 spec_store_bypass",
	physicalCores:  4,
	cores:          1,
	threadsPerCore: 2,
}

// makeCPUString makes a string formated like /proc/cpuinfo for each cpuTestCase
func (tc mockCPU) makeCPUString() string {
	template := `processor	: %d
vendor_id	: %s
cpu family	: %d
model		: %d
model name	: %s
physical id  : %d
core id		: %d
cpu cores	: %d
bugs		: %s
`
	ret := ``
	for i := 0; i < tc.physicalCores; i++ {
		for j := 0; j < tc.cores; j++ {
			for k := 0; k < tc.threadsPerCore; k++ {
				processorNum := (i*tc.cores+j)*tc.threadsPerCore + k
				ret += fmt.Sprintf(template,
					processorNum,              /*processor*/
					tc.vendorID,               /*vendor_id*/
					tc.family,                 /*cpu family*/
					tc.model,                  /*model*/
					tc.modelName,              /*model name*/
					i,                         /*physical id*/
					j,                         /*core id*/
					tc.cores*tc.physicalCores, /*cpu cores*/
					tc.bugs /*bugs*/)
			}
		}
	}
	return ret
}

func (tc mockCPU) makeSysPossibleString() string {
	max := tc.physicalCores * tc.cores * tc.threadsPerCore
	if max == 1 {
		return "0"
	}
	return fmt.Sprintf("0-%d", max-1)
}

// TestMockCPUSet tests mock cpu test cases against the cpuSet functions.
func TestMockCPUSet(t *testing.T) {
	for _, tc := range []struct {
		testCase     mockCPU
		isVulnerable bool
	}{
		{
			testCase:     amd8,
			isVulnerable: false,
		},
		{
			testCase:     haswell2,
			isVulnerable: true,
		},
		{
			testCase:     haswell2core,
			isVulnerable: true,
		},

		{
			testCase:     cascadeLake4,
			isVulnerable: true,
		},
	} {
		t.Run(tc.testCase.name, func(t *testing.T) {
			data := tc.testCase.makeCPUString()
			vulnerable := func(t thread) bool {
				return t.isVulnerable()
			}
			set, err := newCPUSet([]byte(data), vulnerable)
			if err != nil {
				t.Fatalf("Failed to ")
			}
			remaining := set.getRemainingList()
			// In the non-vulnerable case, no cores should be shutdown so all should remain.
			want := tc.testCase.physicalCores * tc.testCase.cores * tc.testCase.threadsPerCore
			if tc.isVulnerable {
				want = tc.testCase.physicalCores * tc.testCase.cores
			}

			if want != len(remaining) {
				t.Fatalf("Failed to shutdown the correct number of cores: want: %d got: %d", want, len(remaining))
			}

			if !tc.isVulnerable {
				return
			}

			// If the set is vulnerable, we expect only 1 thread per hyperthread pair.
			for _, r := range remaining {
				if _, ok := set[r.id]; !ok {
					t.Fatalf("Entry %+v not in map, there must be two entries in the same thread group.", r)
				}
				delete(set, r.id)
			}

			possible := tc.testCase.makeSysPossibleString()
			set, err = newCPUSetFromPossible([]byte(possible))
			if err != nil {
				t.Fatalf("Failed to make cpuSet: %v", err)
			}

			want = tc.testCase.physicalCores * tc.testCase.cores * tc.testCase.threadsPerCore
			got := len(set.getRemainingList())
			if got != want {
				t.Fatalf("Returned the wrong number of CPUs want: %d got: %d", want, got)
			}
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
	want := thread{
		processorNumber: 0,
		vendorID:        "GenuineIntel",
		cpuFamily:       6,
		model:           85,
		id: cpuID{
			physicalID: 0,
			coreID:     0,
		},
		bugs: map[string]struct{}{
			"cpu_meltdown":      struct{}{},
			"spectre_v1":        struct{}{},
			"spectre_v2":        struct{}{},
			"spec_store_bypass": struct{}{},
			"l1tf":              struct{}{},
			"mds":               struct{}{},
			"swapgs":            struct{}{},
			"taa":               struct{}{},
			"itlb_multihit":     struct{}{},
		},
	}

	got, err := newThread(data)
	if err != nil {
		t.Fatalf("getCpu failed with error: %v", err)
	}

	if !want.similarTo(got) {
		t.Fatalf("Failed cpus not similar: got: %+v, want: %+v", got, want)
	}

	if !got.isVulnerable() {
		t.Fatalf("Failed: cpu should be vulnerable.")
	}
}

func TestInvalid(t *testing.T) {
	result, err := getThreads(`something not a processor`)
	if err == nil {
		t.Fatalf("getCPU set didn't return an error: %+v", result)
	}

	if !strings.Contains(err.Error(), "no cpus") {
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
	cpuSet, err := getThreads(data)
	if err != nil {
		t.Fatalf("getCPUSet failed: %v", err)
	}

	wantCPULen := 2
	if len(cpuSet) != wantCPULen {
		t.Fatalf("Num CPU mismatch: want: %d, got: %d", wantCPULen, len(cpuSet))
	}

	wantCPU := thread{
		vendorID:  "GenuineIntel",
		cpuFamily: 6,
		model:     63,
		bugs: map[string]struct{}{
			"cpu_meltdown":      struct{}{},
			"spectre_v1":        struct{}{},
			"spectre_v2":        struct{}{},
			"spec_store_bypass": struct{}{},
			"l1tf":              struct{}{},
			"mds":               struct{}{},
			"swapgs":            struct{}{},
		},
	}

	for _, c := range cpuSet {
		if !wantCPU.similarTo(c) {
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

	vulnerable := func(t thread) bool {
		return t.isVulnerable()
	}

	set, err := newCPUSet(data, vulnerable)
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

	const cascade = `processor       : 0
vendor_id       : GenuineIntel
cpu family      : 6
model           : 85
model name      : Intel(R) Xeon(R) CPU
stepping        : 7
microcode       : 0x1
cpu MHz         : 2800.198
cache size      : 33792 KB
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
flags           : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2
 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmu
lqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowpr
efetch invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid r
tm mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves a
rat avx512_vnni md_clear arch_capabilities
bugs            : spectre_v1 spectre_v2 spec_store_bypass mds swapgs taa
bogomips        : 5600.39
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
			set, err := getThreads(tc.cpuString)
			if err != nil {
				t.Fatalf("Failed to getCPUSet:%v\n %s", err, tc.cpuString)
			}

			if len(set) < 1 {
				t.Fatalf("Returned empty cpu set: %v", set)
			}

			for _, c := range set {
				got := func() bool {
					return c.isVulnerable()
				}()

				if got != tc.vulnerable {
					t.Fatalf("Mismatch vulnerable for cpu %+s: got %t want: %t", tc.name, tc.vulnerable, got)
				}
			}
		})
	}
}

func TestReverse(t *testing.T) {
	const noParse = "-1-"
	for _, tc := range []struct {
		name      string
		output    string
		wantErr   error
		wantCount int
	}{
		{
			name:      "base",
			output:    "0-7",
			wantErr:   nil,
			wantCount: 8,
		},
		{
			name:      "huge",
			output:    "0-111",
			wantErr:   nil,
			wantCount: 112,
		},
		{
			name:      "not zero",
			output:    "50-53",
			wantErr:   nil,
			wantCount: 4,
		},
		{
			name:      "small",
			output:    "0",
			wantErr:   nil,
			wantCount: 1,
		},
		{
			name:    "invalid order",
			output:  "10-6",
			wantErr: fmt.Errorf("invalid cpu bounds from possible: begin: %d end: %d", 10, 6),
		},
		{
			name:    "no parse",
			output:  noParse,
			wantErr: fmt.Errorf(`mismatch regex from /sys/devices/system/cpu/possible: %q`, noParse),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			threads, err := getThreadsFromPossible([]byte(tc.output))

			switch {
			case tc.wantErr == nil:
				if err != nil {
					t.Fatalf("Wanted nil err, got: %v", err)
				}
			case err == nil:
				t.Fatalf("Want error: %v got: %v", tc.wantErr, err)
			default:
				if tc.wantErr.Error() != err.Error() {
					t.Fatalf("Want error: %v got error: %v", tc.wantErr, err)
				}
			}

			if len(threads) != tc.wantCount {
				t.Fatalf("Want count: %d got: %d", tc.wantCount, len(threads))
			}
		})
	}
}

func TestReverseSmoke(t *testing.T) {
	data, err := ioutil.ReadFile(allPossibleCPUs)
	if err != nil {
		t.Fatalf("Failed to read from possible: %v", err)
	}
	threads, err := getThreadsFromPossible(data)
	if err != nil {
		t.Fatalf("Could not parse possible output: %v", err)
	}

	if len(threads) <= 0 {
		t.Fatalf("Didn't get any CPU cores: %d", len(threads))
	}
}
