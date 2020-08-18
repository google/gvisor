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

package tools

import (
	"testing"
)

// TestMeminfo checks the Meminfo parser on sample output.
func TestMeminfo(t *testing.T) {
	sampleData := `
MemTotal:       16337408 kB
MemFree:         3742696 kB
MemAvailable:    9319948 kB
Buffers:         1433884 kB
Cached:          4607036 kB
SwapCached:        45284 kB
Active:          8288376 kB
Inactive:        2685928 kB
Active(anon):    4724912 kB
Inactive(anon):  1047940 kB
Active(file):    3563464 kB
Inactive(file):  1637988 kB
Unevictable:      326940 kB
Mlocked:              48 kB
SwapTotal:      33292284 kB
SwapFree:       32865736 kB
Dirty:               708 kB
Writeback:             0 kB
AnonPages:       4304204 kB
Mapped:           975424 kB
Shmem:            910292 kB
KReclaimable:     744532 kB
Slab:            1058448 kB
SReclaimable:     744532 kB
SUnreclaim:       313916 kB
KernelStack:       25188 kB
PageTables:        65300 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:    41460988 kB
Committed_AS:   22859492 kB
VmallocTotal:   34359738367 kB
VmallocUsed:       63088 kB
VmallocChunk:          0 kB
Percpu:             9248 kB
HardwareCorrupted:     0 kB
AnonHugePages:    786432 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:     5408532 kB
DirectMap2M:    11241472 kB
DirectMap1G:     1048576 kB
`
	want := 9319948.0
	got, err := parseMemAvailable(sampleData)
	if err != nil {
		t.Fatalf("parseMemAvailable failed: %v", err)
	}
	if got != want {
		t.Fatalf("parseMemAvailable got %f, want %f", got, want)
	}
}
