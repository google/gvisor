# python3
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Machine mock files."""

MEMINFO = """\
MemTotal:        7652344 kB
MemFree:         7174724 kB
MemAvailable:    7152008 kB
Buffers:            7544 kB
Cached:           178856 kB
SwapCached:            0 kB
Active:           270928 kB
Inactive:          68436 kB
Active(anon):     153124 kB
Inactive(anon):      880 kB
Active(file):     117804 kB
Inactive(file):    67556 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:               900 kB
Writeback:             0 kB
AnonPages:        153000 kB
Mapped:           129120 kB
Shmem:              1044 kB
Slab:              60864 kB
SReclaimable:      22792 kB
SUnreclaim:        38072 kB
KernelStack:        2672 kB
PageTables:         5756 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     3826172 kB
Committed_AS:     663836 kB
VmallocTotal:   34359738367 kB
VmallocUsed:           0 kB
VmallocChunk:          0 kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
CmaTotal:              0 kB
CmaFree:               0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
DirectMap4k:       94196 kB
DirectMap2M:     4624384 kB
DirectMap1G:     3145728 kB
"""

CONTENTS = {
    "/proc/meminfo": MEMINFO,
}


def Readfile(path: str) -> str:
  """Reads a mock file.

  Args:
    path: The target path.

  Returns:
    Mocked file contents or None.
  """
  return CONTENTS.get(path, None)
