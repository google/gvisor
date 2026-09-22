// Copyright 2023 The gVisor Authors.
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

package linux

// TASK_SIZE on arm64 depends on the kernel's configured VA width rather than
// on the page size, so TaskSize probes for it at runtime. These three values
// correspond to 3-level, 4-level and 5-level paging with a 4K granule, and are
// also the values a 64K granule reaches for VA_BITS of 48 and 52.
//
// TODO(b/259222138): a 64K granule can additionally be configured with
// VA_BITS=42, which is missing here; on such a kernel the probe falls back to
// 1<<39, which is conservative but wastes address space. Adding it would also
// require arch.ConfigureAddressSpace to accept it.
//
// The array has to be sorted in decreasing order.
var feasibleTaskSizes = []uintptr{1 << 52, 1 << 48, 1 << 39}
