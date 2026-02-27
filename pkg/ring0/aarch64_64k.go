// Copyright 2019 The gVisor Authors.
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

//go:build arm64 && pagesize_64k

package ring0

// Page table layout constants for 64K page size.
//
// With 64K pages, we use a 3-level page table structure:
// - PGD (Page Global Directory)
// - PMD (Page Middle Directory)
// - PTE (Page Table Entry)
//
// Each page table has 8192 entries (64K / 8 bytes per entry).
// For 48-bit VA, PGD only uses 64 entries (6 bits), but we allocate full page.
const (
	_PGD_PGT_BASE = 0x10000
	_PGD_PGT_SIZE = 0x10000 // 64K for PGD page table
	// No PUD level in 64K page mode
	_PMD_PGT_BASE = 0x20000
	_PMD_PGT_SIZE = 0x40000 // 256K = 4 page tables for initial kernel mapping
	_PTE_PGT_BASE = 0x60000
	_PTE_PGT_SIZE = 0x10000 // 64K for PTE page table
)
