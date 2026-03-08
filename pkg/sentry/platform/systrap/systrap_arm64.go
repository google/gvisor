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

package systrap

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func stackPointer(r *arch.Registers) uintptr {
	return uintptr(r.Sp)
}

// configureSystrapAddressSpace overrides the default 48-bit address space
// parameters when the host uses a different VA width. On 48-bit VA hosts,
// this function is a no-op, preserving exact compatibility with the
// existing behavior.
//
// This function MUST be called during systrap initialization, before any
// Context64 is created.
func configureSystrapAddressSpace() {
	switch linux.TaskSize {
	case 1 << 39:
		// 39-bit VA (3-level page tables, 512 GB address space).
		//
		// Experience values derived from Linux kernel 5.x+ ARM64 Kconfig
		// and mmap implementation, scaled for a 512 GB address space.
		arch.ConfigureAddressSpace(arch.AddressSpaceConfig{
			// TASK_SIZE = 512 GB.
			MaxAddr64: hostarch.Addr(linux.TaskSize),

			// ARCH_MMAP_RND_BITS_MAX = 24 for ARM64_VA_BITS=39, 4K pages.
			// Source: arch/arm64/Kconfig.
			// maxMmapRand = (1 << 24) * PAGE_SIZE = 64 GB.
			MaxMmapRand64: hostarch.Addr((1 << 24) * hostarch.PageSize),

			// ARCH_MMAP_RND_BITS_MIN = 18 for 4K pages (VA-width independent).
			// Source: arch/arm64/Kconfig.
			// minMmapRand = (1 << 18) * PAGE_SIZE = 1 GB.
			MinMmapRand64: hostarch.Addr((1 << 18) * hostarch.PageSize),

			// ~68.8% of address space. Chosen to be higher than the
			// proportional 49.4% used in 48-bit because the 512 GB
			// space is small and stub/stack regions consume a larger
			// relative share.
			PreferredTopDownAllocMin: 0x5800000000, // 352 GB

			PreferredAllocationGap: 16 << 30, // 16 GB

			// PIE base = maxAddr / 6 * 5, matching gVisor's standard formula.
			PreferredPIELoadAddr: hostarch.Addr(linux.TaskSize / 6 * 5),
		})

	case 1 << 52:
		// 52-bit VA (5-level page tables, 4 PB address space).
		//
		// Critical notes:
		//
		// 1. PIE: Linux uses DEFAULT_MAP_WINDOW_64 (= 1<<48) rather than
		//    TASK_SIZE_64 (= 1<<52) for ELF_ET_DYN_BASE when
		//    CONFIG_ARM64_FORCE_52BIT is not set. Most processes do not
		//    need addresses above 48-bit; keeping PIE in the 48-bit
		//    window avoids compatibility issues with userspace code.
		//
		// 2. MMAP randomization: ARCH_MMAP_RND_BITS_MAX for 52-bit VA
		//    is 33 (same as 48-bit), NOT 37 as the formula would suggest.
		//    This is because mmap_rnd_bits is a global sysctl and the
		//    same process can mix 48-bit and 52-bit mmap calls.
		//    See: https://patchew.org/linux/20250403183638.3386628-1-korneld@google.com/
		//
		arch.ConfigureAddressSpace(arch.AddressSpaceConfig{
			// TASK_SIZE = 4 PB.
			MaxAddr64: hostarch.Addr(linux.TaskSize),

			// ARCH_MMAP_RND_BITS_MAX = 33, same as 48-bit.
			// see note 2 above.
			MaxMmapRand64: hostarch.Addr((1 << 33) * hostarch.PageSize),

			// ARCH_MMAP_RND_BITS_MIN = 18, same as all VA widths.
			MinMmapRand64: hostarch.Addr((1 << 18) * hostarch.PageSize),

			// Same ~49.4% ratio as 48-bit.
			PreferredTopDownAllocMin: 0x7e80000000000, // ~2024 TB

			PreferredAllocationGap: 128 << 30, // 128 GB

			// Use DEFAULT_MAP_WINDOW_64 (48-bit) for PIE, NOT TASK_SIZE.
			// This matches Linux kernel behavior for non-FORCE_52BIT.
			PreferredPIELoadAddr: hostarch.Addr(linux.TaskSize / 6 * 5),
		})

	default:
		// 48-bit VA (4-level page tables, 256 TB address space).
		// No override needed — the defaults in arch_arm64.go are
		// already the correct 48-bit values.
	}
}
