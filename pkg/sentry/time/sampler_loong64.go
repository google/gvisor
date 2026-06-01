// Copyright 2024 The gVisor Authors.
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

//go:build loong64
// +build loong64

package time

// LoongArch's stable counter (read via rdtime.d) ticks at a hardware-fixed
// frequency reported through CPUCFG #4 / #5. Reading those CSRs from
// userspace requires the LSC (and our cpuid package does not expose them
// yet), so we fall back to a conservative hard-coded estimate.
//
// On Loongson-3A5000 the stable counter runs at 100 MHz; on 3A6000 it is
// typically ~125-150 MHz. The exact value only affects the syscall
// overhead heuristic used by the calibrated clock, which is self-tuning
// over time, so an order-of-magnitude estimate is sufficient.
const loongStableCounterHz = 100 * 1000 * 1000

// getCNTFRQ returns the stable counter frequency.
func getCNTFRQ() TSCValue {
	return TSCValue(loongStableCounterHz)
}

// getDefaultArchOverheadCycles estimates the syscall overhead in counter
// cycles. Same formula as arm64: a 1µs reference at 1 GHz scales linearly
// to the actual counter frequency.
func getDefaultArchOverheadCycles() TSCValue {
	cntfrq := getCNTFRQ()
	frqRatio := 1000000000 / float64(cntfrq)
	overheadCycles := (1 * 1000) / frqRatio
	return TSCValue(overheadCycles)
}

// defaultOverheadCycles is the default estimated syscall overhead in
// counter cycles. It is further refined as syscalls are made.
var defaultOverheadCycles = getDefaultArchOverheadCycles()

// maxOverheadCycles is the maximum allowed syscall overhead.
var maxOverheadCycles = 100 * defaultOverheadCycles
