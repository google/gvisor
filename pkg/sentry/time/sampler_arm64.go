// Copyright 2018 The gVisor Authors.
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

package time

// getCNTFRQ get ARM counter-timer frequency
func getCNTFRQ() TSCValue

// getDefaultArchOverheadCycles get default OverheadCycles based on
// ARM counter-timer frequency. Usually ARM counter-timer frequency
// is range from 1-50Mhz which is much less than that on x86, so we
// calibrate defaultOverheadCycles for ARM.
func getDefaultArchOverheadCycles() TSCValue {
	// estimated the clock frequency on x86 is 1Ghz.
	// 1Ghz devided by counter-timer frequency of ARM to get
	// frqRatio. defaultOverheadCycles of ARM equals to that on
	// x86 devided by frqRatio
	cntfrq := getCNTFRQ()
	frqRatio := 1000000000 / cntfrq
	overheadCycles := (1 * 1000) / frqRatio
	return overheadCycles
}

// defaultOverheadTSC is the default estimated syscall overhead in TSC cycles.
// It is further refined as syscalls are made.
var defaultOverheadCycles = getDefaultArchOverheadCycles()

// maxOverheadCycles is the maximum allowed syscall overhead in TSC cycles.
var maxOverheadCycles = 100 * defaultOverheadCycles
