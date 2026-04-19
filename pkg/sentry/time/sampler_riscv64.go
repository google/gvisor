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

//go:build riscv64
// +build riscv64

package time

/*
import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
)
*/

/*
// TODO: getCNTFRQ get RISCV counter-timer frequency
func getCNTFRQ() uint32 {
	buf := make([]byte, 4)

	file, err := ioutil.ReadFile("/proc/device-tree/cpus/timebase-frequency")
	if err != nil {
		fmt.Println("Failed to open file:", err)
		return 0
	}

	copy(buf, file)

	frequency := binary.LittleEndian.Uint32(buf)

	return frequency
}

// getDefaultArchOverheadCycles get default OverheadCycles based on
// ARM counter-timer frequency. Usually ARM counter-timer frequency
// is range from 1-50Mhz which is much less than that on x86, so we
// calibrate defaultOverheadCycles for ARM.
func getDefaultArchOverheadCycles() TSCValue {
	// estimated the clock frequency on x86 is 1Ghz.
	// 1Ghz divided by counter-timer frequency of ARM to get
	// frqRatio. defaultOverheadCycles of ARM equals to that on
	// x86 divided by frqRatio
	cntfrq := getCNTFRQ()
	frqRatio := 1000000000 / float64(cntfrq)
	overheadCycles := (1 * 1000) / frqRatio
	return TSCValue(overheadCycles)
}

// defaultOverheadTSC is the default estimated syscall overhead in TSC cycles.
// It is further refined as syscalls are made.
var defaultOverheadCycles = getDefaultArchOverheadCycles()

// maxOverheadCycles is the maximum allowed syscall overhead in TSC cycles.
var maxOverheadCycles = 100 * defaultOverheadCycles
*/

const (
	// defaultOverheadTSC is the default estimated syscall overhead in TSC cycles.
	// It is further refined as syscalls are made.
	defaultOverheadCycles = 1 * 1000

	// maxOverheadCycles is the maximum allowed syscall overhead in TSC cycles.
	maxOverheadCycles = 100 * defaultOverheadCycles
)
