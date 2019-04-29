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

// Package hostcpu provides utilities for working with CPU information provided
// by a host Linux kernel.
package hostcpu

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
	"unicode"
)

// GetCPU returns the caller's current CPU number, without using the Linux VDSO
// (which is not available to the sentry) or the getcpu(2) system call (which
// is relatively slow).
func GetCPU() uint32

// MaxPossibleCPU returns the highest possible CPU number, which is guaranteed
// not to change for the lifetime of the host kernel.
func MaxPossibleCPU() (uint32, error) {
	const path = "/sys/devices/system/cpu/possible"
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	str := string(data)
	// Linux: drivers/base/cpu.c:show_cpus_attr() =>
	// include/linux/cpumask.h:cpumask_print_to_pagebuf() =>
	// lib/bitmap.c:bitmap_print_to_pagebuf()
	i, err := maxValueInLinuxBitmap(str)
	if err != nil {
		return 0, fmt.Errorf("invalid %s (%q): %v", path, str, err)
	}
	return uint32(i), nil
}

// maxValueInLinuxBitmap returns the maximum value specified in str, which is a
// string emitted by Linux's lib/bitmap.c:bitmap_print_to_pagebuf(list=true).
func maxValueInLinuxBitmap(str string) (uint64, error) {
	str = strings.TrimSpace(str)
	// Find the last decimal number in str.
	idx := strings.LastIndexFunc(str, func(c rune) bool {
		return !unicode.IsDigit(c)
	})
	if idx != -1 {
		str = str[idx+1:]
	}
	i, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return 0, err
	}
	return i, nil
}
