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

// +build arm64

package cpuid

import (
	"io/ioutil"
	"unsafe"

	"gvisor.dev/gvisor/pkg/log"
)

// The auxiliary vector of a process on the Linux system can be read from /proc/self/auxv,
// and tags and values are stored as 8-bytes decimal key-value pairs on the 64-bit system.
//
// $ od -t d8 /proc/self/auxv
//  0000000                   33      140734615224320
//  0000020                   16           3219913727
//  0000040                    6                 4096
//  0000060                   17                  100
//  0000100                    3       94665627353152
//  0000120                    4                   56
//  0000140                    5                    9
//  0000160                    7      140425502162944
//  0000200                    8                    0
//  0000220                    9       94665627365760
//  0000240                   11                 1000
//  0000260                   12                 1000
//  0000300                   13                 1000
//  0000320                   14                 1000
//  0000340                   23                    0
//  0000360                   25      140734614619513
//  0000400                   26                    0
//  0000420                   31      140734614626284
//  0000440                   15      140734614619529
//  0000460                    0                    0
func initHwCap() {
	auxv, err := ioutil.ReadFile("/proc/self/auxv")
	if err != nil {
		log.Warningf("Could not read /proc/self/auxv: %v", err)
		return
	}

	l := len(auxv) / 16
	for i := 0; i < l; i++ {
		tag := *(*uint64)(unsafe.Pointer(&auxv[i*16]))
		val := *(*uint64)(unsafe.Pointer(&auxv[i*16+8]))
		if tag == _AT_HWCAP {
			hwCap = uint(val)
			break
		}
	}
}
