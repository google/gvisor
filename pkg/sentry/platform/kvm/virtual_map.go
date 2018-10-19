// Copyright 2018 Google LLC
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

package kvm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"

	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type virtualRegion struct {
	region
	accessType usermem.AccessType
	shared     bool
	offset     uintptr
	filename   string
}

// mapsLine matches a single line from /proc/PID/maps.
var mapsLine = regexp.MustCompile("([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][sp]) ([0-9a-f]+) [0-9a-f]{2}:[0-9a-f]{2,} [0-9]+\\s+(.*)")

// excludeRegion returns true if these regions should be excluded from the
// physical map. Virtual regions need to be excluded if get_user_pages will
// fail on those addresses, preventing KVM from satisfying EPT faults.
//
// This includes the VVAR page because the VVAR page may be mapped as I/O
// memory. And the VDSO page is knocked out because the VVAR page is not even
// recorded in /proc/self/maps on older kernels; knocking out the VDSO page
// prevents code in the VDSO from accessing the VVAR address.
//
// This is called by the physical map functions, not applyVirtualRegions.
func excludeVirtualRegion(r virtualRegion) bool {
	return r.filename == "[vvar]" || r.filename == "[vdso]"
}

// applyVirtualRegions parses the process maps file.
//
// Unlike mappedRegions, these are not consistent over time.
func applyVirtualRegions(fn func(vr virtualRegion)) error {
	// Open /proc/self/maps.
	f, err := os.Open("/proc/self/maps")
	if err != nil {
		return err
	}
	defer f.Close()

	// Parse all entries.
	r := bufio.NewReader(f)
	for {
		b, err := r.ReadBytes('\n')
		if b != nil && len(b) > 0 {
			m := mapsLine.FindSubmatch(b)
			if m == nil {
				// This should not happen: kernel bug?
				return fmt.Errorf("badly formed line: %v", string(b))
			}
			start, err := strconv.ParseUint(string(m[1]), 16, 64)
			if err != nil {
				return fmt.Errorf("bad start address: %v", string(b))
			}
			end, err := strconv.ParseUint(string(m[2]), 16, 64)
			if err != nil {
				return fmt.Errorf("bad end address: %v", string(b))
			}
			read := m[3][0] == 'r'
			write := m[3][1] == 'w'
			execute := m[3][2] == 'x'
			shared := m[3][3] == 's'
			offset, err := strconv.ParseUint(string(m[4]), 16, 64)
			if err != nil {
				return fmt.Errorf("bad offset: %v", string(b))
			}
			fn(virtualRegion{
				region: region{
					virtual: uintptr(start),
					length:  uintptr(end - start),
				},
				accessType: usermem.AccessType{
					Read:    read,
					Write:   write,
					Execute: execute,
				},
				shared:   shared,
				offset:   uintptr(offset),
				filename: string(m[5]),
			})
		}
		if err != nil && err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}
