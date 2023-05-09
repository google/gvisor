// Copyright 2021 The gVisor Authors.
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

package sandbox

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// totalSystemMemory extracts "MemTotal" from "/proc/meminfo".
func totalSystemMemory() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return parseTotalSystemMemory(f)
}

func parseTotalSystemMemory(r io.Reader) (uint64, error) {
	for scanner := bufio.NewScanner(r); scanner.Scan(); {
		line := scanner.Text()
		totalStr := strings.TrimPrefix(line, "MemTotal:")
		if len(totalStr) < len(line) {
			fields := strings.Fields(totalStr)
			if len(fields) == 0 || len(fields) > 2 {
				return 0, fmt.Errorf(`malformed "MemTotal": %q`, line)
			}
			totalStr = fields[0]
			unit := ""
			if len(fields) == 2 {
				unit = fields[1]
			}
			mem, err := strconv.ParseUint(totalStr, 10, 64)
			if err != nil {
				return 0, err
			}
			switch unit {
			case "":
				// do nothing.
			case "kB":
				memKb := mem
				mem = memKb * 1024
				if mem < memKb {
					return 0, fmt.Errorf(`"MemTotal" too large: %d`, memKb)
				}
			default:
				return 0, fmt.Errorf("unknown unit %q: %q", unit, line)
			}
			return mem, nil
		}
	}
	return 0, fmt.Errorf(`malformed "/proc/meminfo": "MemTotal" not found`)
}
