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

package tools

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

// Meminfo wraps measurements of MemAvailable using /proc/meminfo.
type Meminfo struct {
}

// MakeCmd returns a command for checking meminfo.
func (*Meminfo) MakeCmd() (string, []string) {
	return "cat", []string{"/proc/meminfo"}
}

// Report takes two reads of meminfo, parses them, and reports the difference
// divided by b.N.
func (*Meminfo) Report(b *testing.B, before, after string) {
	b.Helper()

	beforeVal, err := parseMemAvailable(before)
	if err != nil {
		b.Fatalf("could not parse before value %s: %v", before, err)
	}

	afterVal, err := parseMemAvailable(after)
	if err != nil {
		b.Fatalf("could not parse before value %s: %v", before, err)
	}
	val := 1024 * ((beforeVal - afterVal) / float64(b.N))
	ReportCustomMetric(b, val, "average_container_size" /*metric name*/, "bytes" /*units*/)
}

var memInfoRE = regexp.MustCompile(`MemAvailable:\s*(\d+)\skB\n`)

// parseMemAvailable grabs the MemAvailable number from /proc/meminfo.
func parseMemAvailable(data string) (float64, error) {
	match := memInfoRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("couldn't find MemAvailable in %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}
