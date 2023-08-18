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
	"strconv"
	"strings"
	"testing"
)

// Redis is for the client 'redis-benchmark'.
type Redis struct {
	Operation string
}

// MakeCmd returns a redis-benchmark client command.
func (r *Redis) MakeCmd(host string, port, requests int) []string {
	// There is no -t PING_BULK for redis-benchmark, so adjust the command in that case.
	// Note that "ping" will run both PING_INLINE and PING_BULK.
	// runs redis-benchmark -t operation for 100K requests against server.
	return []string{
		"redis-benchmark",
		"--csv",
		"-t", r.Operation,
		"-h", host,
		"-p", fmt.Sprintf("%d", port),
		"-n", fmt.Sprintf("%d", requests),
	}
}

// Report parses output from redis-benchmark client and reports metrics.
func (r *Redis) Report(b *testing.B, output string) {
	b.Helper()
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		b.Fatalf("redis-benchmark failed to parse redis output: %s", output)
	}
	titleLine := lines[0]
	resultLine := ""
	for _, line := range lines[1:] {
		if strings.Contains(line, r.Operation) {
			resultLine = line
			break
		}
	}
	if len(resultLine) < 1 {
		b.Fatalf("redis-benchmark failed to find LRANGE_100 in redis output: %s", output)
	}

	titles := strings.Split(titleLine, ",")
	results := strings.Split(resultLine, ",")
	if len(titles) != len(results) {
		b.Fatalf("redis-benchmark failed to parse redis output: %s", output)
	}

	for i := range titles {
		title := strings.Trim(titles[i], "\"")
		if strings.Contains(title, "test") {
			continue
		}
		result, err := strconv.ParseFloat(strings.Trim(results[i], "\""), 64)
		if err != nil {
			b.Fatalf("redis-benchmark failed to parse redis output %v: %s", err, output)
		}
		ReportCustomMetric(b, result, r.Operation /*metric_name*/, title /*unit*/)
	}
}
