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
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Redis is for the client 'redis-benchmark'.
type Redis struct {
	Operation string
}

// MakeCmd returns a redis-benchmark client command.
func (r *Redis) MakeCmd(ip net.IP, port int) []string {
	// There is no -t PING_BULK for redis-benchmark, so adjust the command in that case.
	// Note that "ping" will run both PING_INLINE and PING_BULK.
	if r.Operation == "PING_BULK" {
		return strings.Split(
			fmt.Sprintf("redis-benchmark --csv -t ping -h %s -p %d", ip, port), " ")
	}

	// runs redis-benchmark -t operation for 100K requests against server.
	return strings.Split(
		fmt.Sprintf("redis-benchmark --csv -t %s -h %s -p %d", r.Operation, ip, port), " ")
}

// Report parses output from redis-benchmark client and reports metrics.
func (r *Redis) Report(b *testing.B, output string) {
	b.Helper()
	result, err := r.parseOperation(output)
	if err != nil {
		b.Fatalf("parsing result %s failed with err: %v", output, err)
	}
	b.ReportMetric(result, r.Operation) // operations per second
}

// parseOperation grabs the metric operations per second from redis-benchmark output.
func (r *Redis) parseOperation(data string) (float64, error) {
	re := regexp.MustCompile(fmt.Sprintf(`"%s( .*)?","(\d*\.\d*)"`, r.Operation))
	match := re.FindStringSubmatch(data)
	if len(match) < 3 {
		return 0.0, fmt.Errorf("could not find %s in %s", r.Operation, data)
	}
	return strconv.ParseFloat(match[2], 64)
}
