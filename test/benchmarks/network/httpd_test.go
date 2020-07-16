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
package network

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// see Dockerfile '//images/benchmarks/httpd'.
var docs = map[string]string{
	"notfound": "notfound",
	"1Kb":      "latin1k.txt",
	"10Kb":     "latin10k.txt",
	"100Kb":    "latin100k.txt",
	"1000Kb":   "latin1000k.txt",
	"1Mb":      "latin1024k.txt",
	"10Mb":     "latin10240k.txt",
}

// BenchmarkHttpdConcurrency iterates the concurrency argument and tests
// how well the runtime under test handles requests in parallel.
func BenchmarkHttpdConcurrency(b *testing.B) {
	// Grab a machine for the client and server.
	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get client: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get server: %v", err)
	}
	defer serverMachine.CleanUp()

	// The test iterates over client concurrency, so set other parameters.
	requests := 1000
	concurrency := []int{1, 5, 10, 25}
	doc := docs["10Kb"]

	for _, c := range concurrency {
		b.Run(fmt.Sprintf("%dConcurrency", c), func(b *testing.B) {
			runHttpd(b, clientMachine, serverMachine, doc, requests, c)
		})
	}
}

// BenchmarkHttpdDocSize iterates over different sized payloads, testing how
// well the runtime handles different payload sizes.
func BenchmarkHttpdDocSize(b *testing.B) {
	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer clientMachine.CleanUp()

	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer serverMachine.CleanUp()

	requests := 1000
	concurrency := 1

	for name, filename := range docs {
		b.Run(name, func(b *testing.B) {
			runHttpd(b, clientMachine, serverMachine, filename, requests, concurrency)
		})
	}
}

// runHttpd runs a single test run.
func runHttpd(b *testing.B, clientMachine, serverMachine harness.Machine, doc string, requests, concurrency int) {
	b.Helper()

	// Grab a container from the server.
	ctx := context.Background()
	server := serverMachine.GetContainer(ctx, b)
	defer server.CleanUp(ctx)

	// Copy the docs to /tmp and serve from there.
	cmd := "mkdir -p /tmp/html; cp -r /local /tmp/html/.; apache2 -X"
	port := 80

	// Start the server.
	server.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/httpd",
		Ports: []int{port},
		Env: []string{
			// Standard environmental variables for httpd.
			"APACHE_RUN_DIR=/tmp",
			"APACHE_RUN_USER=nobody",
			"APACHE_RUN_GROUP=nogroup",
			"APACHE_LOG_DIR=/tmp",
			"APACHE_PID_FILE=/tmp/apache.pid",
		},
	}, "sh", "-c", cmd)

	ip, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to find server ip: %v", err)
	}

	servingPort, err := server.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to find server port %d: %v", port, err)
	}

	// Check the server is serving.
	harness.WaitUntilServing(ctx, clientMachine, ip, servingPort)

	// Grab a client.
	client := clientMachine.GetContainer(ctx, b)
	defer client.CleanUp(ctx)

	path := fmt.Sprintf("http://%s:%d/%s", ip, servingPort, doc)
	// See apachebench (ab) for flags.
	cmd = fmt.Sprintf("ab -n %d -c %d %s", requests, concurrency, path)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := client.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/ab",
		}, "sh", "-c", cmd)
		if err != nil {
			b.Fatalf("run failed with: %v", err)
		}

		b.StopTimer()

		// Parse and report custom metrics.
		transferRate, err := parseTransferRate(out)
		if err != nil {
			b.Logf("failed to parse transferrate: %v", err)
		}
		b.ReportMetric(transferRate*1024, "transfer_rate") // Convert from Kb/s to b/s.

		latency, err := parseLatency(out)
		if err != nil {
			b.Logf("failed to parse latency: %v", err)
		}
		b.ReportMetric(latency/1000, "mean_latency") // Convert from ms to s.

		reqPerSecond, err := parseRequestsPerSecond(out)
		if err != nil {
			b.Logf("failed to parse requests per second: %v", err)
		}
		b.ReportMetric(reqPerSecond, "requests_per_second")

		b.StartTimer()
	}
}

var transferRateRE = regexp.MustCompile(`Transfer rate:\s+(\d+\.?\d+?)\s+\[Kbytes/sec\]\s+received`)

// parseTransferRate parses transfer rate from apachebench output.
func parseTransferRate(data string) (float64, error) {
	match := transferRateRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var latencyRE = regexp.MustCompile(`Total:\s+\d+\s+(\d+)\s+(\d+\.?\d+?)\s+\d+\s+\d+\s`)

// parseLatency parses latency from apachebench output.
func parseLatency(data string) (float64, error) {
	match := latencyRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var requestsPerSecondRE = regexp.MustCompile(`Requests per second:\s+(\d+\.?\d+?)\s+`)

// parseRequestsPerSecond parses requests per second from apachebench output.
func parseRequestsPerSecond(data string) (float64, error) {
	match := requestsPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

// Sample output from apachebench.
const sampleData = `This is ApacheBench, Version 2.3 <$Revision: 1826891 $>
Copyright 1996 Adam Twiss, Zeus Technology Ltd, http://www.zeustech.net/
Licensed to The Apache Software Foundation, http://www.apache.org/

Benchmarking 10.10.10.10 (be patient).....done


Server Software:        Apache/2.4.38
Server Hostname:        10.10.10.10
Server Port:            80

Document Path:          /latin10k.txt
Document Length:        210 bytes

Concurrency Level:      1
Time taken for tests:   0.180 seconds
Complete requests:      100
Failed requests:        0
Non-2xx responses:      100
Total transferred:      38800 bytes
HTML transferred:       21000 bytes
Requests per second:    556.44 [#/sec] (mean)
Time per request:       1.797 [ms] (mean)
Time per request:       1.797 [ms] (mean, across all concurrent requests)
Transfer rate:          210.84 [Kbytes/sec] received

Connection Times (ms)
              min  mean[+/-sd] median   max
Connect:        0    0   0.2      0       2
Processing:     1    2   1.0      1       8
Waiting:        1    1   1.0      1       7
Total:          1    2   1.2      1      10

Percentage of the requests served within a certain time (ms)
  50%      1
  66%      2
  75%      2
  80%      2
  90%      2
  95%      3
  98%      7
  99%     10
 100%     10 (longest request)`

// TestParsers checks the parsers work.
func TestParsers(t *testing.T) {
	want := 210.84
	got, err := parseTransferRate(sampleData)
	if err != nil {
		t.Fatalf("failed to parse transfer rate with error: %v", err)
	} else if got != want {
		t.Fatalf("parseTransferRate got: %f, want: %f", got, want)
	}

	want = 2.0
	got, err = parseLatency(sampleData)
	if err != nil {
		t.Fatalf("failed to parse transfer rate with error: %v", err)
	} else if got != want {
		t.Fatalf("parseLatency got: %f, want: %f", got, want)
	}

	want = 556.44
	got, err = parseRequestsPerSecond(sampleData)
	if err != nil {
		t.Fatalf("failed to parse transfer rate with error: %v", err)
	} else if got != want {
		t.Fatalf("parseRequestsPerSecond got: %f, want: %f", got, want)
	}
}
