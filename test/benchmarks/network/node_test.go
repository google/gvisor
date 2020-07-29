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
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// BenchmarkNode runs 10K requests using 'hey' against a Node server run on
// 'runtime'. The server responds to requests by grabbing some data in a
// redis instance and returns the data in its reponse. The test loops through
// increasing amounts of concurency for requests.
func BenchmarkNode(b *testing.B) {
	requests := 10000
	concurrency := []int{1, 5, 10, 25}

	for _, c := range concurrency {
		b.Run(fmt.Sprintf("Concurrency%d", c), func(b *testing.B) {
			runNode(b, requests, c)
		})
	}
}

// runNode runs the test for a given # of requests and concurrency.
func runNode(b *testing.B, requests, concurrency int) {
	b.Helper()

	// The machine to hold Redis and the Node Server.
	serverMachine, err := h.GetMachine()
	if err != nil {
		b.Fatal("failed to get machine with: %v", err)
	}
	defer serverMachine.CleanUp()

	// The machine to run 'hey'.
	clientMachine, err := h.GetMachine()
	if err != nil {
		b.Fatal("failed to get machine with: %v", err)
	}
	defer clientMachine.CleanUp()

	ctx := context.Background()

	// Spawn a redis instance for the app to use.
	redis := serverMachine.GetNativeContainer(ctx, b)
	if err := redis.Spawn(ctx, dockerutil.RunOpts{
		Image: "benchmarks/redis",
	}); err != nil {
		b.Fatalf("failed to spwan redis instance: %v", err)
	}
	defer redis.CleanUp(ctx)

	if out, err := redis.WaitForOutput(ctx, "Ready to accept connections", 3*time.Second); err != nil {
		b.Fatalf("failed to start redis server: %v %s", err, out)
	}
	redisIP, err := redis.FindIP(ctx)
	if err != nil {
		b.Fatalf("failed to get IP from redis instance: %v", err)
	}

	// Node runs on port 8080.
	port := 8080

	// Start-up the Node server.
	nodeApp := serverMachine.GetContainer(ctx, b)
	if err := nodeApp.Spawn(ctx, dockerutil.RunOpts{
		Image:   "benchmarks/node",
		WorkDir: "/usr/src/app",
		Links:   []string{redis.MakeLink("redis")},
		Ports:   []int{port},
	}, "node", "index.js", redisIP.String()); err != nil {
		b.Fatalf("failed to spawn node instance: %v", err)
	}
	defer nodeApp.CleanUp(ctx)

	servingIP, err := serverMachine.IPAddress()
	if err != nil {
		b.Fatalf("failed to get ip from server: %v", err)
	}

	servingPort, err := nodeApp.FindPort(ctx, port)
	if err != nil {
		b.Fatalf("failed to port from node instance: %v", err)
	}

	// Wait until the Client sees the server as up.
	harness.WaitUntilServing(ctx, clientMachine, servingIP, servingPort)

	heyCmd := strings.Split(fmt.Sprintf("hey -n %d -c %d http://%s:%d/", requests, concurrency, servingIP, servingPort), " ")

	nodeApp.RestartProfiles()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// the client should run on Native.
		client := clientMachine.GetNativeContainer(ctx, b)
		out, err := client.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/hey",
		}, heyCmd...)
		if err != nil {
			b.Fatalf("hey container failed: %v logs: %s", err, out)
		}

		// Stop the timer to parse the data and report stats.
		b.StopTimer()
		requests, err := parseHeyRequestsPerSecond(out)
		if err != nil {
			b.Fatalf("failed to parse requests per second: %v", err)
		}
		b.ReportMetric(requests, "requests_per_second")

		bw, err := parseHeyBandwidth(out)
		if err != nil {
			b.Fatalf("failed to parse bandwidth: %v", err)
		}
		b.ReportMetric(bw, "bandwidth")

		ave, err := parseHeyAverageLatency(out)
		if err != nil {
			b.Fatalf("failed to parse average latency: %v", err)
		}
		b.ReportMetric(ave, "average_latency")
		b.StartTimer()
	}
}

var heyReqPerSecondRE = regexp.MustCompile(`Requests/sec:\s*(\d+\.?\d+?)\s+`)

// parseHeyRequestsPerSecond finds requests per second from hey output.
func parseHeyRequestsPerSecond(data string) (float64, error) {
	match := heyReqPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get bandwidth: %s", data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var heyAverageLatencyRE = regexp.MustCompile(`Average:\s*(\d+\.?\d+?)\s+secs`)

// parseHeyAverageLatency finds Average Latency in seconds form hey output.
func parseHeyAverageLatency(data string) (float64, error) {
	match := heyAverageLatencyRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get average latency match%d : %s", len(match), data)
	}
	return strconv.ParseFloat(match[1], 64)
}

var heySizePerRequestRE = regexp.MustCompile(`Size/request:\s*(\d+\.?\d+?)\s+bytes`)

// parseHeyBandwidth computes bandwidth from request/sec * bytes/request
// and reports in bytes/second.
func parseHeyBandwidth(data string) (float64, error) {
	match := heyReqPerSecondRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get requests per second: %s", data)
	}
	reqPerSecond, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %s to float", match[1])
	}

	match = heySizePerRequestRE.FindStringSubmatch(data)
	if len(match) < 2 {
		return 0, fmt.Errorf("failed get average latency: %s", data)
	}
	requestSize, err := strconv.ParseFloat(match[1], 64)
	return requestSize * reqPerSecond, err
}

// TestHeyParsers tests that the parsers work with sample output.
func TestHeyParsers(t *testing.T) {
	sampleData := `
	Summary:
          Total:	2.2391 secs
          Slowest:	1.6292 secs
          Fastest:	0.0066 secs
          Average:	0.5351 secs
          Requests/sec:	89.3202

          Total data:	841200 bytes
          Size/request:	4206 bytes

        Response time histogram:
          0.007 [1]	|
          0.169 [0]	|
          0.331 [149]	|■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
          0.493 [0]	|
          0.656 [0]	|
          0.818 [0]	|
          0.980 [0]	|
          1.142 [0]	|
          1.305 [0]	|
          1.467 [49]	|■■■■■■■■■■■■■
          1.629 [1]	|


        Latency distribution:
          10% in 0.2149 secs
          25% in 0.2449 secs
          50% in 0.2703 secs
          75% in 1.3315 secs
          90% in 1.4045 secs
          95% in 1.4232 secs
          99% in 1.4362 secs

        Details (average, fastest, slowest):
          DNS+dialup:	0.0002 secs, 0.0066 secs, 1.6292 secs
          DNS-lookup:	0.0000 secs, 0.0000 secs, 0.0000 secs
          req write:	0.0000 secs, 0.0000 secs, 0.0012 secs
          resp wait:	0.5225 secs, 0.0064 secs, 1.4346 secs
          resp read:	0.0122 secs, 0.0001 secs, 0.2006 secs

        Status code distribution:
          [200]	200 responses
	`
	want := 89.3202
	got, err := parseHeyRequestsPerSecond(sampleData)
	if err != nil {
		t.Fatalf("failed to parse request per second with: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	want = 89.3202 * 4206
	got, err = parseHeyBandwidth(sampleData)
	if err != nil {
		t.Fatalf("failed to parse bandwidth with: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

	want = 0.5351
	got, err = parseHeyAverageLatency(sampleData)
	if err != nil {
		t.Fatalf("failed to parse average latency with: %v", err)
	} else if got != want {
		t.Fatalf("got: %f, want: %f", got, want)
	}

}
