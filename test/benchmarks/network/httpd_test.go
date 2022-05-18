// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package network

import (
	"os"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// see Dockerfile '//images/benchmarks/httpd'.
var httpdDocs = map[string]string{
	"notfound": "notfound",
	"1Kb":      "latin1k.txt",
	"10Kb":     "latin10k.txt",
	"100Kb":    "latin100k.txt",
	"1Mb":      "latin1024k.txt",
	"10Mb":     "latin10240k.txt",
}

// BenchmarkHttpd iterates over different sized payloads and concurrency, testing
// how well the runtime handles sending different payload sizes.
func BenchmarkHttpd(b *testing.B) {
	benchmarkHttpdDocSize(b)
}

// BenchmarkContinuousHttpd runs specific benchmarks for continous jobs.
// The runtime under test is the server serving a runc client.
func BenchmarkContinuousHttpd(b *testing.B) {
	sizes := []string{"10Kb", "100Kb", "1Mb"}
	threads := []int{1, 25, 100, 1000}
	benchmarkHttpdContinuous(b, threads, sizes)
}

// benchmarkHttpdDocSize iterates through all doc sizes, running subbenchmarks
// for each size.
func benchmarkHttpdDocSize(b *testing.B) {
	b.Helper()
	for size, filename := range httpdDocs {
		concurrency := []int{1, 25, 50, 100, 1000}
		for _, c := range concurrency {
			fsize := tools.Parameter{
				Name:  "filesize",
				Value: size,
			}
			concurrency := tools.Parameter{
				Name:  "concurrency",
				Value: strconv.Itoa(c),
			}
			name, err := tools.ParametersToName(fsize, concurrency)
			if err != nil {
				b.Fatalf("Failed to parse parameters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    b.N,
					Concurrency: c,
					Doc:         filename,
				}
				runHttpd(b, hey)
			})
		}
	}
}

// benchmarkHttpdContinuous iterates through given sizes and concurrencies.
func benchmarkHttpdContinuous(b *testing.B, concurrency []int, sizes []string) {
	for _, size := range sizes {
		filename := httpdDocs[size]
		for _, c := range concurrency {
			fsize := tools.Parameter{
				Name:  "filesize",
				Value: size,
			}

			threads := tools.Parameter{
				Name:  "concurrency",
				Value: strconv.Itoa(c),
			}

			name, err := tools.ParametersToName(fsize, threads)
			if err != nil {
				b.Fatalf("Failed to parse parameters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    b.N,
					Concurrency: c,
					Doc:         filename,
				}
				runHttpd(b, hey)
			})
		}
	}
}

// runHttpd configures the static serving methods to run httpd.
func runHttpd(b *testing.B, hey *tools.Hey) {
	// httpd runs on port 80.
	port := 80
	httpdRunOpts := dockerutil.RunOpts{
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
	}
	httpdCmd := []string{"sh", "-c", "mkdir -p /tmp/html; cp -r /local/* /tmp/html/.; apache2 -X"}
	runStaticServer(b, httpdRunOpts, httpdCmd, port, hey)
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
