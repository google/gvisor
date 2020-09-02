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
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// see Dockerfile '//images/benchmarks/nginx'.
var nginxDocs = map[string]string{
	"notfound": "notfound",
	"1Kb":      "latin1k.txt",
	"10Kb":     "latin10k.txt",
	"100Kb":    "latin100k.txt",
	"1Mb":      "latin1024k.txt",
	"10Mb":     "latin10240k.txt",
}

// BenchmarkNginxConcurrency iterates the concurrency argument and tests
// how well the runtime under test handles requests in parallel.
func BenchmarkNginxConcurrency(b *testing.B) {
	concurrency := []int{1, 25, 100, 1000}
	for _, c := range concurrency {
		b.Run(fmt.Sprintf("%d", c), func(b *testing.B) {
			hey := &tools.Hey{
				Requests:    c * b.N,
				Concurrency: c,
				Doc:         nginxDocs["10kb"], // see Dockerfile '//images/benchmarks/nginx' and httpd_test.
			}
			runNginx(b, hey, false /* reverse */)
		})
	}
}

// BenchmarkNginxDocSize iterates over different sized payloads, testing how
// well the runtime handles sending different payload sizes.
func BenchmarkNginxDocSize(b *testing.B) {
	benchmarkHttpdDocSize(b, false /* reverse */)
}

// BenchmarkReverseNginxDocSize iterates over different sized payloads, testing
// how well the runtime handles receiving different payload sizes.
func BenchmarkReverseNginxDocSize(b *testing.B) {
	benchmarkHttpdDocSize(b, true /* reverse */)
}

// benchmarkNginxDocSize iterates through all doc sizes, running subbenchmarks
// for each size.
func benchmarkNginxDocSize(b *testing.B, reverse bool) {
	b.Helper()
	for name, filename := range nginxDocs {
		concurrency := []int{1, 25, 50, 100, 1000}
		for _, c := range concurrency {
			b.Run(fmt.Sprintf("%s_%d", name, c), func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    c * b.N,
					Concurrency: c,
					Doc:         filename,
				}
				runNginx(b, hey, reverse)
			})
		}
	}
}

// runNginx configures the static serving methods to run httpd.
func runNginx(b *testing.B, hey *tools.Hey, reverse bool) {
	// nginx runs on port 80.
	port := 80
	nginxRunOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
		Ports: []int{port},
	}

	// Command copies nginxDocs to tmpfs serving directory and runs nginx.
	nginxCmd := []string{"sh", "-c", "mkdir -p /tmp/html && cp -a /local/* /tmp/html && nginx"}
	runStaticServer(b, nginxRunOpts, nginxCmd, port, hey, reverse)
}
