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
	"os"
	"strconv"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
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

// BenchmarkNginxDocSize iterates over different sized payloads, testing how
// well the runtime handles sending different payload sizes.
func BenchmarkNginxDocSize(b *testing.B) {
	benchmarkNginxDocSize(b, true /* tmpfs */)
	benchmarkNginxDocSize(b, false /* tmpfs */)
}

// BenchmarkContinuousNginx runs specific benchmarks for continous jobs.
// The runtime under test is the sever serving a runc client.
func BenchmarkContinuousNginx(b *testing.B) {
	sizes := []string{"10Kb", "100Kb", "1Mb"}
	threads := []int{1, 25, 100, 1000}
	benchmarkNginxContinuous(b, threads, sizes)
}

// benchmarkNginxDocSize iterates through all doc sizes, running subbenchmarks
// for each size.
func benchmarkNginxDocSize(b *testing.B, tmpfs bool) {
	for size, filename := range nginxDocs {
		concurrency := []int{1, 25, 50, 100, 1000}
		for _, c := range concurrency {
			fsize := tools.Parameter{
				Name:  "filesize",
				Value: size,
			}

			threads := tools.Parameter{
				Name:  "concurrency",
				Value: strconv.Itoa(c),
			}

			fs := tools.Parameter{
				Name:  "filesystem",
				Value: "bind",
			}
			if tmpfs {
				fs.Value = "tmpfs"
			}
			name, err := tools.ParametersToName(fsize, threads, fs)
			if err != nil {
				b.Fatalf("Failed to parse parameters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    b.N,
					Concurrency: c,
					Doc:         filename,
				}
				runNginx(b, hey, tmpfs)
			})
		}
	}
}

// benchmarkNginxContinuous iterates through given sizes and concurrencies on a tmpfs mount.
func benchmarkNginxContinuous(b *testing.B, concurrency []int, sizes []string) {
	for _, size := range sizes {
		filename := nginxDocs[size]
		for _, c := range concurrency {
			fsize := tools.Parameter{
				Name:  "filesize",
				Value: size,
			}

			threads := tools.Parameter{
				Name:  "concurrency",
				Value: strconv.Itoa(c),
			}

			fs := tools.Parameter{
				Name:  "filesystem",
				Value: "tmpfs",
			}

			name, err := tools.ParametersToName(fsize, threads, fs)
			if err != nil {
				b.Fatalf("Failed to parse parameters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				hey := &tools.Hey{
					Requests:    b.N,
					Concurrency: c,
					Doc:         filename,
				}
				runNginx(b, hey, true /*tmpfs*/)
			})
		}
	}
}

// runNginx configures the static serving methods to run httpd.
func runNginx(b *testing.B, hey *tools.Hey, tmpfs bool) {
	// nginx runs on port 80.
	port := 80
	nginxRunOpts := dockerutil.RunOpts{
		Image: "benchmarks/nginx",
		Ports: []int{port},
	}

	nginxCmd := []string{"nginx", "-c", "/etc/nginx/nginx_gofer.conf"}
	if tmpfs {
		nginxCmd = []string{"sh", "-c", "mkdir -p /tmp/html && cp -a /local/* /tmp/html && nginx -c /etc/nginx/nginx.conf"}
	}

	// Command copies nginxDocs to tmpfs serving directory and runs nginx.
	runStaticServer(b, nginxRunOpts, nginxCmd, port, hey)
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
