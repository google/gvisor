// Copyright 2026 The gVisor Authors.
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

package container

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Benchmarks for the runsc CLI. Unlike the benchmarks in
// lifecycle_bench_test.go, which prepare an OCI bundle ahead of time and call
// the container package in-process, these invoke the runsc binary as a child
// process and measure the time from process spawn until exit.

// BenchmarkRunscDo measures `runsc do echo ready`. It times starting the runsc
// CLI process, parsing flags, building the OCI spec and bundle directory,
// booting the sandbox, running `echo ready` to completion, and tearing the
// sandbox down.
//
// This benchmark only runs once per platform (without a separate `_overlay`
// variant) because `runsc do` always enables an in-memory overlay by default
// and ignores the `--overlay2` flag.
func BenchmarkRunscDo(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		if bc.Conf.Overlay2.Enabled() {
			continue
		}
		b.Run(bc.Name, func(b *testing.B) {
			args := append(bc.Conf.ToFlags(), "do", "--root=/", "--cwd=/", "echo", readyMsg)
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				cmd := exec.Command(specutils.ExePath, args...)
				var out bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &out
				var err error
				elapsed := testutil.Measure(b, func() {
					err = cmd.Run()
				})
				if err != nil || !strings.Contains(out.String(), readyMsg) {
					b.Fatalf("runsc do: %v\n%s", err, out.String())
				}
				samples = append(samples, elapsed)
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}
