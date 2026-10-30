// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// Benchmarks for the sandboxexec package. sandboxexec starts a detached
// sandbox running `sleep infinity` (New), runs commands inside it (Exec), and
// kills and deletes the sandbox when finished (Close). These benchmarks measure
// New, Exec, and Close individually, as well as a full New + Exec + Close
// cycle (EndToEnd).
//
// These benchmarks use the default sandboxexec options. sandboxexec does not
// expose the gVisor platform, so the sandbox always runs on the default runsc
// platform.

const readyMsg = "ready"

func TestMain(m *testing.M) {
	// Benchmark this build's runsc binary rather than one on PATH.
	path, err := testutil.FindRunsc()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FindRunsc: %v\n", err)
		os.Exit(1)
	}
	os.Setenv(sandbox.RunscPathEnvVar, path)
	os.Exit(m.Run())
}

// checkReady fails the benchmark unless res is a successful run of a command
// that printed readyMsg.
func checkReady(b *testing.B, res *sandbox.ExecResult, err error) {
	b.Helper()
	if err != nil {
		b.Fatalf("Exec: %v", err)
	}
	if res == nil {
		b.Fatal("Exec: returned nil result and nil error")
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, readyMsg) {
		b.Fatalf("Exec: exit code %d, stdout %q, stderr %q", res.ExitCode, res.Stdout, res.Stderr)
	}
}

// BenchmarkSandboxexecNew measures sandbox.New, which creates the OCI bundle
// and runs `runsc run --detach` until the sandbox is running.
func BenchmarkSandboxexecNew(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	b.ResetTimer()
	var samples []time.Duration
	for i := 0; i < b.N; i++ {
		var sb *sandbox.Sandbox
		var err error
		elapsed := testutil.Measure(b, func() {
			sb, err = sandbox.New(ctx)
		})
		if err != nil {
			b.Fatalf("New: %v", err)
		}
		samples = append(samples, elapsed)
		if err := sb.Close(ctx); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
	testutil.ReportPercentiles(b, samples)
}

// BenchmarkSandboxexecExec boots one sandbox and measures b.N calls to
// sandbox.Exec running `echo ready` inside that running sandbox (`runsc exec`).
func BenchmarkSandboxexecExec(b *testing.B) {
	ctx := context.Background()
	sb, err := sandbox.New(ctx)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			b.Errorf("Close: %v", err)
		}
	}()
	b.StopTimer()
	b.ResetTimer()
	var samples []time.Duration
	for i := 0; i < b.N; i++ {
		var res *sandbox.ExecResult
		elapsed := testutil.Measure(b, func() {
			res, err = sb.Exec(ctx, []string{"echo", readyMsg})
		})
		checkReady(b, res, err)
		samples = append(samples, elapsed)
	}
	testutil.ReportPercentiles(b, samples)
}

// BenchmarkSandboxexecClose measures sandbox.Close on a running sandbox.
func BenchmarkSandboxexecClose(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	b.ResetTimer()
	var samples []time.Duration
	for i := 0; i < b.N; i++ {
		sb, err := sandbox.New(ctx)
		if err != nil {
			b.Fatalf("New: %v", err)
		}
		elapsed := testutil.Measure(b, func() {
			err = sb.Close(ctx)
		})
		if err != nil {
			b.Fatalf("Close: %v", err)
		}
		samples = append(samples, elapsed)
	}
	testutil.ReportPercentiles(b, samples)
}

// BenchmarkSandboxexecEndToEnd measures a full command lifecycle.
func BenchmarkSandboxexecEndToEnd(b *testing.B) {
	ctx := context.Background()
	b.StopTimer()
	b.ResetTimer()
	var samples []time.Duration
	for i := 0; i < b.N; i++ {
		var res *sandbox.ExecResult
		var newErr, execErr, closeErr error
		elapsed := testutil.Measure(b, func() {
			var sb *sandbox.Sandbox
			if sb, newErr = sandbox.New(ctx); newErr != nil {
				return
			}
			res, execErr = sb.Exec(ctx, []string{"echo", readyMsg})
			closeErr = sb.Close(ctx)
		})
		if newErr != nil {
			b.Fatalf("New: %v", newErr)
		}
		checkReady(b, res, execErr)
		if closeErr != nil {
			b.Fatalf("Close: %v", closeErr)
		}
		samples = append(samples, elapsed)
	}
	testutil.ReportPercentiles(b, samples)
}
