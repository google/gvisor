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

package maincli

import (
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/coverage"
)

const (
	maxprocsPkg            = "gvisor.dev/gvisor/runsc/cli/maxprocs"
	maxAllocBeforeMaxprocs = 16 << 10
	maxTotalInitAlloc      = 2 << 20
)

// TestMaxProcsInitOrder checks that package maxprocs initializes before GC or
// large init allocations, and that total init allocations fit within the scaled
// GOGC headroom.
func TestMaxProcsInitOrder(t *testing.T) {
	if coverage.Available() || testing.CoverMode() != "" || os.Getenv("GO_COVERAGE_FILE") != "" || os.Getenv("COVERAGE_DIR") != "" {
		t.Skip("coverage instrumentation injects coverdata init before maxprocs")
	}

	// GOMAXPROCS=192 pre-allocates ~3 MiB of runtime.p spans, near the ~3.8 MiB
	// initial GC trigger regardless of host CPUs.
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{
		"GOMAXPROCS=192",
		"GODEBUG=inittrace=1,gcpacertrace=1,gctrace=1",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v failed: %v, output:\n%s", cmd, err, out)
	}
	// Example: "init syscall @0.35 ms, 0.004 ms clock, 336 bytes, 5 allocs"
	allocatedBefore := 0
	seenMaxprocs := false
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "gc ") || strings.HasPrefix(line, "pacer: assist ratio=") {
			t.Fatalf("garbage collection started before %s completed init: %q\noutput:\n%s", maxprocsPkg, line, out)
		}
		pkg, n, ok := parseInitTraceBytes(t, line)
		if !ok {
			continue
		}
		allocatedBefore += n
		if allocatedBefore > maxAllocBeforeMaxprocs {
			t.Fatalf("package initialization allocated %d bytes through %s, want at most %d\noutput:\n%s", allocatedBefore, pkg, maxAllocBeforeMaxprocs, out)
		}
		if pkg == maxprocsPkg {
			seenMaxprocs = true
			break
		}
	}
	if !seenMaxprocs {
		t.Fatalf("no init trace for %s, output:\n%s", maxprocsPkg, out)
	}

	// Measure total init allocations across all packages without gcpacertrace
	// interleaving on stderr.
	cmd = exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = []string{"GODEBUG=inittrace=1"}
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v failed: %v, output:\n%s", cmd, err, out)
	}
	totalAllocated := 0
	for _, line := range strings.Split(string(out), "\n") {
		_, n, ok := parseInitTraceBytes(t, line)
		if !ok {
			continue
		}
		totalAllocated += n
	}
	if totalAllocated > maxTotalInitAlloc {
		t.Fatalf("total package initialization allocated %d bytes, want at most %d\noutput:\n%s", totalAllocated, maxTotalInitAlloc, out)
	}
}

func parseInitTraceBytes(t *testing.T, line string) (string, int, bool) {
	t.Helper()
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "init" {
		return "", 0, false
	}
	i := slices.Index(fields, "bytes,")
	if i < 1 {
		t.Fatalf("failed to parse init trace line %q", line)
	}
	n, err := strconv.Atoi(fields[i-1])
	if err != nil {
		t.Fatalf("failed to parse init trace line %q: %v", line, err)
	}
	return fields[1], n, true
}
