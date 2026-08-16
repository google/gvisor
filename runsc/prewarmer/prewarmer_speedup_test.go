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

package prewarmer_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// highestOpenFD returns the highest FD number currently open in this
// process.
func highestOpenFD(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("cannot list /proc/self/fd: %v", err)
	}
	highest := -1
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if fd > highest {
			highest = fd
		}
	}
	if highest == -1 {
		t.Fatalf("cannot determine highest open FD")
	}
	return highest
}

// timedRun runs argv[0] with the given arguments and returns its wall time.
func timedRun(t *testing.T, argv ...string) time.Duration {
	t.Helper()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v failed: %v", argv, err)
	}
	return time.Since(start)
}

func p50(durations []time.Duration) time.Duration {
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

// TestPrewarmerSpeedsUpFDTableExpansion verifies the assumptions about Linux
// kernel implementation details made in `prewarmer.c` which make it
// worthwhile.
// If this test fails, then either the Linux kernel or the Go runtime
// may have changed, and it is time to consider retiring `prewarmer.c`.
func TestPrewarmerSpeedsUpFDTableExpansion(t *testing.T) {
	prewarmer, err := testutil.FindFile("runsc/prewarmer/gvisor-sentry-prewarmer")
	if err != nil {
		t.Fatalf("cannot find gvisor-sentry-prewarmer binary: %v", err)
	}
	expander, err := testutil.FindFile("runsc/prewarmer/fdtable_expander")
	if err != nil {
		t.Fatalf("cannot find fdtable_expander binary: %v", err)
	}

	// The children we'll spawn inherit their FD table size from the test
	// process, so if we already have an FD table large enough, the prewarmer
	// will be a no-op. We cannot ask the kernel to shrink the FD table, so
	// all we can do is skip the test in such a case.
	if fd := highestOpenFD(t); fd >= 64 {
		t.Skipf("test process has FD %d open, so child processes inherit a pre-expanded FD table; this environment cannot exercise the expansion the prewarmer exists to avoid", fd)
	}

	// One untimed run with both binaries involved just to warm the page cache:
	timedRun(t, prewarmer, expander, "fdtable_expander")

	const runs = 32 // Number of runs to do.

	var alone, prewarmed []time.Duration
	for i := 0; i < runs; i++ {
		alone = append(alone, timedRun(t, expander))
	}
	for i := 0; i < runs; i++ {
		prewarmed = append(prewarmed, timedRun(t, prewarmer, expander, "fdtable_expander"))
	}

	p50Alone, p50Prewarmed := p50(alone), p50(prewarmed)
	t.Logf("fdtable_expander alone: p50 = %v over %d runs", p50Alone, runs)
	t.Logf("fdtable_expander with prewarmer: p50 = %v over %d runs", p50Prewarmed, runs)
	if p50Prewarmed >= p50Alone {
		t.Errorf("prewarming did not speed up FD table expansion: p50 with prewarmer (%v) >= p50 without (%v); either the kernel no longer stalls multi-threaded FD table expansion (and the prewarmer should be deleted), or the prewarmer is broken", p50Prewarmed, p50Alone)
	}
}

// remapLogRegexp matches the timing log line emitted by the Sentry when it
// remaps its stdio FDs to high FD numbers in `loader.go`.
// Used to parse the duration out of the logs.
var remapLogRegexp = regexp.MustCompile(`Remapped stdio FDs to \[\d+, \d+\] in (\S+)`)

// runscDo runs `runsc --rootless do /bin/true` with the given sidecar
// directory and returns the stdio remap duration parsed from the Sentry's
// logs (and the whole logs too).
func runscDo(t *testing.T, runsc, sidecarDir, rootDir string) (time.Duration, string, error) {
	t.Helper()
	cmd := exec.Command(runsc,
		"--rootless",
		"--network=none",
		"--root="+rootDir,
		"--debug-log=/dev/stderr",
		"do", "/bin/true")
	cmd.Env = append(os.Environ(), "GVISOR_SIDECAR_BINARIES_DIR="+sidecarDir)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return 0, output.String(), fmt.Errorf("runsc do failed: %w", err)
	}
	m := remapLogRegexp.FindStringSubmatch(output.String())
	if m == nil {
		return 0, output.String(), fmt.Errorf("no stdio remap timing line in runsc debug log")
	}
	d, err := time.ParseDuration(m[1])
	if err != nil {
		return 0, output.String(), fmt.Errorf("cannot parse stdio remap duration %q: %w", m[1], err)
	}
	return d, output.String(), nil
}

// TestPrewarmerSpeedsUpRealBoot verifies that the Linux kernel implementation
// details that the `prewarmer.c` program takes advantage of actually help
// with gVisor's startup latency in practice.
// It runs `runsc --rootless --network=none do /bin/true` and extracts the FD
// remap timing from the logs, and verifies that this is faster with the
// prewarmer in the startup path vs without the prewarmer.
func TestPrewarmerSpeedsUpRealBoot(t *testing.T) {
	runsc, err := testutil.FindFile("release/runsc")
	if err != nil {
		t.Fatalf("cannot find runsc binary in the release layout: %v", err)
	}
	releaseBinDir, err := testutil.FindFile("release/gvisor-bin")
	if err != nil {
		t.Fatalf("cannot find gvisor-bin directory in the release layout: %v", err)
	}

	// Create a writable symlink-based mirror of the gvisor-bin directory,
	// so that we can delete the prewarmer binary from it later.
	tmp := t.TempDir()
	sidecarDir := filepath.Join(tmp, "gvisor-bin")
	if err := os.Mkdir(sidecarDir, 0755); err != nil {
		t.Fatalf("cannot create sidecar directory: %v", err)
	}
	entries, err := os.ReadDir(releaseBinDir)
	if err != nil {
		t.Fatalf("cannot list %q: %v", releaseBinDir, err)
	}
	prewarmerCopy := ""
	for _, e := range entries {
		src := filepath.Join(releaseBinDir, e.Name())
		dst := filepath.Join(sidecarDir, e.Name())
		if err := os.Symlink(src, dst); err != nil {
			t.Fatalf("cannot symlink %q into sidecar directory: %v", src, err)
		}
		if e.Name() == "gvisor-sentry-prewarmer" {
			prewarmerCopy = dst
		}
	}
	if prewarmerCopy == "" {
		t.Fatalf("release gvisor-bin directory %q does not contain gvisor-sentry-prewarmer; the release is missing the prewarmer sidecar", releaseBinDir)
	}

	// One untimed boot to warm everything up; if this one cannot run at all,
	// that is the environment's limitation, not the prewarmer's.
	if _, output, err := runscDo(t, runsc, sidecarDir, filepath.Join(tmp, "root-prewarmed")); err != nil {
		t.Skipf("cannot run rootless sandboxes in this environment: %v; output:\n%s", err, output)
	}

	const runs = 8 // Number of runs to do per side.

	var prewarmed []time.Duration
	for i := 0; i < runs; i++ {
		d, output, err := runscDo(t, runsc, sidecarDir, filepath.Join(tmp, "root-prewarmed"))
		if err != nil {
			t.Fatalf("runsc do with the prewarmer failed: %v; output:\n%s", err, output)
		}
		prewarmed = append(prewarmed, d)
	}

	if err := os.Remove(prewarmerCopy); err != nil {
		t.Fatalf("cannot delete prewarmer from sidecar directory: %v", err)
	}

	var unprewarmed []time.Duration
	for i := 0; i < runs; i++ {
		d, output, err := runscDo(t, runsc, sidecarDir, filepath.Join(tmp, "root-unprewarmed"))
		if err != nil {
			t.Fatalf("runsc do without the prewarmer failed: %v; output:\n%s", err, output)
		}
		unprewarmed = append(unprewarmed, d)
	}

	p50Prewarmed, p50Unprewarmed := p50(prewarmed), p50(unprewarmed)
	t.Logf("stdio remap with prewarmer:    p50 = %v over %d boots", p50Prewarmed, runs)
	t.Logf("stdio remap without prewarmer: p50 = %v over %d boots", p50Unprewarmed, runs)
	if p50Prewarmed >= p50Unprewarmed {
		t.Errorf("prewarming did not speed up the Sentry's stdio remap: p50 with prewarmer (%v) >= p50 without (%v); either the kernel no longer stalls multi-threaded FD table expansion (and the prewarmer should be deleted), or the prewarmer is broken", p50Prewarmed, p50Unprewarmed)
	}
}
