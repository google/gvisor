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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/timing"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Raw sandbox boot benchmarks. They boot containers that run
// `test_app echo ready` on a minimal root filesystem and report boot
// durations computed from the startup timeline that `runsc boot` exports.

const readyMsg = "ready"

// testPlatforms must be provided by the BUILD rule, or defaults to systrap.
var testPlatforms = flag.String("test_platforms", "systrap", "Platforms to test with.")

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Warning)
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

// bootConfigs returns the sandbox configurations for the platforms in
// --test_platforms (defaults to systrap), sorted by sub-test name.
func bootConfigs(tb testing.TB, newConf func() *config.Config) []testutil.PlatformConfig {
	tb.Helper()
	// ConfigureExePath reads the --runsc flag, which may not be parsed yet in
	// TestMain.
	if err := testutil.ConfigureExePath(); err != nil {
		tb.Fatalf("ConfigureExePath: %v", err)
	}
	return testutil.PlatformConfigs(tb, *testPlatforms, newConf)
}

// setupMinimalRootfs returns a minimal root filesystem: the statically linked
// test_app binary in /bin, and the mount points that the sandbox always
// mounts.
func setupMinimalRootfs(tb testing.TB) string {
	tb.Helper()
	app, err := testutil.FindFile("test/cmd/test_app/test_app")
	if err != nil {
		tb.Fatalf("FindFile: %v", err)
	}
	root := tb.TempDir()
	for _, dir := range []string{"bin", "dev", "proc", "sys"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
			tb.Fatalf("Mkdir: %v", err)
		}
	}
	if err := testutil.Copy(app, filepath.Join(root, "bin", "test_app")); err != nil {
		tb.Fatalf("Copy: %v", err)
	}
	return root
}

// minimalSpec returns the spec of a container that runs `test_app echo ready`
// on the minimal rootfs.
func minimalSpec(root string, conf *config.Config) *specs.Spec {
	spec := testutil.NewSpecWithArgs("/bin/test_app", "echo", readyMsg)
	spec.Root.Path = root
	// Make the root read-only if there is no overlay, otherwise its writeable.
	spec.Root.Readonly = conf.Overlay2.RootOverlayMedium() == config.NoOverlay
	// Test spec comes with pre-defined mounts that we don't want.
	spec.Mounts = nil
	return spec
}

// bootMinimal boots the minimal container at root once with conf, runs it to
// completion, and returns the startup timeline that the sandbox exported.
func bootMinimal(tb testing.TB, conf config.Config, root string) *timing.ExportedTimeline {
	tb.Helper()
	spec := minimalSpec(root, &conf)
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, &conf)
	if err != nil {
		tb.Fatalf("SetupContainer: %v", err)
	}
	defer cleanup()
	conf.BootTimesLog = filepath.Join(bundleDir, "boot-times.json")
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		tb.Fatalf("os.Pipe: %v", err)
	}
	defer stdoutR.Close()
	defer stdoutW.Close()
	if err := stdoutR.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tb.Fatalf("SetReadDeadline: %v", err)
	}
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
		Attached:  true,
		PassFiles: map[int]*os.File{
			1: stdoutW, // redirect container's stdout to pipe writer
		},
	}

	cont, err := New(&conf, args)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	defer func() {
		if err := cont.Destroy(); err != nil {
			tb.Fatalf("Destroy: %v", err)
		}
	}()
	stdoutW.Close()
	if err := cont.Start(&conf); err != nil {
		tb.Fatalf("Start: %v", err)
	}
	if _, err := io.ReadFull(stdoutR, make([]byte, 1)); err != nil {
		tb.Fatalf("waiting for the container's output: %v", err)
	}
	ws, err := cont.Wait()
	if err != nil {
		tb.Fatalf("Wait: %v", err)
	}
	if ws.ExitStatus() != 0 {
		tb.Fatalf("bad exit status: %v", ws)
	}
	tl, err := timing.ReadExportedTimeline(conf.BootTimesLog)
	if err != nil {
		tb.Fatalf("ReadExportedTimeline: %v", err)
	}
	return tl
}

// activeBootTime returns the duration from process start until the kernel is
// started, excluding the wait for the start signal.
func activeBootTime(tl *timing.ExportedTimeline) (time.Duration, error) {
	beforeWait, err := tl.Reached("control server started")
	if err != nil {
		return 0, err
	}
	afterWait, err := tl.Reached("start signal received")
	if err != nil {
		return 0, err
	}
	started, err := tl.Reached("kernel started")
	if err != nil {
		return 0, err
	}
	return beforeWait.Sub(tl.Start) + started.Sub(afterWait), nil
}

// loaderNewTime returns the duration of boot.New.
func loaderNewTime(tl *timing.ExportedTimeline) (time.Duration, error) {
	start, err := tl.Reached("creating loader")
	if err != nil {
		return 0, err
	}
	end, err := tl.Reached("loader created")
	if err != nil {
		return 0, err
	}
	return end.Sub(start), nil
}

// loaderRunTime returns the duration of Loader.Run (start signal to kernel
// started).
func loaderRunTime(tl *timing.ExportedTimeline) (time.Duration, error) {
	start, err := tl.Reached("start signal received")
	if err != nil {
		return 0, err
	}
	end, err := tl.Reached("kernel started")
	if err != nil {
		return 0, err
	}
	return end.Sub(start), nil
}

// reportTimes extracts and reports metric durations from tls.
func reportTimes(b *testing.B, tls []*timing.ExportedTimeline, metric func(*timing.ExportedTimeline) (time.Duration, error)) {
	b.Helper()
	if len(tls) == 0 {
		b.Fatal("no startup timelines: the Boot sub-benchmark did not run")
	}
	samples := make([]time.Duration, 0, len(tls))
	var total time.Duration
	for _, tl := range tls {
		d, err := metric(tl)
		if err != nil {
			b.Fatal(err)
		}
		samples = append(samples, d)
		total += d
	}
	// Report the sandbox-measured durations instead of the local process runtime.
	b.ReportMetric(float64(total.Nanoseconds())/float64(len(tls)), "ns/op")
	testutil.ReportPercentiles(b, samples)
}

// BenchmarkSandboxBoot measures sandbox startup durations across platforms:
//
//   - Boot: Total active boot duration (process start to kernel start).
//   - New:  Loader creation (boot.New).
//   - Run:  Loader startup (Loader.Run).
//
// Containers are booted in the "Boot" sub-benchmark. "New" and "Run" reuse
// those startup timelines to measure individual phases of the same boots.
func BenchmarkSandboxBoot(b *testing.B) {
	root := setupMinimalRootfs(b)
	for _, bc := range bootConfigs(b, func() *config.Config { return testutil.ConfigForBenchmark(b) }) {
		b.Run(bc.Name, func(b *testing.B) {
			var timelines []*timing.ExportedTimeline
			b.Run("Boot", func(b *testing.B) {
				timelines = make([]*timing.ExportedTimeline, 0, b.N)
				for i := 0; i < b.N; i++ {
					timelines = append(timelines, bootMinimal(b, *bc.Conf, root))
				}
				reportTimes(b, timelines, activeBootTime)
			})
			b.Run("New", func(b *testing.B) {
				reportTimes(b, timelines, loaderNewTime)
			})
			b.Run("Run", func(b *testing.B) {
				reportTimes(b, timelines, loaderRunTime)
			})
		})
	}
}
