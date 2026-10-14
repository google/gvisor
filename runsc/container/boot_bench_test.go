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
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Raw sandbox boot benchmarks. Each boots a container that runs
// `test_app echo ready` on a minimal root filesystem and reports the boot
// durations recorded inside `runsc boot` (see boot.Times).

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

// platformConfig is a configuration to boot with, and the name of the sub-test
// that boots with it.
type platformConfig struct {
	name string
	conf *config.Config
}

// platformConfigs returns a configuration for every platform in
// --test_platforms (systrap by default), without and with a root overlay.
// Every configuration starts from the one that newConf returns.
func platformConfigs(tb testing.TB, newConf func() *config.Config) []platformConfig {
	tb.Helper()
	if err := testutil.ConfigureExePath(); err != nil {
		tb.Fatalf("ConfigureExePath: %v", err)
	}
	var ps []string
	for _, p := range strings.Split(*testPlatforms, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ps = append(ps, p)
		}
	}
	ps = slices.DeleteFunc(ps, func(s string) bool {
		return s == "runc" || s == "ptrace"
	})
	if len(ps) == 0 {
		tb.Skipf("no supported platforms (test_platforms=%q)", *testPlatforms)
	}

	var cs []platformConfig
	for _, p := range ps {
		c := newConf()
		c.Overlay2.Set("none")
		c.Platform = p
		cs = append(cs, platformConfig{name: p, conf: c})
	}

	// Overlay versions use "root:self", the runsc default.
	for _, p := range ps {
		c := newConf()
		c.Overlay2.Set("root:self")
		c.Platform = p
		cs = append(cs, platformConfig{name: p + "_overlay", conf: c})
	}
	slices.SortFunc(cs, func(a, b platformConfig) int {
		return cmp.Compare(a.name, b.name)
	})
	return cs
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

// readBootTimes reads out the boot times from the given JSON file.
func readBootTimes(path string) (boot.Times, error) {
	var times boot.Times
	data, err := os.ReadFile(path)
	if err != nil {
		return times, err
	}
	if err := json.Unmarshal(data, &times); err != nil {
		return times, fmt.Errorf("parsing boot times in %q: %w", path, err)
	}
	return times, nil
}

// bootMinimal boots the minimal container at root once with conf, runs it to
// completion, and returns the boot times that the sandbox measured.
func bootMinimal(tb testing.TB, conf config.Config, root string) boot.Times {
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
	if !ws.Exited() || ws.ExitStatus() != 0 {
		tb.Fatalf("bad exit status: %v", ws)
	}
	times, err := readBootTimes(conf.BootTimesLog)
	if err != nil {
		tb.Fatalf("readBootTimes: %v", err)
	}
	return times
}

// benchmarkBoot boots the minimal container b.N times for every platform
// configuration.
func benchmarkBoot(b *testing.B, metric func(boot.Times) time.Duration) {
	root := setupMinimalRootfs(b)
	for _, pc := range platformConfigs(b, func() *config.Config { return testutil.ConfigForBenchmark(b) }) {
		b.Run(pc.name, func(b *testing.B) {
			var samples []time.Duration
			var total time.Duration
			for i := 0; i < b.N; i++ {
				d := metric(bootMinimal(b, *pc.conf, root))
				samples = append(samples, d)
				total += d
			}
			// The benchmark timer can only time code in this process, but the
			// boot happens in the sandbox process, so report the times the
			// sandbox measured rather than using the benchmark timer.
			b.ReportMetric(float64(total.Nanoseconds())/float64(b.N), "ns/op")
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkSandboxBoot measures the total active boot time of `runsc boot`
// from process spawn until the kernel is started, excluding the wait for the
// start signal. This is inclusive of boot.New and Loader.Run times.
func BenchmarkSandboxBoot(b *testing.B) {
	benchmarkBoot(b, func(t boot.Times) time.Duration { return t.Boot })
}

// BenchmarkSandboxBootNew measures the duration of boot.New inside `runsc
// boot`.
func BenchmarkSandboxBootNew(b *testing.B) {
	benchmarkBoot(b, func(t boot.Times) time.Duration { return t.New })
}

// BenchmarkSandboxBootRun measures the duration of Loader.Run inside `runsc
// boot`.
func BenchmarkSandboxBootRun(b *testing.B) {
	benchmarkBoot(b, func(t boot.Times) time.Duration { return t.Run })
}
