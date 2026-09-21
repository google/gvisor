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
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

// testPlatforms must be provided by the BUILD rule, or all platforms are included.
var (
	testPlatforms = flag.String("test_platforms", os.Getenv("TEST_PLATFORMS"), "Platforms to test with.")
	runtimeName   = flag.String("runtime", "", "Runtime/platform name passed by Makefile benchmark-platforms.")
)

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Warning)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

// benchmarkConfigs returns configurations for testing across platforms (e.g. kvm, systrap),
// keyed by sub-benchmark name.
func benchmarkConfigs(b *testing.B) map[string]*config.Config {
	var ps []string
	if *runtimeName != "" {
		ps = []string{*runtimeName}
	} else if *testPlatforms == "" {
		ps = platform.List()
	} else {
		ps = strings.Split(*testPlatforms, ",")
	}
	ps = slices.DeleteFunc(ps, func(s string) bool {
		return s == "runc" || s == "ptrace"
	})
	if len(ps) == 0 {
		b.Skipf("no supported platforms to benchmark (runtime=%q, test_platforms=%q)", *runtimeName, *testPlatforms)
	}

	cs := make(map[string]*config.Config)
	// Non-overlay versions.
	for _, p := range ps {
		c := testutil.ConfigForBenchmark(b)
		c.Overlay2.Set("none")
		c.Platform = p
		cs[p] = c
	}

	// Overlay versions. These use "root:self", the runsc default.
	for _, p := range ps {
		c := testutil.ConfigForBenchmark(b)
		c.Overlay2.Set("root:self")
		c.Platform = p
		cs[p+"_overlay"] = c
	}
	return cs
}

// BenchmarkOCICreate benchmarks container creation.
func BenchmarkOCICreate(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					spec := testutil.NewSpecWithArgs("sleep", "100")
					_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
					if err != nil {
						b.Fatalf("SetupContainer: %v", err)
					}
					defer cleanup()
					args := Args{
						ID:        testutil.RandomContainerID(),
						Spec:      spec,
						BundleDir: bundleDir,
					}

					var cont *Container
					elapsed := testutil.Measure(b, func() {
						cont, err = New(conf, args)
					})
					samples = append(samples, elapsed)

					if err != nil {
						b.Fatalf("New: %v", err)
					}
					defer cont.Destroy()
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkOCIStart benchmarks starting a created container.
func BenchmarkOCIStart(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					spec := testutil.NewSpecWithArgs("sleep", "100")
					_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
					if err != nil {
						b.Fatalf("SetupContainer: %v", err)
					}
					defer cleanup()
					cont, err := New(conf, Args{
						ID:        testutil.RandomContainerID(),
						Spec:      spec,
						BundleDir: bundleDir,
					})
					if err != nil {
						b.Fatalf("New: %v", err)
					}
					defer cont.Destroy()

					elapsed := testutil.Measure(b, func() {
						err = cont.Start(conf)
					})
					samples = append(samples, elapsed)

					if err != nil {
						b.Fatalf("Start: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// startSleepingContainer creates and starts a container running "sleep 100",
// for benchmarks that measure operations on an already-running container. The
// returned function destroys the container and removes its files.
func startSleepingContainer(b *testing.B, conf *config.Config) (*Container, func()) {
	b.Helper()
	spec := testutil.NewSpecWithArgs("sleep", "100")
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		b.Fatalf("SetupContainer: %v", err)
	}
	cont, err := New(conf, Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		cleanup()
		b.Fatalf("New: %v", err)
	}
	if err := cont.Start(conf); err != nil {
		cont.Destroy()
		cleanup()
		b.Fatalf("Start: %v", err)
	}
	return cont, func() {
		cont.Destroy()
		cleanup()
	}
}

// BenchmarkOCIPause benchmarks pausing a running container.
func BenchmarkOCIPause(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			// Use a fresh container per iteration.
			for i := 0; i < b.N; i++ {
				func() {
					cont, cleanup := startSleepingContainer(b, conf)
					defer cleanup()

					var err error
					elapsed := testutil.Measure(b, func() {
						err = cont.Pause()
					})
					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Pause: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkOCIResume benchmarks resuming a paused container.
func BenchmarkOCIResume(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			// Use a fresh container per iteration.
			for i := 0; i < b.N; i++ {
				func() {
					cont, cleanup := startSleepingContainer(b, conf)
					defer cleanup()

					if err := cont.Pause(); err != nil {
						b.Fatalf("Pause: %v", err)
					}
					var err error
					elapsed := testutil.Measure(b, func() {
						err = cont.Resume()
					})
					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Resume: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkOCIKill benchmarks signaling a running container to terminate. It does not measure
// container teardown.
func BenchmarkOCIKill(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					cont, cleanup := startSleepingContainer(b, conf)
					defer cleanup()

					var err error
					elapsed := testutil.Measure(b, func() {
						err = cont.SignalContainer(unix.SIGKILL, false)
					})
					samples = append(samples, elapsed)

					if err != nil {
						b.Fatalf("SignalContainer: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkOCIDestroy benchmarks destroying an already-exited container.
func BenchmarkOCIDestroy(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					spec := testutil.NewSpecWithArgs("echo", "ready")
					_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
					if err != nil {
						b.Fatalf("SetupContainer: %v", err)
					}
					defer cleanup()
					cont, err := New(conf, Args{
						ID:        testutil.RandomContainerID(),
						Spec:      spec,
						BundleDir: bundleDir,
					})
					if err != nil {
						b.Fatalf("New: %v", err)
					}
					// Still call Destroy if we fail before testing it.
					defer func() {
						if cont != nil {
							cont.Destroy()
						}
					}()
					if err := cont.Start(conf); err != nil {
						b.Fatalf("Start: %v", err)
					}
					if _, err := cont.Wait(); err != nil {
						b.Fatalf("Wait: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						err = cont.Destroy()
					})
					samples = append(samples, elapsed)

					if err != nil {
						b.Fatalf("Destroy: %v", err)
					}
					cont = nil
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

const readyMsg = "ready"

// BenchmarkTimeToReady measures cold-start time until the application outputs
// "ready" over a pipe. It covers container creation, start, and reaching the point of
// producing output, but not exit or teardown.
func BenchmarkTimeToReady(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					r, w, err := os.Pipe()
					if err != nil {
						b.Fatalf("os.Pipe: %v", err)
					}
					defer r.Close()
					defer w.Close()
					spec := testutil.NewSpecWithArgs("echo", readyMsg)
					_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
					if err != nil {
						b.Fatalf("SetupContainer: %v", err)
					}
					defer cleanup()
					args := Args{
						ID:        testutil.RandomContainerID(),
						Spec:      spec,
						BundleDir: bundleDir,
						Attached:  true,
						PassFiles: map[int]*os.File{
							1: w, // redirect container's stdout to pipe writer
						},
					}
					buf := make([]byte, 1)
					var cont *Container
					defer func() {
						if cont != nil {
							cont.Destroy()
						}
					}()
					// Set deadline for reading from the pipe.
					if err := r.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						b.Fatalf("SetReadDeadline: %v", err)
					}
					elapsed := testutil.Measure(b, func() {
						if cont, err = New(conf, args); err != nil {
							return
						}
						w.Close() // Close parent's write end of pipe to avoid deadlock.
						if err = cont.Start(conf); err != nil {
							return
						}
						_, err = io.ReadFull(r, buf)
					})
					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("TimeToReady: %v", err)
					}
					// Not measured, but confirms the workload actually ran to
					// completion.
					ws, err := cont.Wait()
					if err != nil {
						b.Fatalf("Wait: %v", err)
					}
					if !ws.Exited() || ws.ExitStatus() != 0 {
						b.Fatalf("bad exit status: %v", ws)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkEndToEnd measures the complete container lifecycle: create, start,
// run to exit, and delete. It uses the same workload as BenchmarkTimeToReady,
// so the difference between the two is the cost of exiting and tearing down the
// container.
func BenchmarkEndToEnd(b *testing.B) {
	for platformName, conf := range benchmarkConfigs(b) {
		b.Run(platformName, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					spec := testutil.NewSpecWithArgs("echo", readyMsg)
					_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
					if err != nil {
						b.Fatalf("SetupContainer: %v", err)
					}
					defer cleanup()
					args := Args{
						ID:        testutil.RandomContainerID(),
						Spec:      spec,
						BundleDir: bundleDir,
					}
					var cont *Container
					defer func() {
						if cont != nil {
							cont.Destroy()
						}
					}()

					elapsed := testutil.Measure(b, func() {
						if cont, err = New(conf, args); err != nil {
							return
						}
						if err = cont.Start(conf); err != nil {
							return
						}
						ws, waitErr := cont.Wait()
						if waitErr != nil {
							err = waitErr
							return
						}
						if !ws.Exited() || ws.ExitStatus() != 0 {
							err = fmt.Errorf("bad exit status: %v", ws)
							return
						}
						if err = cont.Destroy(); err != nil {
							return
						}
						cont = nil
					})
					samples = append(samples, elapsed)

					if err != nil {
						b.Fatalf("EndToEnd: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}
