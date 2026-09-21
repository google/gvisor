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

package shim_test

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	typeurl "github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/shim/shimutils"
)

var (
	platforms   = flag.String("test_platforms", os.Getenv("TEST_PLATFORMS"), "Platforms to test with.")
	runtimeFlag = flag.String("runtime", "", "Runtime/platform name passed by Makefile benchmark-platforms.")
)

func TestMain(m *testing.M) {
	config.RegisterFlags(flag.CommandLine)
	log.SetLevel(log.Warning)
	if err := testutil.ConfigureExePath(); err != nil {
		panic(err.Error())
	}
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Process")
	if err := specutils.MaybeRunAsRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running as root: %v\n", err)
		os.Exit(123)
	}
	os.Exit(m.Run())
}

// benchmarkConfig holds a sub-benchmark name and its runtime configuration.
type benchmarkConfig struct {
	name string
	conf *config.Config
}

// benchmarkConfigs returns configurations for testing across platforms (defaults to systrap),
// sorted by sub-benchmark name.
func benchmarkConfigs(b *testing.B) []benchmarkConfig {
	var ps []string
	if *runtimeFlag != "" {
		ps = []string{*runtimeFlag}
	} else if *platforms == "" {
		ps = []string{"systrap"}
	} else {
		for _, p := range strings.Split(*platforms, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ps = append(ps, p)
			}
		}
	}
	slices.Sort(ps)
	ps = slices.Compact(ps)
	ps = slices.DeleteFunc(ps, func(s string) bool {
		return s == "runc" || s == "ptrace"
	})
	if len(ps) == 0 {
		b.Skipf("no supported platforms to benchmark (runtime=%q, test_platforms=%q)", *runtimeFlag, *platforms)
	}

	var cs []benchmarkConfig
	for _, p := range ps {
		c := testutil.ConfigForBenchmark(b)
		c.Overlay2.Set("none")
		c.Platform = p
		cs = append(cs, benchmarkConfig{name: p, conf: c})
	}
	for _, p := range ps {
		c := testutil.ConfigForBenchmark(b)
		c.Overlay2.Set("root:self")
		c.Platform = p
		cs = append(cs, benchmarkConfig{name: p + "_overlay", conf: c})
	}
	slices.SortFunc(cs, func(a, b benchmarkConfig) int {
		return cmp.Compare(a.name, b.name)
	})
	return cs
}

// newSandboxContainer creates and returns a newly configured sandbox container. It does not start
// or return an actual live container.
func newSandboxContainer(b *testing.B, containerd *shimutils.MockContainerd, args ...string) *shimutils.Container {
	b.Helper()
	spec := shimutils.NewSandboxSpecWithArgs(args...)
	c, err := shimutils.NewContainer(spec, containerd)
	if err != nil {
		containerd.Cleanup()
		b.Fatalf("NewContainer: %v", err)
	}
	return c
}

// startSleepingSandbox creates and starts a sandbox container running "sleep 100"
// for benchmarks that measure operations on an already-running sandbox. The returned cleanup
// function kills and deletes the sandbox and cleans up MockContainerd.
func startSleepingSandbox(b *testing.B, conf *config.Config) (*shimutils.MockContainerd, task.TaskService, string, func()) {
	b.Helper()
	containerd := shimutils.NewMockContainerdForBenchmark(b, conf)
	cu := cleanup.Make(containerd.Cleanup)
	defer cu.Clean()

	sandbox := newSandboxContainer(b, containerd, "sleep", "100")
	if err := containerd.StartShim(b, sandbox); err != nil {
		b.Fatalf("StartShim: %v", err)
	}
	shim := containerd.GetClient(b)
	ctx := b.Context()
	opts, err := containerd.GetRuntimeOptions()
	if err != nil {
		b.Fatalf("GetRuntimeOptions: %v", err)
	}
	if _, err := shim.Create(ctx, &task.CreateTaskRequest{
		ID:      sandbox.ID(),
		Bundle:  sandbox.Bundle(),
		Options: opts,
	}); err != nil {
		b.Fatalf("Create: %v", err)
	}
	if _, err := shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()}); err != nil {
		b.Fatalf("Start: %v", err)
	}
	cleanContainerd := cu.Release()
	cleanup := func() {
		defer cleanContainerd()
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = shim.Kill(cleanupCtx, &task.KillRequest{
			ID:     sandbox.ID(),
			Signal: uint32(unix.SIGKILL),
			All:    true,
		})
		if err := containerd.WaitForExit(cleanupCtx, sandbox.ID()); err != nil {
			b.Fatalf("WaitForExit: %v", err)
		}
		if _, err := shim.Delete(cleanupCtx, &task.DeleteRequest{ID: sandbox.ID()}); err != nil {
			b.Fatalf("Delete: %v", err)
		}
	}
	return containerd, shim, sandbox.ID(), cleanup
}

// BenchmarkShimStart benchmarks spawning the shim daemon process
// and establishing a TTRPC connection over its Unix domain socket.
func BenchmarkShimStart(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "sleep", "100")

					var err error
					elapsed := testutil.Measure(b, func() {
						err = containerd.StartShim(b, sandbox)
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("StartShim: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimCreate benchmarks the TTRPC CreateTaskRequest through the shim. This
// initializes the sandbox and starts the Sentry and Gofer processes; the guest application
// has not yet started.
func BenchmarkShimCreate(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "sleep", "100")
					if err := containerd.StartShim(b, sandbox); err != nil {
						b.Fatalf("StartShim: %v", err)
					}
					shim := containerd.GetClient(b)
					ctx := b.Context()
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}
					req := &task.CreateTaskRequest{
						ID:      sandbox.ID(),
						Bundle:  sandbox.Bundle(),
						Options: opts,
					}

					elapsed := testutil.Measure(b, func() {
						_, err = shim.Create(ctx, req)
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Create: %v", err)
					}
					cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					_, _ = shim.Kill(cleanupCtx, &task.KillRequest{ID: sandbox.ID(), Signal: uint32(unix.SIGKILL), All: true})
					if _, err := shim.Delete(cleanupCtx, &task.DeleteRequest{ID: sandbox.ID()}); err != nil {
						b.Fatalf("Delete: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimContainerStart benchmarks sending a Start request to an already-created sandbox
// container. This does not measure application execution time.
func BenchmarkShimContainerStart(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "sleep", "100")
					if err := containerd.StartShim(b, sandbox); err != nil {
						b.Fatalf("StartShim: %v", err)
					}
					shim := containerd.GetClient(b)
					ctx := b.Context()
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}
					if _, err := shim.Create(ctx, &task.CreateTaskRequest{
						ID:      sandbox.ID(),
						Bundle:  sandbox.Bundle(),
						Options: opts,
					}); err != nil {
						b.Fatalf("Create: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						_, err = shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Start: %v", err)
					}
					cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					_, _ = shim.Kill(cleanupCtx, &task.KillRequest{ID: sandbox.ID(), Signal: uint32(unix.SIGKILL), All: true})
					if err := containerd.WaitForExit(cleanupCtx, sandbox.ID()); err != nil {
						b.Fatalf("WaitForExit: %v", err)
					}
					if _, err := shim.Delete(cleanupCtx, &task.DeleteRequest{ID: sandbox.ID()}); err != nil {
						b.Fatalf("Delete: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimPause benchmarks pausing a running container via the shim.
func BenchmarkShimPause(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					_, shim, id, cleanup := startSleepingSandbox(b, bc.conf)
					defer cleanup()
					ctx := b.Context()

					var err error
					elapsed := testutil.Measure(b, func() {
						_, err = shim.Pause(ctx, &task.PauseRequest{ID: id})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Pause: %v", err)
					}
					_, _ = shim.Resume(ctx, &task.ResumeRequest{ID: id})
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimResume benchmarks resuming a paused container via the shim.
func BenchmarkShimResume(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					_, shim, id, cleanup := startSleepingSandbox(b, bc.conf)
					defer cleanup()
					ctx := b.Context()
					if _, err := shim.Pause(ctx, &task.PauseRequest{ID: id}); err != nil {
						b.Fatalf("Pause: %v", err)
					}

					var err error
					elapsed := testutil.Measure(b, func() {
						_, err = shim.Resume(ctx, &task.ResumeRequest{ID: id})
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

// BenchmarkShimKill benchmarks signaling a running container to terminate via
// the shim. Container exit and teardown happen outside the measured time.
func BenchmarkShimKill(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					_, shim, id, cleanup := startSleepingSandbox(b, bc.conf)
					defer cleanup()
					ctx := b.Context()

					var err error
					elapsed := testutil.Measure(b, func() {
						_, err = shim.Kill(ctx, &task.KillRequest{
							ID:     id,
							Signal: uint32(unix.SIGKILL),
							All:    true,
						})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Kill: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

const readyMsg = "ready"

// BenchmarkShimDelete benchmarks deleting an already-exited container via the shim.
func BenchmarkShimDelete(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "echo", readyMsg)
					if err := containerd.StartShim(b, sandbox); err != nil {
						b.Fatalf("StartShim: %v", err)
					}
					shim := containerd.GetClient(b)
					ctx := b.Context()
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}
					if _, err := shim.Create(ctx, &task.CreateTaskRequest{
						ID:      sandbox.ID(),
						Bundle:  sandbox.Bundle(),
						Options: opts,
					}); err != nil {
						b.Fatalf("Create: %v", err)
					}
					if _, err := shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()}); err != nil {
						b.Fatalf("Start: %v", err)
					}
					if err := containerd.WaitForExit(ctx, sandbox.ID()); err != nil {
						b.Fatalf("WaitForExit: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						_, err = shim.Delete(ctx, &task.DeleteRequest{ID: sandbox.ID()})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("Delete: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimTimeToReady measures start time through the shim until the
// application outputs "ready" over a named pipe. This measures (Create -> Start -> Read), through
// an already-started shim daemon.
func BenchmarkShimTimeToReady(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "echo", readyMsg)
					fifoDir, err := os.MkdirTemp("/tmp", "shim-fifo-")
					if err != nil {
						b.Fatalf("MkdirTemp: %v", err)
					}
					defer os.RemoveAll(fifoDir)
					fifoPath := filepath.Join(fifoDir, "stdout-"+sandbox.ID()+".fifo")
					if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
						b.Fatalf("Mkfifo: %v", err)
					}
					fifoFile, err := os.OpenFile(fifoPath, os.O_RDWR, 0)
					if err != nil {
						b.Fatalf("OpenFile fifo: %v", err)
					}
					defer fifoFile.Close()
					// Guard against infinite read blocking if the container never writes to pipe.
					if err := fifoFile.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
						b.Fatalf("SetReadDeadline: %v", err)
					}
					if err := containerd.StartShim(b, sandbox); err != nil {
						b.Fatalf("StartShim: %v", err)
					}
					shim := containerd.GetClient(b)
					ctx := b.Context()
					buf := make([]byte, 1)
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						if _, err = shim.Create(ctx, &task.CreateTaskRequest{
							ID:      sandbox.ID(),
							Bundle:  sandbox.Bundle(),
							Stdout:  fifoPath,
							Stderr:  "/dev/null",
							Options: opts,
						}); err != nil {
							return
						}
						if _, err = shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()}); err != nil {
							return
						}
						_, err = io.ReadFull(fifoFile, buf)
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("TimeToReady: %v", err)
					}
					cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
					defer cancel()
					if err := containerd.WaitForExit(cleanupCtx, sandbox.ID()); err != nil {
						b.Fatalf("WaitForExit: %v", err)
					}
					if _, err := shim.Delete(cleanupCtx, &task.DeleteRequest{ID: sandbox.ID()}); err != nil {
						b.Fatalf("Delete: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimEndToEnd measures complete container lifecycle (Create ->
// Start -> Exit -> Delete) through an already-started shim daemon. Does not
// include shim daemon spawn and shutdown time.
func BenchmarkShimEndToEnd(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "echo", readyMsg)
					if err := containerd.StartShim(b, sandbox); err != nil {
						b.Fatalf("StartShim: %v", err)
					}
					shim := containerd.GetClient(b)
					ctx := b.Context()
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						if _, err = shim.Create(ctx, &task.CreateTaskRequest{
							ID:      sandbox.ID(),
							Bundle:  sandbox.Bundle(),
							Options: opts,
						}); err != nil {
							return
						}
						if _, err = shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()}); err != nil {
							return
						}
						if err = containerd.WaitForExit(ctx, sandbox.ID()); err != nil {
							return
						}
						_, err = shim.Delete(ctx, &task.DeleteRequest{ID: sandbox.ID()})
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

// BenchmarkShimSubcontainerEndToEnd measures the complete lifecycle (Create ->
// Start -> Exit -> Delete) of a subcontainer joining an already-running
// sandbox via the same shim daemon. Because the Sentry and Gofer are already
// started, this isolates the shim and runsc CLI overhead for starting a
// workload container inside an existing pod.
func BenchmarkShimSubcontainerEndToEnd(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd, shim, sandboxID, cleanup := startSleepingSandbox(b, bc.conf)
					defer cleanup()
					subSpec := shimutils.NewContainerSpec(sandboxID, []string{"echo", readyMsg})
					subcontainer, err := shimutils.NewContainer(subSpec, containerd)
					if err != nil {
						b.Fatalf("NewContainer subcontainer: %v", err)
					}
					ctx := b.Context()
					sandboxState, err := shim.State(ctx, &task.StateRequest{ID: sandboxID})
					if err != nil {
						b.Fatalf("State: %v", err)
					}
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}

					var resp *task.CreateTaskResponse
					elapsed := testutil.Measure(b, func() {
						if resp, err = shim.Create(ctx, &task.CreateTaskRequest{
							ID:      subcontainer.ID(),
							Bundle:  subcontainer.Bundle(),
							Options: opts,
						}); err != nil {
							return
						}
						if _, err = shim.Start(ctx, &task.StartRequest{ID: subcontainer.ID()}); err != nil {
							return
						}
						if err = containerd.WaitForExit(ctx, subcontainer.ID()); err != nil {
							return
						}
						_, err = shim.Delete(ctx, &task.DeleteRequest{ID: subcontainer.ID()})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("SubcontainerEndToEnd: %v", err)
					}
					if resp.Pid != sandboxState.Pid {
						b.Fatalf("subcontainer joined wrong sandbox: got PID %d, want sandbox PID %d", resp.Pid, sandboxState.Pid)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}

// BenchmarkShimEndToEndCold measures complete container lifecycle including
// cold shim daemon spawn (StartShim -> Create -> Start -> Exit -> Delete).
func BenchmarkShimEndToEndCold(b *testing.B) {
	for _, bc := range benchmarkConfigs(b) {
		b.Run(bc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			var samples []time.Duration
			for i := 0; i < b.N; i++ {
				func() {
					containerd := shimutils.NewMockContainerdForBenchmark(b, bc.conf)
					defer containerd.Cleanup()
					sandbox := newSandboxContainer(b, containerd, "echo", readyMsg)
					ctx := b.Context()
					opts, err := containerd.GetRuntimeOptions()
					if err != nil {
						b.Fatalf("GetRuntimeOptions: %v", err)
					}

					elapsed := testutil.Measure(b, func() {
						if err = containerd.StartShim(b, sandbox); err != nil {
							return
						}
						shim := containerd.GetClient(b)
						if _, err = shim.Create(ctx, &task.CreateTaskRequest{
							ID:      sandbox.ID(),
							Bundle:  sandbox.Bundle(),
							Options: opts,
						}); err != nil {
							return
						}
						if _, err = shim.Start(ctx, &task.StartRequest{ID: sandbox.ID()}); err != nil {
							return
						}
						if err = containerd.WaitForExit(ctx, sandbox.ID()); err != nil {
							return
						}
						_, err = shim.Delete(ctx, &task.DeleteRequest{ID: sandbox.ID()})
					})

					samples = append(samples, elapsed)
					if err != nil {
						b.Fatalf("EndToEndCold: %v", err)
					}
				}()
			}
			testutil.ReportPercentiles(b, samples)
		})
	}
}
