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
package bazel_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// Note: CleanCache versions of this test require running with root permissions.
func BenchmarkBuildABSL(b *testing.B) {
	runBuildBenchmark(b, "benchmarks/absl", "/abseil-cpp", "absl/base/...")
}

// Note: CleanCache versions of this test require running with root permissions.
// Note: This test takes on the order of 10m per permutation for runsc on kvm.
func BenchmarkBuildRunsc(b *testing.B) {
	runBuildBenchmark(b, "benchmarks/runsc", "/gvisor", "runsc:runsc")
}

func runBuildBenchmark(b *testing.B, image, workdir, target string) {
	b.Helper()
	// Get a machine from the Harness on which to run.
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	// Dimensions here are clean/dirty cache (do or don't drop caches)
	// and if the mount on which we are compiling is a tmpfs/bind mount.
	benchmarks := []struct {
		clearCache bool // clearCache drops caches before running.
		tmpfs      bool // tmpfs will run compilation on a tmpfs.
	}{
		{clearCache: true, tmpfs: false},
		{clearCache: false, tmpfs: false},
		{clearCache: true, tmpfs: true},
		{clearCache: false, tmpfs: true},
	}
	for _, bm := range benchmarks {
		pageCache := tools.Parameter{
			Name:  "page_cache",
			Value: "dirty",
		}
		if bm.clearCache {
			pageCache.Value = "clean"
		}

		filesystem := tools.Parameter{
			Name:  "filesystem",
			Value: "bind",
		}
		if bm.tmpfs {
			filesystem.Value = "tmpfs"
		}
		name, err := tools.ParametersToName(pageCache, filesystem)
		if err != nil {
			b.Fatalf("Failed to parse parameters: %v", err)
		}

		b.Run(name, func(b *testing.B) {
			// Grab a container.
			ctx := context.Background()
			container := machine.GetContainer(ctx, b)
			defer container.CleanUp(ctx)

			// Start a container and sleep.
			if err := container.Spawn(ctx, dockerutil.RunOpts{
				Image: image,
			}, "sleep", fmt.Sprintf("%d", 1000000)); err != nil {
				b.Fatalf("run failed with: %v", err)
			}

			// If we are running on a tmpfs, copy to /tmp which is a tmpfs.
			prefix := ""
			if bm.tmpfs {
				if out, err := container.Exec(ctx, dockerutil.ExecOpts{},
					"cp", "-r", workdir, "/tmp/."); err != nil {
					b.Fatalf("failed to copy directory: %v (%s)", err, out)
				}
				prefix = "/tmp"
			}

			b.ResetTimer()
			b.StopTimer()

			// Drop Caches and bazel clean should happen inside the loop as we may use
			// time options with b.N. (e.g. Run for an hour.)
			for i := 0; i < b.N; i++ {
				// Drop Caches for clear cache runs.
				if bm.clearCache {
					if err := harness.DropCaches(machine); err != nil {
						b.Skipf("failed to drop caches: %v. You probably need root.", err)
					}
				}

				b.StartTimer()
				got, err := container.Exec(ctx, dockerutil.ExecOpts{
					WorkDir: prefix + workdir,
				}, "bazel", "build", "-c", "opt", target)
				if err != nil {
					b.Fatalf("build failed with: %v", err)
				}
				b.StopTimer()

				want := "Build completed successfully"
				if !strings.Contains(got, want) {
					b.Fatalf("string %s not in: %s", want, got)
				}

				// Clean bazel in the case we are doing another run.
				if i < b.N-1 {
					if _, err = container.Exec(ctx, dockerutil.ExecOpts{
						WorkDir: prefix + workdir,
					}, "bazel", "clean"); err != nil {
						b.Fatalf("build failed with: %v", err)
					}
				}
			}
		})
	}
}

// TestMain is the main method for package fs.
func TestMain(m *testing.M) {
	harness.Init()
	harness.SetFixedBenchmarks()
	os.Exit(m.Run())
}
