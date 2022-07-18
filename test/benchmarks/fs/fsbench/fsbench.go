// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package fsbench provides utility functions for filesystem benchmarks.
package fsbench

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// FSBenchmark represents a set of work to perform within a container that is instrumented with
// different filesystem configurations.
type FSBenchmark struct {
	// Image is the Docker image to load.
	Image string
	// WorkDir is where the action takes place.
	// The commands below are run from a directory that has the same file as what the container image
	// has at this directory.
	WorkDir string
	// RunCmd is the command to run to execute the benchmark.
	RunCmd []string
	// WantOutput, if set, is verified to be a substring of the output of RunCmd.
	WantOutput string
	// CleanCmd, if set, is run to clean up between benchmarks.
	CleanCmd []string
	// Variants is a list of benchmarka variants to run.
	// If unset, the typical set is used.
	Variants []Variant
}

// Variant is a specific configuration for a benchmark.
// Dimensions here are clean/dirty cache (do or don't drop caches)
// and if the mount on which we are compiling is a tmpfs/bind mount.
type Variant struct {
	// clearCache drops caches before running.
	clearCache bool
	// fsType is the type of filesystem to use.
	fsType harness.FileSystemType
}

// TypicalVariants returns the typical full set of benchmark variants.
func TypicalVariants() []Variant {
	variants := make([]Variant, 0, 6)
	for _, filesys := range []harness.FileSystemType{harness.BindFS, harness.TmpFS, harness.RootFS} {
		variants = append(variants, Variant{
			clearCache: true,
			fsType:     filesys,
		})
		variants = append(variants, Variant{
			clearCache: false,
			fsType:     filesys,
		})
	}
	return variants
}

// RunWithDifferentFilesystems runs a
func RunWithDifferentFilesystems(ctx context.Context, b *testing.B, machine harness.Machine, bm FSBenchmark) {
	b.Helper()

	benchmarkVariants := bm.Variants
	if len(benchmarkVariants) == 0 {
		benchmarkVariants = TypicalVariants()
	}
	for _, variant := range benchmarkVariants {
		pageCache := tools.Parameter{
			Name:  "page_cache",
			Value: "dirty",
		}
		if variant.clearCache {
			pageCache.Value = "clean"
		}

		filesystem := tools.Parameter{
			Name:  "filesystem",
			Value: string(variant.fsType),
		}
		name, err := tools.ParametersToName(pageCache, filesystem)
		if err != nil {
			b.Fatalf("Failed to parse parameters: %v", err)
		}

		b.Run(name, func(b *testing.B) {
			// Grab a container.
			container := machine.GetContainer(ctx, b)
			cu := cleanup.Make(func() {
				container.CleanUp(ctx)
			})
			defer cu.Clean()
			mts, prefix, err := harness.MakeMount(machine, variant.fsType, &cu)
			if err != nil {
				b.Fatalf("Failed to make mount: %v", err)
			}

			runOpts := dockerutil.RunOpts{
				Image:  bm.Image,
				Mounts: mts,
			}

			// Start a container and sleep.
			if err := container.Spawn(ctx, runOpts, "sleep", "24h"); err != nil {
				b.Fatalf("run failed with: %v", err)
			}

			cpCmd := fmt.Sprintf("mkdir -p %s && cp -r %s %s/.", prefix, bm.WorkDir, prefix)
			if out, err := container.Exec(ctx, dockerutil.ExecOpts{},
				"/bin/sh", "-c", cpCmd); err != nil {
				b.Fatalf("failed to copy directory: %v (%s)", err, out)
			}

			b.ResetTimer()
			b.StopTimer()

			// Drop Caches and bazel clean should happen inside the loop as we may use
			// time options with b.N. (e.g. Run for an hour.)
			for i := 0; i < b.N; i++ {
				// Drop Caches for clear cache runs.
				if variant.clearCache {
					if err := harness.DropCaches(machine); err != nil {
						b.Skipf("failed to drop caches: %v. You probably need root.", err)
					}
				}

				b.StartTimer()
				got, err := container.Exec(ctx, dockerutil.ExecOpts{
					WorkDir: prefix + bm.WorkDir,
				}, bm.RunCmd...)
				if err != nil {
					b.Fatalf("Command %v failed with: %v logs: %s", bm.RunCmd, err, got)
				}
				b.StopTimer()

				if bm.WantOutput != "" && !strings.Contains(got, bm.WantOutput) {
					b.Fatalf("string %s not in: %s", bm.WantOutput, got)
				}

				// Clean the container in case we are doing another run.
				if i < b.N-1 && len(bm.CleanCmd) != 0 {
					if _, err = container.Exec(ctx, dockerutil.ExecOpts{
						WorkDir: prefix + bm.WorkDir,
					}, bm.CleanCmd...); err != nil {
						b.Fatalf("Cleanup command %v failed with: %v", bm.CleanCmd, err)
					}
				}
			}
		})
	}
}
