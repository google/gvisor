// Copyright 2020 The gVisor Authors.
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
package fio_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// Fio benchmarks run fio on the runtime under test. There are 4 basic test
// cases each run on a tmpfs mount and a bind mount. Fio requires root so that
// caches can be dropped.

// BenchmarkFioWrite runs write operation benchmark cases.
func BenchmarkFioWrite(b *testing.B) {
	testCases := []tools.Fio{
		{
			Test:        "write",
			IOEngine:    tools.EngineSync,
			BlockSizeKB: 4,
			IODepth:     1,
		},
		{
			Test:        "write",
			IOEngine:    tools.EngineSync,
			BlockSizeKB: 64,
			IODepth:     1,
		},
		{
			Test:        "write",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 1024,
			IODepth:     4,
		},
		{
			Test:        "write",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 4,
			IODepth:     4,
			Direct:      true,
		},
		{
			Test:        "write",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 64,
			IODepth:     4,
			Direct:      true,
		},
		{
			Test:        "write",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 1024,
			IODepth:     4,
			Direct:      true,
		},
	}
	doFioBenchmark(b, testCases)
}

// BenchmarkFioRead runs read operation test cases.
func BenchmarkFioRead(b *testing.B) {
	testCases := []tools.Fio{
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 4,
			IODepth:     4,
		},
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 64,
			IODepth:     4,
		},
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 1024,
			IODepth:     4,
		},
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 4,
			IODepth:     4,
			Direct:      true,
		},
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 64,
			IODepth:     4,
			Direct:      true,
		},
		{
			Test:        "read",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 1024,
			IODepth:     4,
			Direct:      true,
		},
	}
	doFioBenchmark(b, testCases)
}

// BenchmarkFioRandWrite runs randwrite test cases.
func BenchmarkFioRandWrite(b *testing.B) {
	testCases := []tools.Fio{
		{
			Test:        "randwrite",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 4,
			IODepth:     4,
		},
		{
			Test:        "randwrite",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 4,
			IODepth:     4,
			Direct:      true,
		},
	}
	doFioBenchmark(b, testCases)
}

// BenchmarkFioRandRead runs randread test cases.
func BenchmarkFioRandRead(b *testing.B) {
	testCases := []tools.Fio{
		{
			Test:        "randread",
			IOEngine:    tools.EngineLibAIO,
			BlockSizeKB: 4,
			IODepth:     4,
		},
		{
			Test:        "randread",
			IOEngine:    tools.EngineLibAIO,
			Jobs:        8,
			BlockSizeKB: 4,
			IODepth:     4,
			Direct:      true,
		},
	}
	doFioBenchmark(b, testCases)
}

func doFioBenchmark(b *testing.B, testCases []tools.Fio) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	for _, fsType := range []harness.FileSystemType{harness.BindFS, harness.TmpFS, harness.RootFS} {
		for _, tc := range testCases {
			filesystem := tools.Parameter{
				Name:  "filesystem",
				Value: string(fsType),
			}
			_, name := tc.Parameters(b, filesystem)
			b.Run(name, func(b *testing.B) {
				b.StopTimer()
				tc.SizeMB = b.N

				ctx := context.Background()
				container := machine.GetContainer(ctx, b)
				cu := cleanup.Make(func() {
					container.CleanUp(ctx)
				})
				defer cu.Clean()

				mnts, outdir, err := harness.MakeMount(machine, fsType, &cu)
				if err != nil {
					b.Fatalf("failed to make mount: %v", err)
				}

				runOpts := dockerutil.RunOpts{
					Image:  "benchmarks/fio",
					Mounts: mnts,
				}
				// Start the container with the mount.
				if err := container.Spawn(
					ctx, runOpts,
					// Sleep on the order of b.N.
					"sleep", fmt.Sprintf("%d", 1000*b.N),
				); err != nil {
					b.Fatalf("failed to start fio container with: %v", err)
				}

				if out, err := container.Exec(ctx, dockerutil.ExecOpts{},
					"mkdir", "-p", outdir); err != nil {
					b.Fatalf("failed to copy directory: %v (%s)", err, out)
				}

				if fsType == harness.FuseFS {
					container.CopyFiles(&runOpts, "/fusebin", "test/runner/fuse/fuse")
					_, err := container.ExecProcess(ctx, dockerutil.ExecOpts{
						Privileged: true,
					}, "/fusebin/fuse", "--dir="+outdir, "--debug=false")
					if err != nil {
						b.Fatalf("starting fuse server failed with: %v", err)
					}
				}

				// Directory and filename inside container where fio will read/write.
				outfile := filepath.Join(outdir, "test.txt")

				// For reads, we need a file to read so make one inside the container.
				if strings.Contains(tc.Test, "read") {
					fallocateCmd := fmt.Sprintf("fallocate -l %dM %s", tc.SizeMB, outfile)
					if out, err := container.Exec(ctx, dockerutil.ExecOpts{},
						strings.Split(fallocateCmd, " ")...); err != nil {
						b.Fatalf("failed to create readable file on mount: %v, %s", err, out)
					}
				}

				// Drop caches just before running.
				if err := harness.DropCaches(machine); err != nil {
					b.Skipf("failed to drop caches with %v. You probably need root.", err)
				}

				cmd := tc.MakeCmd(outfile)
				if err := harness.DropCaches(machine); err != nil {
					b.Fatalf("failed to drop caches: %v", err)
				}

				// Run fio.
				b.StartTimer()
				data, err := container.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
				if err != nil {
					b.Fatalf("failed to run cmd %v: %v", cmd, err)
				}
				b.StopTimer()
				tc.Report(b, data)
			})
		}
	}
}

// TestMain is the main method for package fs.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
