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
package fio_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkFio runs fio on the runtime under test. There are 4 basic test
// cases each run on a tmpfs mount and a bind mount. Fio requires root so that
// caches can be dropped.
func BenchmarkFio(b *testing.B) {
	testCases := []tools.Fio{
		{
			Test:      "write",
			BlockSize: 4,
			IODepth:   4,
		},
		{
			Test:      "write",
			BlockSize: 1024,
			IODepth:   4,
		},
		{
			Test:      "read",
			BlockSize: 4,
			IODepth:   4,
		},
		{
			Test:      "read",
			BlockSize: 1024,
			IODepth:   4,
		},
		{
			Test:      "randwrite",
			BlockSize: 4,
			IODepth:   4,
		},
		{
			Test:      "randread",
			BlockSize: 4,
			IODepth:   4,
		},
	}

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	for _, fsType := range []string{harness.BindFS, harness.TmpFS, harness.RootFS} {
		for _, tc := range testCases {
			operation := tools.Parameter{
				Name:  "operation",
				Value: tc.Test,
			}
			blockSize := tools.Parameter{
				Name:  "blockSize",
				Value: fmt.Sprintf("%dK", tc.BlockSize),
			}
			filesystem := tools.Parameter{
				Name:  "filesystem",
				Value: fsType,
			}
			name, err := tools.ParametersToName(operation, blockSize, filesystem)
			if err != nil {
				b.Fatalf("Failed to parser paramters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				b.StopTimer()
				tc.Size = b.N
				ctx := context.Background()
				container := machine.GetContainer(ctx, b)
				defer container.CleanUp(ctx)

				mnts, outdir, mountCleanup, err := harness.MakeMount(machine, fsType)
				if err != nil {
					b.Fatalf("failed to make mount: %v", err)
				}
				defer mountCleanup()

				// Start the container with the mount.
				if err := container.Spawn(
					ctx, dockerutil.RunOpts{
						Image:  "benchmarks/fio",
						Mounts: mnts,
					},
					// Sleep on the order of b.N.
					"sleep", fmt.Sprintf("%d", 1000*b.N),
				); err != nil {
					b.Fatalf("failed to start fio container with: %v", err)
				}

				// Directory and filename inside container where fio will read/write.
				outfile := filepath.Join(outdir, "test.txt")

				// For reads, we need a file to read so make one inside the container.
				if strings.Contains(tc.Test, "read") {
					fallocateCmd := fmt.Sprintf("fallocate -l %dK %s", tc.Size, outfile)
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
