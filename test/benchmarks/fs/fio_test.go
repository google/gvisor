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

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
)

// BenchmarkFio runs fio on the runtime under test. There are 4 basic test
// cases each run on a tmpfs mount and a bind mount. Fio requires root so that
// caches can be dropped.
func BenchmarkFio(b *testing.B) {
	testCases := []tools.Fio{
		tools.Fio{
			Test:      "write",
			Size:      b.N,
			BlockSize: 4,
			IODepth:   4,
		},
		tools.Fio{
			Test:      "write",
			Size:      b.N,
			BlockSize: 1024,
			IODepth:   4,
		},
		tools.Fio{
			Test:      "read",
			Size:      b.N,
			BlockSize: 4,
			IODepth:   4,
		},
		tools.Fio{
			Test:      "read",
			Size:      b.N,
			BlockSize: 1024,
			IODepth:   4,
		},
		tools.Fio{
			Test:      "randwrite",
			Size:      b.N,
			BlockSize: 4,
			IODepth:   4,
		},
		tools.Fio{
			Test:      "randread",
			Size:      b.N,
			BlockSize: 4,
			IODepth:   4,
		},
	}

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine with: %v", err)
	}
	defer machine.CleanUp()

	for _, fsType := range []mount.Type{mount.TypeBind, mount.TypeTmpfs} {
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
				Value: string(fsType),
			}
			name, err := tools.ParametersToName(operation, blockSize, filesystem)
			if err != nil {
				b.Fatalf("Failed to parser paramters: %v", err)
			}
			b.Run(name, func(b *testing.B) {
				ctx := context.Background()
				container := machine.GetContainer(ctx, b)
				defer container.CleanUp(ctx)

				// Directory and filename inside container where fio will read/write.
				outdir := "/data"
				outfile := filepath.Join(outdir, "test.txt")

				// Make the required mount and grab a cleanup for bind mounts
				// as they are backed by a temp directory (mktemp).
				mnt, mountCleanup, err := makeMount(machine, fsType, outdir)
				if err != nil {
					b.Fatalf("failed to make mount: %v", err)
				}
				defer mountCleanup()

				// Start the container with the mount.
				if err := container.Spawn(
					ctx,
					dockerutil.RunOpts{
						Image: "benchmarks/fio",
						Mounts: []mount.Mount{
							mnt,
						},
					},
					// Sleep on the order of b.N.
					"sleep", fmt.Sprintf("%d", 1000*b.N),
				); err != nil {
					b.Fatalf("failed to start fio container with: %v", err)
				}

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

				b.ResetTimer()
				b.StopTimer()

				for i := 0; i < b.N; i++ {
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
					b.SetBytes(1024 * 1024) // Bytes for go reporting (Size is in megabytes).
					tc.Report(b, data)
				}
			})
		}
	}
}

// makeMount makes a mount and cleanup based on the requested type. Bind
// and volume mounts are backed by a temp directory made with mktemp.
// tmpfs mounts require no such backing and are just made.
// It is up to the caller to call the returned cleanup.
func makeMount(machine harness.Machine, mountType mount.Type, target string) (mount.Mount, func(), error) {
	switch mountType {
	case mount.TypeVolume, mount.TypeBind:
		dir, err := machine.RunCommand("mktemp", "-d")
		if err != nil {
			return mount.Mount{}, func() {}, fmt.Errorf("failed to create tempdir: %v", err)
		}
		dir = strings.TrimSuffix(dir, "\n")

		out, err := machine.RunCommand("chmod", "777", dir)
		if err != nil {
			machine.RunCommand("rm", "-rf", dir)
			return mount.Mount{}, func() {}, fmt.Errorf("failed modify directory: %v %s", err, out)
		}
		return mount.Mount{
			Target: target,
			Source: dir,
			Type:   mount.TypeBind,
		}, func() { machine.RunCommand("rm", "-rf", dir) }, nil
	case mount.TypeTmpfs:
		return mount.Mount{
			Target: target,
			Type:   mount.TypeTmpfs,
		}, func() {}, nil
	default:
		return mount.Mount{}, func() {}, fmt.Errorf("illegal mount time not supported: %v", mountType)
	}
}

// TestMain is the main method for package fs.
func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
