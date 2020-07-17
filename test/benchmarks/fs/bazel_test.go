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
package fs

import (
	"context"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// Note: CleanCache versions of this test require running with root permissions.
func BenchmarkABSL(b *testing.B) {
	// Get a machine from the Harness on which to run.
	machine, err := h.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	// Dimensions here are clean/dirty cache (do or don't drop caches)
	// and if the mount on which we are compiling is a tmpfs/bind mount.
	benchmarks := []struct {
		name       string
		clearCache bool // clearCache drops caches before running.
		tmpfs      bool // tmpfs will run compilation on a tmpfs.
	}{
		{name: "CleanCache", clearCache: true, tmpfs: false},
		{name: "DirtyCache", clearCache: false, tmpfs: false},
		{name: "CleanCacheTmpfs", clearCache: true, tmpfs: true},
		{name: "DirtyCacheTmpfs", clearCache: false, tmpfs: true},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Grab a container.
			ctx := context.Background()
			container := machine.GetContainer(ctx, b)
			defer container.CleanUp(ctx)

			workdir := "/abseil-cpp"

			// Start a container.
			if err := container.Spawn(ctx, dockerutil.RunOpts{
				Image: "benchmarks/absl",
			}, "sleep", "1000"); err != nil {
				b.Fatalf("run failed with: %v", err)
			}

			// If we are running on a tmpfs, copy to /tmp which is a tmpfs.
			if bm.tmpfs {
				if _, err := container.Exec(ctx, dockerutil.ExecOpts{},
					"cp", "-r", "/abseil-cpp", "/tmp/."); err != nil {
					b.Fatal("failed to copy directory: %v", err)
				}
				workdir = "/tmp" + workdir
			}

			// Drop Caches.
			if bm.clearCache {
				if out, err := machine.RunCommand("/bin/sh -c sync; echo 3 > /proc/sys/vm/drop_caches"); err != nil {
					b.Fatalf("failed to drop caches: %v %s", err, out)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got, err := container.Exec(ctx, dockerutil.ExecOpts{
					WorkDir: workdir,
				}, "bazel", "build", "-c", "opt", "absl/base/...")
				if err != nil {
					b.Fatalf("build failed with: %v", err)
				}
				b.StopTimer()

				want := "Build completed successfully"
				if !strings.Contains(got, want) {
					b.Fatalf("string %s not in: %s", want, got)
				}
				b.StartTimer()
			}
		})
	}
}
