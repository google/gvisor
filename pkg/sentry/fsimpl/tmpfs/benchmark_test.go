// Copyright 2019 The gVisor Authors.
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

package benchmark_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Differences from stat_benchmark:
//
//   - Syscall interception, CopyInPath, copyOutStat, and overlayfs overheads are
//     not included.
//
//   - *MountStat benchmarks use a tmpfs root mount and a tmpfs submount at /tmp.
//
// Non-MountStat benchmarks use a tmpfs root mount and no submounts.
// stat_benchmark uses a varying root mount, a tmpfs submount at /tmp, and a
// subdirectory /tmp/<top_dir> (assuming TEST_TMPDIR == "/tmp"). Thus
// stat_benchmark at depth 1 does a comparable amount of work to *MountStat
// benchmarks at depth 2, and non-MountStat benchmarks at depth 3.
var depths = []int{1, 2, 3, 8, 64, 100}

const (
	mountPointName = "tmp"
	filename       = "gvisor_test_temp_0_1557494568"
)

func BenchmarkTmpfsStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				b.Fatalf("VFS init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
				AllowUserMount: true,
			})
			mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{})
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mntns.DecRef(ctx)

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create nested directories with given depth.
			root := mntns.Root()
			root.IncRef()
			defer root.DecRef(ctx)
			vd := root
			vd.IncRef()
			for i := depth; i > 0; i-- {
				name := fmt.Sprintf("%d", i)
				pop := vfs.PathOperation{
					Root:  root,
					Start: vd,
					Path:  fspath.Parse(name),
				}
				if err := vfsObj.MkdirAt(ctx, creds, &pop, &vfs.MkdirOptions{
					Mode: 0755,
				}); err != nil {
					b.Fatalf("failed to create directory %q: %v", name, err)
				}
				nextVD, err := vfsObj.GetDentryAt(ctx, creds, &pop, &vfs.GetDentryOptions{})
				if err != nil {
					b.Fatalf("failed to walk to directory %q: %v", name, err)
				}
				vd.DecRef(ctx)
				vd = nextVD
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Create the file that will be stat'd.
			fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
				Root:               root,
				Start:              vd,
				Path:               fspath.Parse(filename),
				FollowFinalSymlink: true,
			}, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
				Mode:  0644,
			})
			vd.DecRef(ctx)
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			defer fd.DecRef(ctx)
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               root,
					Start:              root,
					Path:               fspath.Parse(filePath),
					FollowFinalSymlink: true,
				}, &vfs.StatOptions{})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
				// Sanity check.
				if stat.Mode&^linux.S_IFMT != 0644 {
					b.Fatalf("got wrong permissions (%0o)", stat.Mode)
				}
			}
			// Don't include deferred cleanup in benchmark time.
			b.StopTimer()
		})
	}
}

func BenchmarkTmpfsMountStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				b.Fatalf("VFS init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
				AllowUserMount: true,
			})
			mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{})
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mntns.DecRef(ctx)

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create the mount point.
			root := mntns.Root()
			root.IncRef()
			defer root.DecRef(ctx)
			pop := vfs.PathOperation{
				Root:  root,
				Start: root,
				Path:  fspath.Parse(mountPointName),
			}
			if err := vfsObj.MkdirAt(ctx, creds, &pop, &vfs.MkdirOptions{
				Mode: 0755,
			}); err != nil {
				b.Fatalf("failed to create mount point: %v", err)
			}
			// Save the mount point for later use.
			mountPoint, err := vfsObj.GetDentryAt(ctx, creds, &pop, &vfs.GetDentryOptions{})
			if err != nil {
				b.Fatalf("failed to walk to mount point: %v", err)
			}
			defer mountPoint.DecRef(ctx)
			// Create and mount the submount.
			if _, err := vfsObj.MountAt(ctx, creds, "", &pop, "tmpfs", &vfs.MountOptions{}); err != nil {
				b.Fatalf("failed to mount tmpfs submount: %v", err)
			}
			filePathBuilder.WriteString(mountPointName)
			filePathBuilder.WriteByte('/')

			// Create nested directories with given depth.
			vd, err := vfsObj.GetDentryAt(ctx, creds, &pop, &vfs.GetDentryOptions{})
			if err != nil {
				b.Fatalf("failed to walk to mount root: %v", err)
			}
			for i := depth; i > 0; i-- {
				name := fmt.Sprintf("%d", i)
				pop := vfs.PathOperation{
					Root:  root,
					Start: vd,
					Path:  fspath.Parse(name),
				}
				if err := vfsObj.MkdirAt(ctx, creds, &pop, &vfs.MkdirOptions{
					Mode: 0755,
				}); err != nil {
					b.Fatalf("failed to create directory %q: %v", name, err)
				}
				nextVD, err := vfsObj.GetDentryAt(ctx, creds, &pop, &vfs.GetDentryOptions{})
				if err != nil {
					b.Fatalf("failed to walk to directory %q: %v", name, err)
				}
				vd.DecRef(ctx)
				vd = nextVD
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Create the file that will be stat'd.
			fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
				Root:               root,
				Start:              vd,
				Path:               fspath.Parse(filename),
				FollowFinalSymlink: true,
			}, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
				Mode:  0644,
			})
			vd.DecRef(ctx)
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			fd.DecRef(ctx)
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               root,
					Start:              root,
					Path:               fspath.Parse(filePath),
					FollowFinalSymlink: true,
				}, &vfs.StatOptions{})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
				// Sanity check.
				if stat.Mode&^linux.S_IFMT != 0644 {
					b.Fatalf("got wrong permissions (%0o)", stat.Mode)
				}
			}
			// Don't include deferred cleanup in benchmark time.
			b.StopTimer()
		})
	}
}

func init() {
	// Turn off reference leak checking for a benchmarking.
	refs.SetLeakMode(refs.NoLeakChecking)
}
