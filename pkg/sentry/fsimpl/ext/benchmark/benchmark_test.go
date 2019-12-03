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

// These benchmarks emulate memfs benchmarks. Ext4 images must be created
// before this benchmark is run using the `make_deep_ext4.sh` script at
// /tmp/image-{depth}.ext4 for all the depths tested below.
package benchmark_test

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ext"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var depths = []int{1, 2, 3, 8, 64, 100}

const filename = "file.txt"

// setUp opens imagePath as an ext Filesystem and returns all necessary
// elements required to run tests. If error is nil, it also returns a tear
// down function which must be called after the test is run for clean up.
func setUp(b *testing.B, imagePath string) (context.Context, *vfs.VirtualFilesystem, *vfs.VirtualDentry, func(), error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ctx := contexttest.Context(b)
	creds := auth.CredentialsFromContext(ctx)

	// Create VFS.
	vfsObj := vfs.New()
	vfsObj.MustRegisterFilesystemType("extfs", ext.FilesystemType{})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, imagePath, "extfs", &vfs.GetFilesystemOptions{InternalData: int(f.Fd())})
	if err != nil {
		f.Close()
		return nil, nil, nil, nil, err
	}

	root := mntns.Root()

	tearDown := func() {
		root.DecRef()

		if err := f.Close(); err != nil {
			b.Fatalf("tearDown failed: %v", err)
		}
	}
	return ctx, vfsObj, &root, tearDown, nil
}

// mount mounts extfs at the path operation passed. Returns a tear down
// function which must be called after the test is run for clean up.
func mount(b *testing.B, imagePath string, vfsfs *vfs.VirtualFilesystem, pop *vfs.PathOperation) func() {
	b.Helper()

	f, err := os.Open(imagePath)
	if err != nil {
		b.Fatalf("could not open image at %s: %v", imagePath, err)
	}

	ctx := contexttest.Context(b)
	creds := auth.CredentialsFromContext(ctx)

	if err := vfsfs.MountAt(ctx, creds, imagePath, pop, "extfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: int(f.Fd()),
		},
	}); err != nil {
		b.Fatalf("failed to mount tmpfs submount: %v", err)
	}
	return func() {
		if err := f.Close(); err != nil {
			b.Fatalf("tearDown failed: %v", err)
		}
	}
}

// BenchmarkVFS2Ext4fsStat emulates BenchmarkVFS2MemfsStat.
func BenchmarkVFS2Ext4fsStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx, vfsfs, root, tearDown, err := setUp(b, fmt.Sprintf("/tmp/image-%d.ext4", depth))
			if err != nil {
				b.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			creds := auth.CredentialsFromContext(ctx)
			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')
			for i := 1; i <= depth; i++ {
				filePathBuilder.WriteString(fmt.Sprintf("%d", i))
				filePathBuilder.WriteByte('/')
			}
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsfs.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               *root,
					Start:              *root,
					Pathname:           filePath,
					FollowFinalSymlink: true,
				}, &vfs.StatOptions{})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
				// Sanity check.
				if stat.Size > 0 {
					b.Fatalf("got wrong file size (%d)", stat.Size)
				}
			}
		})
	}
}

// BenchmarkVFS2ExtfsMountStat emulates BenchmarkVFS2MemfsMountStat.
func BenchmarkVFS2ExtfsMountStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			// Create root extfs with depth 1 so we can mount extfs again at /1/.
			ctx, vfsfs, root, tearDown, err := setUp(b, fmt.Sprintf("/tmp/image-%d.ext4", 1))
			if err != nil {
				b.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			creds := auth.CredentialsFromContext(ctx)
			mountPointName := "/1/"
			pop := vfs.PathOperation{
				Root:     *root,
				Start:    *root,
				Pathname: mountPointName,
			}

			// Save the mount point for later use.
			mountPoint, err := vfsfs.GetDentryAt(ctx, creds, &pop, &vfs.GetDentryOptions{})
			if err != nil {
				b.Fatalf("failed to walk to mount point: %v", err)
			}
			defer mountPoint.DecRef()

			// Create extfs submount.
			mountTearDown := mount(b, fmt.Sprintf("/tmp/image-%d.ext4", depth), vfsfs, &pop)
			defer mountTearDown()

			var filePathBuilder strings.Builder
			filePathBuilder.WriteString(mountPointName)
			for i := 1; i <= depth; i++ {
				filePathBuilder.WriteString(fmt.Sprintf("%d", i))
				filePathBuilder.WriteByte('/')
			}
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsfs.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               *root,
					Start:              *root,
					Pathname:           filePath,
					FollowFinalSymlink: true,
				}, &vfs.StatOptions{})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
				// Sanity check. touch(1) always creates files of size 0 (empty).
				if stat.Size > 0 {
					b.Fatalf("got wrong file size (%d)", stat.Size)
				}
			}
		})
	}
}
