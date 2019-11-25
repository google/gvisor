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
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/memfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Differences from stat_benchmark:
//
// - Syscall interception, CopyInPath, copyOutStat, and overlayfs overheads are
// not included.
//
// - *MountStat benchmarks use a tmpfs root mount and a tmpfs submount at /tmp.
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

// This is copied from syscalls/linux/sys_file.go, with the dependency on
// kernel.Task stripped out.
func fileOpOn(ctx context.Context, mntns *fs.MountNamespace, root, wd *fs.Dirent, dirFD int32, path string, resolve bool, fn func(root *fs.Dirent, d *fs.Dirent) error) error {
	var (
		d   *fs.Dirent // The file.
		rel *fs.Dirent // The relative directory for search (if required.)
		err error
	)

	// Extract the working directory (maybe).
	if len(path) > 0 && path[0] == '/' {
		// Absolute path; rel can be nil.
	} else if dirFD == linux.AT_FDCWD {
		// Need to reference the working directory.
		rel = wd
	} else {
		// Need to extract the given FD.
		return syserror.EBADF
	}

	// Lookup the node.
	remainingTraversals := uint(linux.MaxSymlinkTraversals)
	if resolve {
		d, err = mntns.FindInode(ctx, root, rel, path, &remainingTraversals)
	} else {
		d, err = mntns.FindLink(ctx, root, rel, path, &remainingTraversals)
	}
	if err != nil {
		return err
	}

	err = fn(root, d)
	d.DecRef()
	return err
}

func BenchmarkVFS1TmpfsStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)

			// Create VFS.
			tmpfsFS, ok := fs.FindFilesystem("tmpfs")
			if !ok {
				b.Fatalf("failed to find tmpfs filesystem type")
			}
			rootInode, err := tmpfsFS.Mount(ctx, "tmpfs", fs.MountSourceFlags{}, "", nil)
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			mntns, err := fs.NewMountNamespace(ctx, rootInode)
			if err != nil {
				b.Fatalf("failed to create mount namespace: %v", err)
			}
			defer mntns.DecRef()

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create nested directories with given depth.
			root := mntns.Root()
			defer root.DecRef()
			d := root
			d.IncRef()
			defer d.DecRef()
			for i := depth; i > 0; i-- {
				name := fmt.Sprintf("%d", i)
				if err := d.Inode.CreateDirectory(ctx, d, name, fs.FilePermsFromMode(0755)); err != nil {
					b.Fatalf("failed to create directory %q: %v", name, err)
				}
				next, err := d.Walk(ctx, root, name)
				if err != nil {
					b.Fatalf("failed to walk to directory %q: %v", name, err)
				}
				d.DecRef()
				d = next
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Create the file that will be stat'd.
			file, err := d.Inode.Create(ctx, d, filename, fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0644))
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			file.DecRef()
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			dirPath := false
			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := fileOpOn(ctx, mntns, root, root, linux.AT_FDCWD, filePath, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent) error {
					if dirPath && !fs.IsDir(d.Inode.StableAttr) {
						return syserror.ENOTDIR
					}
					uattr, err := d.Inode.UnstableAttr(ctx)
					if err != nil {
						return err
					}
					// Sanity check.
					if uattr.Perms.User.Execute {
						b.Fatalf("got wrong permissions (%0o)", uattr.Perms.LinuxMode())
					}
					return nil
				})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
			}
			// Don't include deferred cleanup in benchmark time.
			b.StopTimer()
		})
	}
}

func BenchmarkVFS2MemfsStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.New()
			vfsObj.MustRegisterFilesystemType("memfs", memfs.FilesystemType{})
			mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "memfs", &vfs.NewFilesystemOptions{})
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mntns.DecRef(vfsObj)

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create nested directories with given depth.
			root := mntns.Root()
			defer root.DecRef()
			vd := root
			vd.IncRef()
			for i := depth; i > 0; i-- {
				name := fmt.Sprintf("%d", i)
				pop := vfs.PathOperation{
					Root:     root,
					Start:    vd,
					Pathname: name,
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
				vd.DecRef()
				vd = nextVD
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Create the file that will be stat'd.
			fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
				Root:               root,
				Start:              vd,
				Pathname:           filename,
				FollowFinalSymlink: true,
			}, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
				Mode:  0644,
			})
			vd.DecRef()
			vd = vfs.VirtualDentry{}
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			defer fd.DecRef()
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               root,
					Start:              root,
					Pathname:           filePath,
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

func BenchmarkVFS1TmpfsMountStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)

			// Create VFS.
			tmpfsFS, ok := fs.FindFilesystem("tmpfs")
			if !ok {
				b.Fatalf("failed to find tmpfs filesystem type")
			}
			rootInode, err := tmpfsFS.Mount(ctx, "tmpfs", fs.MountSourceFlags{}, "", nil)
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			mntns, err := fs.NewMountNamespace(ctx, rootInode)
			if err != nil {
				b.Fatalf("failed to create mount namespace: %v", err)
			}
			defer mntns.DecRef()

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create and mount the submount.
			root := mntns.Root()
			defer root.DecRef()
			if err := root.Inode.CreateDirectory(ctx, root, mountPointName, fs.FilePermsFromMode(0755)); err != nil {
				b.Fatalf("failed to create mount point: %v", err)
			}
			mountPoint, err := root.Walk(ctx, root, mountPointName)
			if err != nil {
				b.Fatalf("failed to walk to mount point: %v", err)
			}
			defer mountPoint.DecRef()
			submountInode, err := tmpfsFS.Mount(ctx, "tmpfs", fs.MountSourceFlags{}, "", nil)
			if err != nil {
				b.Fatalf("failed to create tmpfs submount: %v", err)
			}
			if err := mntns.Mount(ctx, mountPoint, submountInode); err != nil {
				b.Fatalf("failed to mount tmpfs submount: %v", err)
			}
			filePathBuilder.WriteString(mountPointName)
			filePathBuilder.WriteByte('/')

			// Create nested directories with given depth.
			d, err := root.Walk(ctx, root, mountPointName)
			if err != nil {
				b.Fatalf("failed to walk to mount root: %v", err)
			}
			defer d.DecRef()
			for i := depth; i > 0; i-- {
				name := fmt.Sprintf("%d", i)
				if err := d.Inode.CreateDirectory(ctx, d, name, fs.FilePermsFromMode(0755)); err != nil {
					b.Fatalf("failed to create directory %q: %v", name, err)
				}
				next, err := d.Walk(ctx, root, name)
				if err != nil {
					b.Fatalf("failed to walk to directory %q: %v", name, err)
				}
				d.DecRef()
				d = next
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Create the file that will be stat'd.
			file, err := d.Inode.Create(ctx, d, filename, fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0644))
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			file.DecRef()
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			dirPath := false
			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err := fileOpOn(ctx, mntns, root, root, linux.AT_FDCWD, filePath, true /* resolve */, func(root *fs.Dirent, d *fs.Dirent) error {
					if dirPath && !fs.IsDir(d.Inode.StableAttr) {
						return syserror.ENOTDIR
					}
					uattr, err := d.Inode.UnstableAttr(ctx)
					if err != nil {
						return err
					}
					// Sanity check.
					if uattr.Perms.User.Execute {
						b.Fatalf("got wrong permissions (%0o)", uattr.Perms.LinuxMode())
					}
					return nil
				})
				if err != nil {
					b.Fatalf("stat(%q) failed: %v", filePath, err)
				}
			}
			// Don't include deferred cleanup in benchmark time.
			b.StopTimer()
		})
	}
}

func BenchmarkVFS2MemfsMountStat(b *testing.B) {
	for _, depth := range depths {
		b.Run(fmt.Sprintf("%d", depth), func(b *testing.B) {
			ctx := contexttest.Context(b)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.New()
			vfsObj.MustRegisterFilesystemType("memfs", memfs.FilesystemType{})
			mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "memfs", &vfs.NewFilesystemOptions{})
			if err != nil {
				b.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mntns.DecRef(vfsObj)

			var filePathBuilder strings.Builder
			filePathBuilder.WriteByte('/')

			// Create the mount point.
			root := mntns.Root()
			defer root.DecRef()
			pop := vfs.PathOperation{
				Root:     root,
				Start:    root,
				Pathname: mountPointName,
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
			defer mountPoint.DecRef()
			// Create and mount the submount.
			if err := vfsObj.NewMount(ctx, creds, "", &pop, "memfs", &vfs.NewFilesystemOptions{}); err != nil {
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
					Root:     root,
					Start:    vd,
					Pathname: name,
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
				vd.DecRef()
				vd = nextVD
				filePathBuilder.WriteString(name)
				filePathBuilder.WriteByte('/')
			}

			// Verify that we didn't create any directories under the mount
			// point (i.e. they were all created on the submount).
			firstDirName := fmt.Sprintf("%d", depth)
			if child := mountPoint.Dentry().Child(firstDirName); child != nil {
				b.Fatalf("created directory %q under root mount, not submount", firstDirName)
			}

			// Create the file that will be stat'd.
			fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
				Root:               root,
				Start:              vd,
				Pathname:           filename,
				FollowFinalSymlink: true,
			}, &vfs.OpenOptions{
				Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
				Mode:  0644,
			})
			vd.DecRef()
			if err != nil {
				b.Fatalf("failed to create file %q: %v", filename, err)
			}
			fd.DecRef()
			filePathBuilder.WriteString(filename)
			filePath := filePathBuilder.String()

			runtime.GC()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				stat, err := vfsObj.StatAt(ctx, creds, &vfs.PathOperation{
					Root:               root,
					Start:              root,
					Pathname:           filePath,
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
	// Turn off reference leak checking for a fair comparison between vfs1 and
	// vfs2.
	refs.SetLeakMode(refs.NoLeakChecking)
}
