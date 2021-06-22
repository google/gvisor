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

package ext

import (
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	assetsDir = "pkg/sentry/fsimpl/ext/assets"
)

var (
	ext2ImagePath = path.Join(assetsDir, "tiny.ext2")
	ext3ImagePath = path.Join(assetsDir, "tiny.ext3")
	ext4ImagePath = path.Join(assetsDir, "tiny.ext4")
)

// setUp opens imagePath as an ext Filesystem and returns all necessary
// elements required to run tests. If error is non-nil, it also returns a tear
// down function which must be called after the test is run for clean up.
func setUp(t *testing.T, imagePath string) (context.Context, *vfs.VirtualFilesystem, *vfs.VirtualDentry, func(), error) {
	localImagePath, err := testutil.FindFile(imagePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to open local image at path %s: %v", imagePath, err)
	}

	f, err := os.Open(localImagePath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Create VFS.
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType("extfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, localImagePath, "extfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: int(f.Fd()),
		},
	})
	if err != nil {
		f.Close()
		return nil, nil, nil, nil, err
	}

	root := mntns.Root()
	root.IncRef()

	tearDown := func() {
		root.DecRef(ctx)

		if err := f.Close(); err != nil {
			t.Fatalf("tearDown failed: %v", err)
		}
	}
	return ctx, vfsObj, &root, tearDown, nil
}

// TODO(b/134676337): Test vfs.FilesystemImpl.ReadlinkAt and
// vfs.FilesystemImpl.StatFSAt which are not implemented in
// vfs.VirtualFilesystem yet.

// TestSeek tests vfs.FileDescriptionImpl.Seek functionality.
func TestSeek(t *testing.T) {
	type seekTest struct {
		name  string
		image string
		path  string
	}

	tests := []seekTest{
		{
			name:  "ext4 root dir seek",
			image: ext4ImagePath,
			path:  "/",
		},
		{
			name:  "ext3 root dir seek",
			image: ext3ImagePath,
			path:  "/",
		},
		{
			name:  "ext2 root dir seek",
			image: ext2ImagePath,
			path:  "/",
		},
		{
			name:  "ext4 reg file seek",
			image: ext4ImagePath,
			path:  "/file.txt",
		},
		{
			name:  "ext3 reg file seek",
			image: ext3ImagePath,
			path:  "/file.txt",
		},
		{
			name:  "ext2 reg file seek",
			image: ext2ImagePath,
			path:  "/file.txt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, vfsfs, root, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			fd, err := vfsfs.OpenAt(
				ctx,
				auth.CredentialsFromContext(ctx),
				&vfs.PathOperation{Root: *root, Start: *root, Path: fspath.Parse(test.path)},
				&vfs.OpenOptions{},
			)
			if err != nil {
				t.Fatalf("vfsfs.OpenAt failed: %v", err)
			}

			if n, err := fd.Seek(ctx, 0, linux.SEEK_SET); n != 0 || err != nil {
				t.Errorf("expected seek position 0, got %d and error %v", n, err)
			}

			stat, err := fd.Stat(ctx, vfs.StatOptions{})
			if err != nil {
				t.Errorf("fd.stat failed for file %s in image %s: %v", test.path, test.image, err)
			}

			// We should be able to seek beyond the end of file.
			size := int64(stat.Size)
			if n, err := fd.Seek(ctx, size, linux.SEEK_SET); n != size || err != nil {
				t.Errorf("expected seek position %d, got %d and error %v", size, n, err)
			}

			// EINVAL should be returned if the resulting offset is negative.
			if _, err := fd.Seek(ctx, -1, linux.SEEK_SET); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("expected error EINVAL but got %v", err)
			}

			if n, err := fd.Seek(ctx, 3, linux.SEEK_CUR); n != size+3 || err != nil {
				t.Errorf("expected seek position %d, got %d and error %v", size+3, n, err)
			}

			// Make sure negative offsets work with SEEK_CUR.
			if n, err := fd.Seek(ctx, -2, linux.SEEK_CUR); n != size+1 || err != nil {
				t.Errorf("expected seek position %d, got %d and error %v", size+1, n, err)
			}

			// EINVAL should be returned if the resulting offset is negative.
			if _, err := fd.Seek(ctx, -(size + 2), linux.SEEK_CUR); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("expected error EINVAL but got %v", err)
			}

			// Make sure SEEK_END works with regular files.
			if _, ok := fd.Impl().(*regularFileFD); ok {
				// Seek back to 0.
				if n, err := fd.Seek(ctx, -size, linux.SEEK_END); n != 0 || err != nil {
					t.Errorf("expected seek position %d, got %d and error %v", 0, n, err)
				}

				// Seek forward beyond EOF.
				if n, err := fd.Seek(ctx, 1, linux.SEEK_END); n != size+1 || err != nil {
					t.Errorf("expected seek position %d, got %d and error %v", size+1, n, err)
				}

				// EINVAL should be returned if the resulting offset is negative.
				if _, err := fd.Seek(ctx, -(size + 1), linux.SEEK_END); !linuxerr.Equals(linuxerr.EINVAL, err) {
					t.Errorf("expected error EINVAL but got %v", err)
				}
			}
		})
	}
}

// TestStatAt tests filesystem.StatAt functionality.
func TestStatAt(t *testing.T) {
	type statAtTest struct {
		name  string
		image string
		path  string
		want  linux.Statx
	}

	tests := []statAtTest{
		{
			name:  "ext4 statx small file",
			image: ext4ImagePath,
			path:  "/file.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13,
			},
		},
		{
			name:  "ext3 statx small file",
			image: ext3ImagePath,
			path:  "/file.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13,
			},
		},
		{
			name:  "ext2 statx small file",
			image: ext2ImagePath,
			path:  "/file.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13,
			},
		},
		{
			name:  "ext4 statx big file",
			image: ext4ImagePath,
			path:  "/bigfile.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13042,
			},
		},
		{
			name:  "ext3 statx big file",
			image: ext3ImagePath,
			path:  "/bigfile.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13042,
			},
		},
		{
			name:  "ext2 statx big file",
			image: ext2ImagePath,
			path:  "/bigfile.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0644 | linux.ModeRegular,
				Size:    13042,
			},
		},
		{
			name:  "ext4 statx symlink file",
			image: ext4ImagePath,
			path:  "/symlink.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0777 | linux.ModeSymlink,
				Size:    8,
			},
		},
		{
			name:  "ext3 statx symlink file",
			image: ext3ImagePath,
			path:  "/symlink.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0777 | linux.ModeSymlink,
				Size:    8,
			},
		},
		{
			name:  "ext2 statx symlink file",
			image: ext2ImagePath,
			path:  "/symlink.txt",
			want: linux.Statx{
				Blksize: 0x400,
				Nlink:   1,
				UID:     0,
				GID:     0,
				Mode:    0777 | linux.ModeSymlink,
				Size:    8,
			},
		},
	}

	// Ignore the fields that are not supported by filesystem.StatAt yet and
	// those which are likely to change as the image does.
	ignoredFields := map[string]bool{
		"Attributes":     true,
		"AttributesMask": true,
		"Atime":          true,
		"Blocks":         true,
		"Btime":          true,
		"Ctime":          true,
		"DevMajor":       true,
		"DevMinor":       true,
		"Ino":            true,
		"Mask":           true,
		"Mtime":          true,
		"RdevMajor":      true,
		"RdevMinor":      true,
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, vfsfs, root, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			got, err := vfsfs.StatAt(ctx,
				auth.CredentialsFromContext(ctx),
				&vfs.PathOperation{Root: *root, Start: *root, Path: fspath.Parse(test.path)},
				&vfs.StatOptions{},
			)
			if err != nil {
				t.Fatalf("vfsfs.StatAt failed for file %s in image %s: %v", test.path, test.image, err)
			}

			cmpIgnoreFields := cmp.FilterPath(func(p cmp.Path) bool {
				_, ok := ignoredFields[p.String()]
				return ok
			}, cmp.Ignore())
			if diff := cmp.Diff(got, test.want, cmpIgnoreFields, cmpopts.IgnoreUnexported(linux.Statx{})); diff != "" {
				t.Errorf("stat mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRead tests the read functionality for vfs file descriptions.
func TestRead(t *testing.T) {
	type readTest struct {
		name    string
		image   string
		absPath string
	}

	tests := []readTest{
		{
			name:    "ext4 read small file",
			image:   ext4ImagePath,
			absPath: "/file.txt",
		},
		{
			name:    "ext3 read small file",
			image:   ext3ImagePath,
			absPath: "/file.txt",
		},
		{
			name:    "ext2 read small file",
			image:   ext2ImagePath,
			absPath: "/file.txt",
		},
		{
			name:    "ext4 read big file",
			image:   ext4ImagePath,
			absPath: "/bigfile.txt",
		},
		{
			name:    "ext3 read big file",
			image:   ext3ImagePath,
			absPath: "/bigfile.txt",
		},
		{
			name:    "ext2 read big file",
			image:   ext2ImagePath,
			absPath: "/bigfile.txt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, vfsfs, root, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			fd, err := vfsfs.OpenAt(
				ctx,
				auth.CredentialsFromContext(ctx),
				&vfs.PathOperation{Root: *root, Start: *root, Path: fspath.Parse(test.absPath)},
				&vfs.OpenOptions{},
			)
			if err != nil {
				t.Fatalf("vfsfs.OpenAt failed: %v", err)
			}

			// Get a local file descriptor and compare its functionality with a vfs file
			// description for the same file.
			localFile, err := testutil.FindFile(path.Join(assetsDir, test.absPath))
			if err != nil {
				t.Fatalf("testutil.FindFile failed for %s: %v", test.absPath, err)
			}

			f, err := os.Open(localFile)
			if err != nil {
				t.Fatalf("os.Open failed for %s: %v", localFile, err)
			}
			defer f.Close()

			// Read the entire file by reading one byte repeatedly. Doing this stress
			// tests the underlying file reader implementation.
			got := make([]byte, 1)
			want := make([]byte, 1)
			for {
				n, err := f.Read(want)
				fd.Read(ctx, usermem.BytesIOSequence(got), vfs.ReadOptions{})

				if diff := cmp.Diff(got, want); diff != "" {
					t.Errorf("file data mismatch (-want +got):\n%s", diff)
				}

				// Make sure there is no more file data left after getting EOF.
				if n == 0 || err == io.EOF {
					if n, _ := fd.Read(ctx, usermem.BytesIOSequence(got), vfs.ReadOptions{}); n != 0 {
						t.Errorf("extra unexpected file data in file %s in image %s", test.absPath, test.image)
					}

					break
				}

				if err != nil {
					t.Fatalf("read failed: %v", err)
				}
			}
		})
	}
}

// iterDirentsCb is a simple callback which just keeps adding the dirents to an
// internal list. Implements vfs.IterDirentsCallback.
type iterDirentsCb struct {
	dirents []vfs.Dirent
}

// Compiles only if iterDirentCb implements vfs.IterDirentsCallback.
var _ vfs.IterDirentsCallback = (*iterDirentsCb)(nil)

// newIterDirentsCb is the iterDirent
func newIterDirentCb() *iterDirentsCb {
	return &iterDirentsCb{dirents: make([]vfs.Dirent, 0)}
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (cb *iterDirentsCb) Handle(dirent vfs.Dirent) error {
	cb.dirents = append(cb.dirents, dirent)
	return nil
}

// TestIterDirents tests the FileDescriptionImpl.IterDirents functionality.
func TestIterDirents(t *testing.T) {
	type iterDirentTest struct {
		name  string
		image string
		path  string
		want  []vfs.Dirent
	}

	wantDirents := []vfs.Dirent{
		{
			Name: ".",
			Type: linux.DT_DIR,
		},
		{
			Name: "..",
			Type: linux.DT_DIR,
		},
		{
			Name: "lost+found",
			Type: linux.DT_DIR,
		},
		{
			Name: "file.txt",
			Type: linux.DT_REG,
		},
		{
			Name: "bigfile.txt",
			Type: linux.DT_REG,
		},
		{
			Name: "symlink.txt",
			Type: linux.DT_LNK,
		},
	}
	tests := []iterDirentTest{
		{
			name:  "ext4 root dir iteration",
			image: ext4ImagePath,
			path:  "/",
			want:  wantDirents,
		},
		{
			name:  "ext3 root dir iteration",
			image: ext3ImagePath,
			path:  "/",
			want:  wantDirents,
		},
		{
			name:  "ext2 root dir iteration",
			image: ext2ImagePath,
			path:  "/",
			want:  wantDirents,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, vfsfs, root, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			fd, err := vfsfs.OpenAt(
				ctx,
				auth.CredentialsFromContext(ctx),
				&vfs.PathOperation{Root: *root, Start: *root, Path: fspath.Parse(test.path)},
				&vfs.OpenOptions{},
			)
			if err != nil {
				t.Fatalf("vfsfs.OpenAt failed: %v", err)
			}

			cb := &iterDirentsCb{}
			if err = fd.IterDirents(ctx, cb); err != nil {
				t.Fatalf("dir fd.IterDirents() failed: %v", err)
			}

			sort.Slice(cb.dirents, func(i int, j int) bool { return cb.dirents[i].Name < cb.dirents[j].Name })
			sort.Slice(test.want, func(i int, j int) bool { return test.want[i].Name < test.want[j].Name })

			// Ignore the inode number and offset of dirents because those are likely to
			// change as the underlying image changes.
			cmpIgnoreFields := cmp.FilterPath(func(p cmp.Path) bool {
				return p.String() == "Ino" || p.String() == "NextOff"
			}, cmp.Ignore())
			if diff := cmp.Diff(cb.dirents, test.want, cmpIgnoreFields); diff != "" {
				t.Errorf("dirents mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRootDir tests that the root directory inode is correctly initialized and
// returned from setUp.
func TestRootDir(t *testing.T) {
	type inodeProps struct {
		Mode      linux.FileMode
		UID       auth.KUID
		GID       auth.KGID
		Size      uint64
		InodeSize uint16
		Links     uint16
		Flags     disklayout.InodeFlags
	}

	type rootDirTest struct {
		name      string
		image     string
		wantInode inodeProps
	}

	tests := []rootDirTest{
		{
			name:  "ext4 root dir",
			image: ext4ImagePath,
			wantInode: inodeProps{
				Mode:      linux.ModeDirectory | 0755,
				Size:      0x400,
				InodeSize: 0x80,
				Links:     3,
				Flags:     disklayout.InodeFlags{Extents: true},
			},
		},
		{
			name:  "ext3 root dir",
			image: ext3ImagePath,
			wantInode: inodeProps{
				Mode:      linux.ModeDirectory | 0755,
				Size:      0x400,
				InodeSize: 0x80,
				Links:     3,
			},
		},
		{
			name:  "ext2 root dir",
			image: ext2ImagePath,
			wantInode: inodeProps{
				Mode:      linux.ModeDirectory | 0755,
				Size:      0x400,
				InodeSize: 0x80,
				Links:     3,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, vd, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			d, ok := vd.Dentry().Impl().(*dentry)
			if !ok {
				t.Fatalf("ext dentry of incorrect type: %T", vd.Dentry().Impl())
			}

			// Offload inode contents into local structs for comparison.
			gotInode := inodeProps{
				Mode:      d.inode.diskInode.Mode(),
				UID:       d.inode.diskInode.UID(),
				GID:       d.inode.diskInode.GID(),
				Size:      d.inode.diskInode.Size(),
				InodeSize: d.inode.diskInode.InodeSize(),
				Links:     d.inode.diskInode.LinksCount(),
				Flags:     d.inode.diskInode.Flags(),
			}

			if diff := cmp.Diff(gotInode, test.wantInode); diff != "" {
				t.Errorf("inode mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestFilesystemInit tests that the filesystem superblock and block group
// descriptors are correctly read in and initialized.
func TestFilesystemInit(t *testing.T) {
	// sb only contains the immutable properties of the superblock.
	type sb struct {
		InodesCount      uint32
		BlocksCount      uint64
		MaxMountCount    uint16
		FirstDataBlock   uint32
		BlockSize        uint64
		BlocksPerGroup   uint32
		ClusterSize      uint64
		ClustersPerGroup uint32
		InodeSize        uint16
		InodesPerGroup   uint32
		BgDescSize       uint16
		Magic            uint16
		Revision         disklayout.SbRevision
		CompatFeatures   disklayout.CompatFeatures
		IncompatFeatures disklayout.IncompatFeatures
		RoCompatFeatures disklayout.RoCompatFeatures
	}

	// bg only contains the immutable properties of the block group descriptor.
	type bg struct {
		InodeTable      uint64
		BlockBitmap     uint64
		InodeBitmap     uint64
		ExclusionBitmap uint64
		Flags           disklayout.BGFlags
	}

	type fsInitTest struct {
		name    string
		image   string
		wantSb  sb
		wantBgs []bg
	}

	tests := []fsInitTest{
		{
			name:  "ext4 filesystem init",
			image: ext4ImagePath,
			wantSb: sb{
				InodesCount:      0x10,
				BlocksCount:      0x40,
				MaxMountCount:    0xffff,
				FirstDataBlock:   0x1,
				BlockSize:        0x400,
				BlocksPerGroup:   0x2000,
				ClusterSize:      0x400,
				ClustersPerGroup: 0x2000,
				InodeSize:        0x80,
				InodesPerGroup:   0x10,
				BgDescSize:       0x40,
				Magic:            linux.EXT_SUPER_MAGIC,
				Revision:         disklayout.DynamicRev,
				CompatFeatures: disklayout.CompatFeatures{
					ExtAttr:     true,
					ResizeInode: true,
					DirIndex:    true,
				},
				IncompatFeatures: disklayout.IncompatFeatures{
					DirentFileType: true,
					Extents:        true,
					Is64Bit:        true,
					FlexBg:         true,
				},
				RoCompatFeatures: disklayout.RoCompatFeatures{
					Sparse:       true,
					LargeFile:    true,
					HugeFile:     true,
					DirNlink:     true,
					ExtraIsize:   true,
					MetadataCsum: true,
				},
			},
			wantBgs: []bg{
				{
					InodeTable:  0x23,
					BlockBitmap: 0x3,
					InodeBitmap: 0x13,
					Flags: disklayout.BGFlags{
						InodeZeroed: true,
					},
				},
			},
		},
		{
			name:  "ext3 filesystem init",
			image: ext3ImagePath,
			wantSb: sb{
				InodesCount:      0x10,
				BlocksCount:      0x40,
				MaxMountCount:    0xffff,
				FirstDataBlock:   0x1,
				BlockSize:        0x400,
				BlocksPerGroup:   0x2000,
				ClusterSize:      0x400,
				ClustersPerGroup: 0x2000,
				InodeSize:        0x80,
				InodesPerGroup:   0x10,
				BgDescSize:       0x20,
				Magic:            linux.EXT_SUPER_MAGIC,
				Revision:         disklayout.DynamicRev,
				CompatFeatures: disklayout.CompatFeatures{
					ExtAttr:     true,
					ResizeInode: true,
					DirIndex:    true,
				},
				IncompatFeatures: disklayout.IncompatFeatures{
					DirentFileType: true,
				},
				RoCompatFeatures: disklayout.RoCompatFeatures{
					Sparse:    true,
					LargeFile: true,
				},
			},
			wantBgs: []bg{
				{
					InodeTable:  0x5,
					BlockBitmap: 0x3,
					InodeBitmap: 0x4,
					Flags: disklayout.BGFlags{
						InodeZeroed: true,
					},
				},
			},
		},
		{
			name:  "ext2 filesystem init",
			image: ext2ImagePath,
			wantSb: sb{
				InodesCount:      0x10,
				BlocksCount:      0x40,
				MaxMountCount:    0xffff,
				FirstDataBlock:   0x1,
				BlockSize:        0x400,
				BlocksPerGroup:   0x2000,
				ClusterSize:      0x400,
				ClustersPerGroup: 0x2000,
				InodeSize:        0x80,
				InodesPerGroup:   0x10,
				BgDescSize:       0x20,
				Magic:            linux.EXT_SUPER_MAGIC,
				Revision:         disklayout.DynamicRev,
				CompatFeatures: disklayout.CompatFeatures{
					ExtAttr:     true,
					ResizeInode: true,
					DirIndex:    true,
				},
				IncompatFeatures: disklayout.IncompatFeatures{
					DirentFileType: true,
				},
				RoCompatFeatures: disklayout.RoCompatFeatures{
					Sparse:    true,
					LargeFile: true,
				},
			},
			wantBgs: []bg{
				{
					InodeTable:  0x5,
					BlockBitmap: 0x3,
					InodeBitmap: 0x4,
					Flags: disklayout.BGFlags{
						InodeZeroed: true,
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, vd, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			fs, ok := vd.Mount().Filesystem().Impl().(*filesystem)
			if !ok {
				t.Fatalf("ext filesystem of incorrect type: %T", vd.Mount().Filesystem().Impl())
			}

			// Offload superblock and block group descriptors contents into
			// local structs for comparison.
			totalFreeInodes := uint32(0)
			totalFreeBlocks := uint64(0)
			gotSb := sb{
				InodesCount:      fs.sb.InodesCount(),
				BlocksCount:      fs.sb.BlocksCount(),
				MaxMountCount:    fs.sb.MaxMountCount(),
				FirstDataBlock:   fs.sb.FirstDataBlock(),
				BlockSize:        fs.sb.BlockSize(),
				BlocksPerGroup:   fs.sb.BlocksPerGroup(),
				ClusterSize:      fs.sb.ClusterSize(),
				ClustersPerGroup: fs.sb.ClustersPerGroup(),
				InodeSize:        fs.sb.InodeSize(),
				InodesPerGroup:   fs.sb.InodesPerGroup(),
				BgDescSize:       fs.sb.BgDescSize(),
				Magic:            fs.sb.Magic(),
				Revision:         fs.sb.Revision(),
				CompatFeatures:   fs.sb.CompatibleFeatures(),
				IncompatFeatures: fs.sb.IncompatibleFeatures(),
				RoCompatFeatures: fs.sb.ReadOnlyCompatibleFeatures(),
			}
			gotNumBgs := len(fs.bgs)
			gotBgs := make([]bg, gotNumBgs)
			for i := 0; i < gotNumBgs; i++ {
				gotBgs[i].InodeTable = fs.bgs[i].InodeTable()
				gotBgs[i].BlockBitmap = fs.bgs[i].BlockBitmap()
				gotBgs[i].InodeBitmap = fs.bgs[i].InodeBitmap()
				gotBgs[i].ExclusionBitmap = fs.bgs[i].ExclusionBitmap()
				gotBgs[i].Flags = fs.bgs[i].Flags()

				totalFreeInodes += fs.bgs[i].FreeInodesCount()
				totalFreeBlocks += uint64(fs.bgs[i].FreeBlocksCount())
			}

			if diff := cmp.Diff(gotSb, test.wantSb); diff != "" {
				t.Errorf("superblock mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(gotBgs, test.wantBgs); diff != "" {
				t.Errorf("block group descriptors mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(totalFreeInodes, fs.sb.FreeInodesCount()); diff != "" {
				t.Errorf("total free inodes mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(totalFreeBlocks, fs.sb.FreeBlocksCount()); diff != "" {
				t.Errorf("total free blocks mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
