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
	"os"
	"path"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"

	"gvisor.dev/gvisor/runsc/test/testutil"
)

const (
	assetsDir = "pkg/sentry/fs/ext/assets"
)

var (
	ext2ImagePath = path.Join(assetsDir, "tiny.ext2")
	ext3ImagePath = path.Join(assetsDir, "tiny.ext3")
	ext4ImagePath = path.Join(assetsDir, "tiny.ext4")
)

func beginning(_ uint64) uint64 {
	return 0
}

func middle(i uint64) uint64 {
	return i / 2
}

func end(i uint64) uint64 {
	return i
}

// setUp opens imagePath as an ext Filesystem and returns all necessary
// elements required to run tests. If error is non-nil, it also returns a tear
// down function which must be called after the test is run for clean up.
func setUp(t *testing.T, imagePath string) (context.Context, *vfs.Filesystem, *vfs.Dentry, func(), error) {
	localImagePath, err := testutil.FindFile(imagePath)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to open local image at path %s: %v", imagePath, err)
	}

	f, err := os.Open(localImagePath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Mount the ext4 fs and retrieve the inode structure for the file.
	mockCtx := contexttest.Context(t)
	fs, d, err := filesystemType{}.NewFilesystem(mockCtx, nil, localImagePath, vfs.NewFilesystemOptions{InternalData: int(f.Fd())})
	if err != nil {
		f.Close()
		return nil, nil, nil, nil, err
	}

	tearDown := func() {
		if err := f.Close(); err != nil {
			t.Fatalf("tearDown failed: %v", err)
		}
	}
	return mockCtx, fs, d, tearDown, nil
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
			_, _, vfsd, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			d, ok := vfsd.Impl().(*dentry)
			if !ok {
				t.Fatalf("ext dentry of incorrect type: %T", vfsd.Impl())
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
			_, vfsfs, _, tearDown, err := setUp(t, test.image)
			if err != nil {
				t.Fatalf("setUp failed: %v", err)
			}
			defer tearDown()

			fs, ok := vfsfs.Impl().(*filesystem)
			if !ok {
				t.Fatalf("ext filesystem of incorrect type: %T", vfsfs.Impl())
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
