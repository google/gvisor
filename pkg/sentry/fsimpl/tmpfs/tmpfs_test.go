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

package tmpfs

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// nextFileID is used to generate unique file names.
var nextFileID atomicbitops.Int64

// newTmpfsRoot creates a new tmpfs mount, and returns the root. If the error
// is not nil, then cleanup should be called when the root is no longer needed.
func newTmpfsRoot(ctx context.Context) (*vfs.VirtualFilesystem, vfs.VirtualDentry, func(), error) {
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("VFS init: %v", err)
	}

	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("failed to create tmpfs root mount: %v", err)
	}
	root := mntns.Root(ctx)
	return vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}, nil
}

// newFileFD creates a new file in a new tmpfs mount, and returns the FD. If
// the returned err is not nil, then cleanup should be called when the FD is no
// longer needed.
func newFileFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	filename := fmt.Sprintf("tmpfs-test-file-%d", nextFileID.Add(1))

	// Create the file that will be write/read.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  linux.ModeRegular | mode,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create file %q: %v", filename, err)
	}

	return fd, cleanup, nil
}

// newDirFD is like newFileFD, but for directories.
func newDirFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	dirname := fmt.Sprintf("tmpfs-test-dir-%d", nextFileID.Add(1))

	// Create the dir.
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dirname),
	}, &vfs.MkdirOptions{
		Mode: linux.ModeDirectory | mode,
	}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create directory %q: %v", dirname, err)
	}

	// Open the dir and return it.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(dirname),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to open directory %q: %v", dirname, err)
	}

	return fd, cleanup, nil
}

// newPipeFD is like newFileFD, but for pipes.
func newPipeFD(ctx context.Context, mode linux.FileMode) (*vfs.FileDescription, func(), error) {
	creds := auth.CredentialsFromContext(ctx)
	vfsObj, root, cleanup, err := newTmpfsRoot(ctx)
	if err != nil {
		return nil, nil, err
	}

	name := fmt.Sprintf("tmpfs-test-%d", nextFileID.Add(1))

	if err := vfsObj.MknodAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}, &vfs.MknodOptions{
		Mode: linux.ModeNamedPipe | mode,
	}); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to create pipe %q: %v", name, err)
	}

	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to open pipe %q: %v", name, err)
	}

	return fd, cleanup, nil
}

func TestParseSize(t *testing.T) {
	// 4 GiB of host memory
	SetTotalHostMem(4096 * 1024 * 1024)

	tests := []struct {
		s                  string
		want               uint64
		wantPercentageUsed bool
		wantError          bool
	}{
		{"500", 500, false, false},
		{"5k", (5 * 1024), false, false},
		{"5m", (5 * 1024 * 1024), false, false},
		{"5G", (5 * 1024 * 1024 * 1024), false, false},
		{"5t", (5 * 1024 * 1024 * 1024 * 1024), false, false},
		{"5P", (5 * 1024 * 1024 * 1024 * 1024 * 1024), false, false},
		{"5e", (5 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024), false, false},
		{"5%", (5 * (totalHostMem / 100)), true, false},
		{"5e3", 0, false, true},
		{"", 0, false, true},
		{"9999999999999999P", 0, false, true},
	}
	for _, tt := range tests {
		testname := tt.s
		t.Run(testname, func(t *testing.T) {
			size, percentageUsed, err := parseSize(tt.s)
			if tt.wantError && err == nil {
				t.Errorf("Invalid input: %v parsed", tt.s)
			}
			if !tt.wantError {
				if err != nil {
					t.Errorf("Couldn't parse size, Error: %v", err)
				}
				if size != tt.want || percentageUsed != tt.wantPercentageUsed {
					t.Errorf("got: (%v, %v), want (%v, %v)", size, percentageUsed, tt.want, tt.wantPercentageUsed)
				}
			}
		})
	}
}

func TestMountOptions(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	// Ensure totalHostMem is set for default size calculation.
	SetTotalHostMem(4096 * 1024 * 1024) // 4 GiB

	tests := []struct {
		name       string
		opts       string
		wantBlocks uint64
		wantErr    bool
	}{
		{
			name:       "default size",
			opts:       "",
			wantBlocks: (totalHostMem / 2) / hostarch.PageSize,
			wantErr:    false,
		},
		{
			name:       "size 1M",
			opts:       "size=1M",
			wantBlocks: (1024 * 1024) / hostarch.PageSize,
			wantErr:    false,
		},
		{
			name:       "nr_blocks 10",
			opts:       "nr_blocks=10",
			wantBlocks: 10,
			wantErr:    false,
		},
		{
			name:       "nr_blocks 10, size 1M (nr_blocks wins if last)",
			opts:       "size=1M,nr_blocks=10",
			wantBlocks: 10,
			wantErr:    false,
		},
		{
			name:       "nr_blocks 10, size 1M (size wins if last)",
			opts:       "nr_blocks=10,size=1M",
			wantBlocks: (1024 * 1024) / hostarch.PageSize,
			wantErr:    false,
		},
		{
			name:    "nr_blocks percentage fails",
			opts:    "nr_blocks=10%",
			wantErr: true,
		},
		{
			name:    "invalid nr_blocks fails",
			opts:    "nr_blocks=invalid",
			wantErr: true,
		},
		{
			name:    "unknown option fails",
			opts:    "unknown=1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vfsObj := &vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				t.Fatalf("VFS init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
				AllowUserMount: true,
			})

			mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
				GetFilesystemOptions: vfs.GetFilesystemOptions{
					Data: tt.opts,
				},
			}, nil)
			if tt.wantErr {
				if err == nil {
					mntns.DecRef(ctx)
					t.Errorf("expected mount to fail for opts %q", tt.opts)
				}
				return
			}
			if err != nil {
				t.Fatalf("mount failed for opts %q: %v", tt.opts, err)
			}
			defer mntns.DecRef(ctx)

			root := mntns.Root(ctx)
			defer root.DecRef(ctx)

			statfs, err := vfsObj.StatFSAt(ctx, creds, &vfs.PathOperation{
				Root:  root,
				Start: root,
			})
			if err != nil {
				t.Fatalf("StatFS failed: %v", err)
			}

			if statfs.Blocks != tt.wantBlocks {
				t.Errorf("got blocks %d, want %d", statfs.Blocks, tt.wantBlocks)
			}
		})
	}
}

func TestMountOptionsEnforcement(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	vfsObj.MustRegisterFilesystemType("tmpfs", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	// Mount with nr_blocks=1 (which means max 1 page = 4096 bytes).
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			Data: "nr_blocks=1",
		},
	}, nil)
	if err != nil {
		t.Fatalf("failed to create tmpfs mount: %v", err)
	}
	root := mntns.Root(ctx)
	defer root.DecRef(ctx)
	defer mntns.DecRef(ctx)

	// Create a file.
	filename := "test-file"
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  0644,
	})
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer fd.DecRef(ctx)

	// Write 1 page of data.
	data1 := make([]byte, hostarch.PageSize)
	n1, err := fd.Write(ctx, usermem.BytesIOSequence(data1), vfs.WriteOptions{})
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n1 != int64(len(data1)) {
		t.Fatalf("first write short: got %d, want %d", n1, len(data1))
	}

	// Write 1 more byte (should fail with ENOSPC because we are at the limit).
	data2 := []byte{'a'}
	_, err = fd.Write(ctx, usermem.BytesIOSequence(data2), vfs.WriteOptions{})
	if !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("second write got err %v, want ENOSPC", err)
	}
}
