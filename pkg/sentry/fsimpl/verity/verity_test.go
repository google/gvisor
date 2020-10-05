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

package verity

import (
	"fmt"
	"io"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// rootMerkleFilename is the name of the root Merkle tree file.
const rootMerkleFilename = "root.verity"

// maxDataSize is the maximum data size written to the file for test.
const maxDataSize = 100000

// newVerityRoot creates a new verity mount, and returns the root. The
// underlying file system is tmpfs. If the error is not nil, then cleanup
// should be called when the root is no longer needed.
func newVerityRoot(ctx context.Context) (*vfs.VirtualFilesystem, vfs.VirtualDentry, func(), error) {
	rand.Seed(time.Now().UnixNano())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("VFS init: %v", err)
	}

	vfsObj.MustRegisterFilesystemType("verity", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mntns, err := vfsObj.NewMountNamespace(ctx, auth.CredentialsFromContext(ctx), "", "verity", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				RootMerkleFileName:           rootMerkleFilename,
				LowerName:                    "tmpfs",
				AllowRuntimeEnable:           true,
				NoCrashOnVerificationFailure: true,
			},
		},
	})
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("NewMountNamespace: %v", err)
	}
	root := mntns.Root()
	return vfsObj, root, func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	}, nil
}

// newFileFD creates a new file in the verity mount, and returns the FD. The FD
// points to a file that has random data generated.
func newFileFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, filePath string, mode linux.FileMode) (*vfs.FileDescription, int, error) {
	creds := auth.CredentialsFromContext(ctx)
	lowerRoot := root.Dentry().Impl().(*dentry).lowerVD

	// Create the file in the underlying file system.
	lowerFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(filePath),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR | linux.O_CREAT | linux.O_EXCL,
		Mode:  linux.ModeRegular | mode,
	})
	if err != nil {
		return nil, 0, err
	}

	// Generate random data to be written to the file.
	dataSize := rand.Intn(maxDataSize) + 1
	data := make([]byte, dataSize)
	rand.Read(data)

	// Write directly to the underlying FD, since verity FD is read-only.
	n, err := lowerFD.Write(ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	if err != nil {
		return nil, 0, err
	}

	if n != int64(len(data)) {
		return nil, 0, fmt.Errorf("lowerFD.Write got write length %d, want %d", n, len(data))
	}

	lowerFD.DecRef(ctx)

	// Now open the verity file descriptor.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filePath),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
		Mode:  linux.ModeRegular | mode,
	})
	return fd, dataSize, err
}

// corruptRandomBit randomly flips a bit in the file represented by fd.
func corruptRandomBit(ctx context.Context, fd *vfs.FileDescription, size int) error {
	// Flip a random bit in the underlying file.
	randomPos := int64(rand.Intn(size))
	byteToModify := make([]byte, 1)
	if _, err := fd.PRead(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.ReadOptions{}); err != nil {
		return fmt.Errorf("lowerFD.PRead: %v", err)
	}
	byteToModify[0] ^= 1
	if _, err := fd.PWrite(ctx, usermem.BytesIOSequence(byteToModify), randomPos, vfs.WriteOptions{}); err != nil {
		return fmt.Errorf("lowerFD.PWrite: %v", err)
	}
	return nil
}

// TestOpen ensures that when a file is created, the corresponding Merkle tree
// file and the root Merkle tree file exist.
func TestOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	if _, _, err := newFileFD(ctx, vfsObj, root, filename, 0644); err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Ensure that the corresponding Merkle tree file is created.
	lowerRoot := root.Dentry().Impl().(*dentry).lowerVD
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(merklePrefix + filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	}); err != nil {
		t.Errorf("OpenAt Merkle tree file %s: %v", merklePrefix+filename, err)
	}

	// Ensure the root merkle tree file is created.
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse(merklePrefix + rootMerkleFilename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	}); err != nil {
		t.Errorf("OpenAt root Merkle tree file %s: %v", merklePrefix+rootMerkleFilename, err)
	}
}

// TestUntouchedFileSucceeds ensures that read from an untouched verity file
// succeeds after enabling verity for it.
func TestReadUntouchedFileSucceeds(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file and confirm a normal read succeeds.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	buf := make([]byte, size)
	n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("fd.PRead: %v", err)
	}

	if n != int64(size) {
		t.Errorf("fd.PRead got read length %d, want %d", n, size)
	}
}

// TestReopenUntouchedFileSucceeds ensures that reopen an untouched verity file
// succeeds after enabling verity for it.
func TestReopenUntouchedFileSucceeds(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	fd, _, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file and confirms a normal read succeeds.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	// Ensure reopening the verity enabled file succeeds.
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
		Mode:  linux.ModeRegular,
	}); err != nil {
		t.Errorf("reopen enabled file failed: %v", err)
	}
}

// TestModifiedFileFails ensures that read from a modified verity file fails.
func TestModifiedFileFails(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	// Open a new lowerFD that's read/writable.
	lowerVD := fd.Impl().(*fileDescription).d.lowerVD

	lowerFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerVD,
		Start: lowerVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	if err := corruptRandomBit(ctx, lowerFD, size); err != nil {
		t.Fatalf("corruptRandomBit: %v", err)
	}

	// Confirm that read from the modified file fails.
	buf := make([]byte, size)
	if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
		t.Fatalf("fd.PRead succeeded with modified file")
	}
}

// TestModifiedMerkleFails ensures that read from a verity file fails if the
// corresponding Merkle tree file is modified.
func TestModifiedMerkleFails(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	fd, size, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	// Open a new lowerMerkleFD that's read/writable.
	lowerMerkleVD := fd.Impl().(*fileDescription).d.lowerMerkleVD

	lowerMerkleFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  lowerMerkleVD,
		Start: lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	// Flip a random bit in the Merkle tree file.
	stat, err := lowerMerkleFD.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	merkleSize := int(stat.Size)
	if err := corruptRandomBit(ctx, lowerMerkleFD, merkleSize); err != nil {
		t.Fatalf("corruptRandomBit: %v", err)
	}

	// Confirm that read from a file with modified Merkle tree fails.
	buf := make([]byte, size)
	if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
		fmt.Println(buf)
		t.Fatalf("fd.PRead succeeded with modified Merkle file")
	}
}

// TestModifiedParentMerkleFails ensures that open a verity enabled file in a
// verity enabled directory fails if the hashes related to the target file in
// the parent Merkle tree file is modified.
func TestModifiedParentMerkleFails(t *testing.T) {
	ctx := contexttest.Context(t)
	vfsObj, root, cleanup, err := newVerityRoot(ctx)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}
	defer cleanup()

	filename := "verity-test-file"
	fd, _, err := newFileFD(ctx, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file.
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	// Enable verity on the parent directory.
	parentFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  root,
		Start: root,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	if _, err := parentFD.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("Ioctl: %v", err)
	}

	// Open a new lowerMerkleFD that's read/writable.
	parentLowerMerkleVD := fd.Impl().(*fileDescription).d.parent.lowerMerkleVD

	parentLowerMerkleFD, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  parentLowerMerkleVD,
		Start: parentLowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}

	// Flip a random bit in the parent Merkle tree file.
	// This parent directory contains only one child, so any random
	// modification in the parent Merkle tree should cause verification
	// failure when opening the child file.
	stat, err := parentLowerMerkleFD.Stat(ctx, vfs.StatOptions{})
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	parentMerkleSize := int(stat.Size)
	if err := corruptRandomBit(ctx, parentLowerMerkleFD, parentMerkleSize); err != nil {
		t.Fatalf("corruptRandomBit: %v", err)
	}

	parentLowerMerkleFD.DecRef(ctx)

	// Ensure reopening the verity enabled file fails.
	if _, err = vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filename),
	}, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
		Mode:  linux.ModeRegular,
	}); err == nil {
		t.Errorf("OpenAt file with modified parent Merkle succeeded")
	}
}
