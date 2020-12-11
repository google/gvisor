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
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// rootMerkleFilename is the name of the root Merkle tree file.
	rootMerkleFilename = "root.verity"
	// maxDataSize is the maximum data size of a test file.
	maxDataSize = 100000
)

var hashAlgs = []HashAlgorithm{SHA256, SHA512}

func dentryFromVD(t *testing.T, vd vfs.VirtualDentry) *dentry {
	t.Helper()
	d, ok := vd.Dentry().Impl().(*dentry)
	if !ok {
		t.Fatalf("can't assert %T as a *dentry", vd)
	}
	return d
}

// dentryFromFD returns the dentry corresponding to fd.
func dentryFromFD(t *testing.T, fd *vfs.FileDescription) *dentry {
	t.Helper()
	f, ok := fd.Impl().(*fileDescription)
	if !ok {
		t.Fatalf("can't assert %T as a *fileDescription", fd)
	}
	return f.d
}

// newVerityRoot creates a new verity mount, and returns the root. The
// underlying file system is tmpfs. If the error is not nil, then cleanup
// should be called when the root is no longer needed.
func newVerityRoot(t *testing.T, hashAlg HashAlgorithm) (*vfs.VirtualFilesystem, vfs.VirtualDentry, *kernel.Task, error) {
	t.Helper()
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("testutil.Boot: %v", err)
	}

	ctx := k.SupervisorContext()

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
				Alg:                          hashAlg,
				AllowRuntimeEnable:           true,
				NoCrashOnVerificationFailure: true,
			},
		},
	})
	if err != nil {
		return nil, vfs.VirtualDentry{}, nil, fmt.Errorf("NewMountNamespace: %v", err)
	}
	root := mntns.Root()
	root.IncRef()

	// Use lowerRoot in the task as we modify the lower file system
	// directly in many tests.
	lowerRoot := root.Dentry().Impl().(*dentry).lowerVD
	tc := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, k.GlobalInit().Limits())
	task, err := testutil.CreateTask(ctx, "name", tc, mntns, lowerRoot, lowerRoot)
	if err != nil {
		t.Fatalf("testutil.CreateTask: %v", err)
	}

	t.Cleanup(func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	})
	return vfsObj, root, task, nil
}

// openVerityAt opens a verity file.
//
// TODO(chongc): release reference from opening the file when done.
func openVerityAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, vd vfs.VirtualDentry, path string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  vd,
		Start: vd,
		Path:  fspath.Parse(path),
	}, &vfs.OpenOptions{
		Flags: flags,
		Mode:  mode,
	})
}

// openLowerAt opens the file in the underlying file system.
//
// TODO(chongc): release reference from opening the file when done.
func (d *dentry) openLowerAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, path string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(path),
	}, &vfs.OpenOptions{
		Flags: flags,
		Mode:  mode,
	})
}

// openLowerMerkleAt opens the Merkle file in the underlying file system.
//
// TODO(chongc): release reference from opening the file when done.
func (d *dentry) openLowerMerkleAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerMerkleVD,
		Start: d.lowerMerkleVD,
	}, &vfs.OpenOptions{
		Flags: flags,
		Mode:  mode,
	})
}

// unlinkLowerAt deletes the file in the underlying file system.
func (d *dentry) unlinkLowerAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, path string) error {
	return vfsObj.UnlinkAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(path),
	})
}

// unlinkLowerMerkleAt deletes the Merkle file in the underlying file system.
func (d *dentry) unlinkLowerMerkleAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, path string) error {
	return vfsObj.UnlinkAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(merklePrefix + path),
	})
}

// renameLowerAt renames file name to newName in the underlying file system.
func (d *dentry) renameLowerAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, name string, newName string) error {
	return vfsObj.RenameAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(name),
	}, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(newName),
	}, &vfs.RenameOptions{})
}

// renameLowerMerkleAt renames Merkle file name to newName in the underlying
// file system.
func (d *dentry) renameLowerMerkleAt(ctx context.Context, vfsObj *vfs.VirtualFilesystem, name string, newName string) error {
	return vfsObj.RenameAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(merklePrefix + name),
	}, &vfs.PathOperation{
		Root:  d.lowerVD,
		Start: d.lowerVD,
		Path:  fspath.Parse(merklePrefix + newName),
	}, &vfs.RenameOptions{})
}

// newFileFD creates a new file in the verity mount, and returns the FD. The FD
// points to a file that has random data generated.
func newFileFD(ctx context.Context, t *testing.T, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, filePath string, mode linux.FileMode) (*vfs.FileDescription, int, error) {
	// Create the file in the underlying file system.
	lowerFD, err := dentryFromVD(t, root).openLowerAt(ctx, vfsObj, filePath, linux.O_RDWR|linux.O_CREAT|linux.O_EXCL, linux.ModeRegular|mode)
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
	fd, err := openVerityAt(ctx, vfsObj, root, filePath, linux.O_RDONLY, mode)
	return fd, dataSize, err
}

// newEmptyFileFD creates a new empty file in the verity mount, and returns the FD.
func newEmptyFileFD(ctx context.Context, t *testing.T, vfsObj *vfs.VirtualFilesystem, root vfs.VirtualDentry, filePath string, mode linux.FileMode) (*vfs.FileDescription, error) {
	// Create the file in the underlying file system.
	_, err := dentryFromVD(t, root).openLowerAt(ctx, vfsObj, filePath, linux.O_RDWR|linux.O_CREAT|linux.O_EXCL, linux.ModeRegular|mode)
	if err != nil {
		return nil, err
	}
	// Now open the verity file descriptor.
	fd, err := openVerityAt(ctx, vfsObj, root, filePath, linux.O_RDONLY, mode)
	return fd, err
}

// flipRandomBit randomly flips a bit in the file represented by fd.
func flipRandomBit(ctx context.Context, fd *vfs.FileDescription, size int) error {
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

func enableVerity(ctx context.Context, t *testing.T, fd *vfs.FileDescription) {
	t.Helper()
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: linux.FS_IOC_ENABLE_VERITY}
	if _, err := fd.Ioctl(ctx, nil /* uio */, args); err != nil {
		t.Fatalf("enable verity: %v", err)
	}
}

// TestOpen ensures that when a file is created, the corresponding Merkle tree
// file and the root Merkle tree file exist.
func TestOpen(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Ensure that the corresponding Merkle tree file is created.
		if _, err = dentryFromFD(t, fd).openLowerMerkleAt(ctx, vfsObj, linux.O_RDONLY, linux.ModeRegular); err != nil {
			t.Errorf("OpenAt Merkle tree file %s: %v", merklePrefix+filename, err)
		}

		// Ensure the root merkle tree file is created.
		if _, err = dentryFromVD(t, root).openLowerMerkleAt(ctx, vfsObj, linux.O_RDONLY, linux.ModeRegular); err != nil {
			t.Errorf("OpenAt root Merkle tree file %s: %v", merklePrefix+rootMerkleFilename, err)
		}
	}
}

// TestPReadUnmodifiedFileSucceeds ensures that pread from an untouched verity
// file succeeds after enabling verity for it.
func TestPReadUnmodifiedFileSucceeds(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, size, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file and confirm a normal read succeeds.
		enableVerity(ctx, t, fd)

		buf := make([]byte, size)
		n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{})
		if err != nil && err != io.EOF {
			t.Fatalf("fd.PRead: %v", err)
		}

		if n != int64(size) {
			t.Errorf("fd.PRead got read length %d, want %d", n, size)
		}
	}
}

// TestReadUnmodifiedFileSucceeds ensures that read from an untouched verity
// file succeeds after enabling verity for it.
func TestReadUnmodifiedFileSucceeds(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, size, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file and confirm a normal read succeeds.
		enableVerity(ctx, t, fd)

		buf := make([]byte, size)
		n, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if err != nil && err != io.EOF {
			t.Fatalf("fd.Read: %v", err)
		}

		if n != int64(size) {
			t.Errorf("fd.PRead got read length %d, want %d", n, size)
		}
	}
}

// TestReadUnmodifiedEmptyFileSucceeds ensures that read from an untouched empty verity
// file succeeds after enabling verity for it.
func TestReadUnmodifiedEmptyFileSucceeds(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-empty-file"
		fd, err := newEmptyFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newEmptyFileFD: %v", err)
		}

		// Enable verity on the file and confirm a normal read succeeds.
		enableVerity(ctx, t, fd)

		var buf []byte
		n, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if err != nil && err != io.EOF {
			t.Fatalf("fd.Read: %v", err)
		}

		if n != 0 {
			t.Errorf("fd.Read got read length %d, expected 0", n)
		}
	}
}

// TestReopenUnmodifiedFileSucceeds ensures that reopen an untouched verity file
// succeeds after enabling verity for it.
func TestReopenUnmodifiedFileSucceeds(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file and confirms a normal read succeeds.
		enableVerity(ctx, t, fd)

		// Ensure reopening the verity enabled file succeeds.
		if _, err = openVerityAt(ctx, vfsObj, root, filename, linux.O_RDONLY, linux.ModeRegular); err != nil {
			t.Errorf("reopen enabled file failed: %v", err)
		}
	}
}

// TestOpenNonexistentFile ensures that opening a nonexistent file does not
// trigger verification failure, even if the parent directory is verified.
func TestOpenNonexistentFile(t *testing.T) {
	vfsObj, root, ctx, err := newVerityRoot(t, SHA256)
	if err != nil {
		t.Fatalf("newVerityRoot: %v", err)
	}

	filename := "verity-test-file"
	fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
	if err != nil {
		t.Fatalf("newFileFD: %v", err)
	}

	// Enable verity on the file and confirms a normal read succeeds.
	enableVerity(ctx, t, fd)

	// Enable verity on the parent directory.
	parentFD, err := openVerityAt(ctx, vfsObj, root, "", linux.O_RDONLY, linux.ModeRegular)
	if err != nil {
		t.Fatalf("OpenAt: %v", err)
	}
	enableVerity(ctx, t, parentFD)

	// Ensure open an unexpected file in the parent directory fails with
	// ENOENT rather than verification failure.
	if _, err = openVerityAt(ctx, vfsObj, root, filename+"abc", linux.O_RDONLY, linux.ModeRegular); err != syserror.ENOENT {
		t.Errorf("OpenAt unexpected error: %v", err)
	}
}

// TestPReadModifiedFileFails ensures that read from a modified verity file
// fails.
func TestPReadModifiedFileFails(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, size, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file.
		enableVerity(ctx, t, fd)

		// Open a new lowerFD that's read/writable.
		lowerFD, err := dentryFromFD(t, fd).openLowerAt(ctx, vfsObj, "", linux.O_RDWR, linux.ModeRegular)
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}

		if err := flipRandomBit(ctx, lowerFD, size); err != nil {
			t.Fatalf("flipRandomBit: %v", err)
		}

		// Confirm that read from the modified file fails.
		buf := make([]byte, size)
		if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
			t.Fatalf("fd.PRead succeeded, expected failure")
		}
	}
}

// TestReadModifiedFileFails ensures that read from a modified verity file
// fails.
func TestReadModifiedFileFails(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, size, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file.
		enableVerity(ctx, t, fd)

		// Open a new lowerFD that's read/writable.
		lowerFD, err := dentryFromFD(t, fd).openLowerAt(ctx, vfsObj, "", linux.O_RDWR, linux.ModeRegular)
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}

		if err := flipRandomBit(ctx, lowerFD, size); err != nil {
			t.Fatalf("flipRandomBit: %v", err)
		}

		// Confirm that read from the modified file fails.
		buf := make([]byte, size)
		if _, err := fd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); err == nil {
			t.Fatalf("fd.Read succeeded, expected failure")
		}
	}
}

// TestModifiedMerkleFails ensures that read from a verity file fails if the
// corresponding Merkle tree file is modified.
func TestModifiedMerkleFails(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, size, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file.
		enableVerity(ctx, t, fd)

		// Open a new lowerMerkleFD that's read/writable.
		lowerMerkleFD, err := dentryFromFD(t, fd).openLowerMerkleAt(ctx, vfsObj, linux.O_RDWR, linux.ModeRegular)
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}

		// Flip a random bit in the Merkle tree file.
		stat, err := lowerMerkleFD.Stat(ctx, vfs.StatOptions{})
		if err != nil {
			t.Errorf("lowerMerkleFD.Stat: %v", err)
		}

		if err := flipRandomBit(ctx, lowerMerkleFD, int(stat.Size)); err != nil {
			t.Fatalf("flipRandomBit: %v", err)
		}

		// Confirm that read from a file with modified Merkle tree fails.
		buf := make([]byte, size)
		if _, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0 /* offset */, vfs.ReadOptions{}); err == nil {
			t.Fatalf("fd.PRead succeeded with modified Merkle file")
		}
	}
}

// TestModifiedParentMerkleFails ensures that open a verity enabled file in a
// verity enabled directory fails if the hashes related to the target file in
// the parent Merkle tree file is modified.
func TestModifiedParentMerkleFails(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file.
		enableVerity(ctx, t, fd)

		// Enable verity on the parent directory.
		parentFD, err := openVerityAt(ctx, vfsObj, root, "", linux.O_RDONLY, linux.ModeRegular)
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}
		enableVerity(ctx, t, parentFD)

		// Open a new lowerMerkleFD that's read/writable.
		parentLowerMerkleFD, err := dentryFromFD(t, fd).parent.openLowerMerkleAt(ctx, vfsObj, linux.O_RDWR, linux.ModeRegular)
		if err != nil {
			t.Fatalf("OpenAt: %v", err)
		}

		// Flip a random bit in the parent Merkle tree file.
		// This parent directory contains only one child, so any random
		// modification in the parent Merkle tree should cause verification
		// failure when opening the child file.
		sizeString, err := parentLowerMerkleFD.GetXattr(ctx, &vfs.GetXattrOptions{
			Name: childrenOffsetXattr,
			Size: sizeOfStringInt32,
		})
		if err != nil {
			t.Fatalf("parentLowerMerkleFD.GetXattr: %v", err)
		}
		parentMerkleSize, err := strconv.Atoi(sizeString)
		if err != nil {
			t.Fatalf("Failed convert size to int: %v", err)
		}
		if err := flipRandomBit(ctx, parentLowerMerkleFD, parentMerkleSize); err != nil {
			t.Fatalf("flipRandomBit: %v", err)
		}

		parentLowerMerkleFD.DecRef(ctx)

		// Ensure reopening the verity enabled file fails.
		if _, err = openVerityAt(ctx, vfsObj, root, filename, linux.O_RDONLY, linux.ModeRegular); err == nil {
			t.Errorf("OpenAt file with modified parent Merkle succeeded")
		}
	}
}

// TestUnmodifiedStatSucceeds ensures that stat of an untouched verity file
// succeeds after enabling verity for it.
func TestUnmodifiedStatSucceeds(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file and confirm that stat succeeds.
		enableVerity(ctx, t, fd)
		if _, err := fd.Stat(ctx, vfs.StatOptions{}); err != nil {
			t.Errorf("fd.Stat: %v", err)
		}
	}
}

// TestModifiedStatFails checks that getting stat for a file with modified stat
// should fail.
func TestModifiedStatFails(t *testing.T) {
	for _, alg := range hashAlgs {
		vfsObj, root, ctx, err := newVerityRoot(t, alg)
		if err != nil {
			t.Fatalf("newVerityRoot: %v", err)
		}

		filename := "verity-test-file"
		fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
		if err != nil {
			t.Fatalf("newFileFD: %v", err)
		}

		// Enable verity on the file.
		enableVerity(ctx, t, fd)

		lowerFD := fd.Impl().(*fileDescription).lowerFD
		// Change the stat of the underlying file, and check that stat fails.
		if err := lowerFD.SetStat(ctx, vfs.SetStatOptions{
			Stat: linux.Statx{
				Mask: uint32(linux.STATX_MODE),
				Mode: 0777,
			},
		}); err != nil {
			t.Fatalf("lowerFD.SetStat: %v", err)
		}

		if _, err := fd.Stat(ctx, vfs.StatOptions{}); err == nil {
			t.Errorf("fd.Stat succeeded when it should fail")
		}
	}
}

// TestOpenDeletedFileFails ensures that opening a deleted verity enabled file
// and/or the corresponding Merkle tree file fails with the verity error.
func TestOpenDeletedFileFails(t *testing.T) {
	testCases := []struct {
		name string
		// The original file is removed if changeFile is true.
		changeFile bool
		// The Merkle tree file is removed if changeMerkleFile is true.
		changeMerkleFile bool
	}{
		{
			name:             "FileOnly",
			changeFile:       true,
			changeMerkleFile: false,
		},
		{
			name:             "MerkleOnly",
			changeFile:       false,
			changeMerkleFile: true,
		},
		{
			name:             "FileAndMerkle",
			changeFile:       true,
			changeMerkleFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vfsObj, root, ctx, err := newVerityRoot(t, SHA256)
			if err != nil {
				t.Fatalf("newVerityRoot: %v", err)
			}

			filename := "verity-test-file"
			fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
			if err != nil {
				t.Fatalf("newFileFD: %v", err)
			}

			// Enable verity on the file.
			enableVerity(ctx, t, fd)

			if tc.changeFile {
				if err := dentryFromVD(t, root).unlinkLowerAt(ctx, vfsObj, filename); err != nil {
					t.Fatalf("UnlinkAt: %v", err)
				}
			}
			if tc.changeMerkleFile {
				if err := dentryFromVD(t, root).unlinkLowerMerkleAt(ctx, vfsObj, filename); err != nil {
					t.Fatalf("UnlinkAt: %v", err)
				}
			}

			// Ensure reopening the verity enabled file fails.
			if _, err = openVerityAt(ctx, vfsObj, root, filename, linux.O_RDONLY, linux.ModeRegular); err != syserror.EIO {
				t.Errorf("got OpenAt error: %v, expected EIO", err)
			}
		})
	}
}

// TestOpenRenamedFileFails ensures that opening a renamed verity enabled file
// and/or the corresponding Merkle tree file fails with the verity error.
func TestOpenRenamedFileFails(t *testing.T) {
	testCases := []struct {
		name string
		// The original file is renamed if changeFile is true.
		changeFile bool
		// The Merkle tree file is renamed if changeMerkleFile is true.
		changeMerkleFile bool
	}{
		{
			name:             "FileOnly",
			changeFile:       true,
			changeMerkleFile: false,
		},
		{
			name:             "MerkleOnly",
			changeFile:       false,
			changeMerkleFile: true,
		},
		{
			name:             "FileAndMerkle",
			changeFile:       true,
			changeMerkleFile: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vfsObj, root, ctx, err := newVerityRoot(t, SHA256)
			if err != nil {
				t.Fatalf("newVerityRoot: %v", err)
			}

			filename := "verity-test-file"
			fd, _, err := newFileFD(ctx, t, vfsObj, root, filename, 0644)
			if err != nil {
				t.Fatalf("newFileFD: %v", err)
			}

			// Enable verity on the file.
			enableVerity(ctx, t, fd)

			newFilename := "renamed-test-file"
			if tc.changeFile {
				if err := dentryFromVD(t, root).renameLowerAt(ctx, vfsObj, filename, newFilename); err != nil {
					t.Fatalf("RenameAt: %v", err)
				}
			}
			if tc.changeMerkleFile {
				if err := dentryFromVD(t, root).renameLowerMerkleAt(ctx, vfsObj, filename, newFilename); err != nil {
					t.Fatalf("UnlinkAt: %v", err)
				}
			}

			// Ensure reopening the verity enabled file fails.
			if _, err = openVerityAt(ctx, vfsObj, root, filename, linux.O_RDONLY, linux.ModeRegular); err != syserror.EIO {
				t.Errorf("got OpenAt error: %v, expected EIO", err)
			}
		})
	}
}
