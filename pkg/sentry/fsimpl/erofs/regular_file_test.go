// Copyright 2026 The gVisor Authors.
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

package erofs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const testFileNid = 127

// newTestImage returns a 10-block image whose root directory contains the
// regular file "file", described by the compact inode file.
func newTestImage(features uint32, file erofs.InodeCompact) []byte {
	const rootNid = 96
	data := make([]byte, 10*hostarch.PageSize)
	sb := erofs.SuperBlock{Magic: erofs.SuperBlockMagicV1, BlockSizeBits: 12, RootNid: rootNid, Blocks: 10, FeatureIncompat: features}
	sb.MarshalUnsafe(data[erofs.SuperBlockOffset:])
	rootOff := rootNid << erofs.InodeSlotBits
	root := erofs.InodeCompact{Format: erofs.InodeDataLayoutFlatInline << erofs.InodeDataLayoutBit, Mode: linux.S_IFDIR | 0755, Size: 16, Nlink: 2}
	root.MarshalUnsafe(data[rootOff:])
	dirent := erofs.Dirent{NidLow: testFileNid, NameOff: erofs.DirentSize, FileType: 1}
	dirent.MarshalUnsafe(data[rootOff+erofs.InodeCompactSize:])
	copy(data[rootOff+erofs.InodeCompactSize+erofs.DirentSize:], "file")
	file.Mode = linux.S_IFREG | 0444
	file.Nlink = 1
	file.MarshalUnsafe(data[testFileNid<<erofs.InodeSlotBits:])
	return data
}

// openTestFile mounts image and opens its file "file".
func openTestFile(t *testing.T, image []byte) *regularFileFD {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "image")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(image); err != nil {
		f.Close()
		t.Fatal(err)
	}
	imageFD, err := unix.Dup(int(f.Fd()))
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx := contexttest.Context(t)
	mf := pgalloc.MemoryFileFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	vfsObj.MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	mntns, err := vfsObj.NewMountNamespace(ctx, auth.CredentialsFromContext(ctx), "", Name, &vfs.MountOptions{GetFilesystemOptions: vfs.GetFilesystemOptions{Data: fmt.Sprintf("ifd=%d", imageFD)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootVD := mntns.Root(ctx)
	vfsfd, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("file")}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vfsfd.DecRef(ctx); rootVD.DecRef(ctx); mntns.DecRef(ctx); vfsObj.Release(ctx); mf.Destroy() })
	return vfsfd.Impl().(*regularFileFD)
}

func TestReadSpansInlineTail(t *testing.T) {
	const size = hostarch.PageSize + 904
	for _, useRead := range []bool{false, true} {
		t.Run(fmt.Sprintf("read=%t", useRead), func(t *testing.T) {
			data := newTestImage(0, erofs.InodeCompact{Format: erofs.InodeDataLayoutFlatInline << erofs.InodeDataLayoutBit, Size: size, RawBlockAddr: 4})
			want := make([]byte, size)
			for i := range want {
				want[i] = byte(i % 251)
			}
			copy(data[4*hostarch.PageSize:], want[:hostarch.PageSize])
			copy(data[testFileNid<<erofs.InodeSlotBits+erofs.InodeCompactSize:], want[hostarch.PageSize:])
			fd := openTestFile(t, data)
			fd.inode().fs.useReadForIO = useRead
			got := make([]byte, 2*hostarch.PageSize)
			n, err := fd.PRead(contexttest.Context(t), usermem.BytesIOSequence(got), 0, vfs.ReadOptions{})
			if err != nil && err != io.EOF {
				t.Fatalf("PRead: %v", err)
			}
			if n != size || !bytes.Equal(got[:n], want) {
				t.Fatalf("PRead returned %d bytes, want all %d", n, size)
			}
		})
	}
}
