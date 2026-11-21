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
	"encoding/binary"
	"slices"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const (
	testXattrIndexUser      = 1
	testXattrIndexACLAccess = 2
	testXattrIndexTrusted   = 4
	testXattrIndexSecurity  = 6
)

type testXattr struct {
	index uint8
	name  string
	value string
}

// newXattrTestImage returns an image whose file's xattr area holds entries.
func newXattrTestImage(entries []testXattr) []byte {
	data := newTestImage(0, erofs.InodeCompact{Format: erofs.InodeDataLayoutFlatPlain << erofs.InodeDataLayoutBit, RawBlockAddr: 4})
	inodeOff := testFileNid << erofs.InodeSlotBits
	off := inodeOff + erofs.InodeCompactSize + 12
	for _, x := range entries {
		data[off] = uint8(len(x.name))
		data[off+1] = x.index
		binary.LittleEndian.PutUint16(data[off+2:], uint16(len(x.value)))
		copy(data[off+4:], x.name)
		copy(data[off+4+len(x.name):], x.value)
		off += (4 + len(x.name) + len(x.value) + 3) &^ 3
	}
	var ino erofs.InodeCompact
	ino.UnmarshalUnsafe(data[inodeOff:])
	ino.XattrCount = uint16((off-inodeOff-erofs.InodeCompactSize-12)/4 + 1)
	ino.MarshalUnsafe(data[inodeOff:])
	return data
}

// vfsCapData returns a security.capability value that grants CAP_NET_RAW.
func vfsCapData(revision uint32) string {
	size := linux.XATTR_CAPS_SZ_2
	if revision == linux.VFS_CAP_REVISION_3 {
		size = linux.XATTR_CAPS_SZ_3
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, revision|linux.VFS_CAP_FLAGS_EFFECTIVE)
	binary.LittleEndian.PutUint32(b[4:], 1<<linux.CAP_NET_RAW)
	return string(b)
}

func TestXattrs(t *testing.T) {
	ctx, vfsObj, rootVD := mountTestImage(t, newXattrTestImage([]testXattr{
		{index: testXattrIndexUser, name: "u", value: "user-value"},
		{index: testXattrIndexTrusted, name: "t", value: "trusted-value"},
		{index: testXattrIndexSecurity, name: "capability", value: vfsCapData(linux.VFS_CAP_REVISION_3)},
	}))
	pop := &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("file")}
	userns := auth.CredentialsFromContext(ctx).UserNamespace
	root := auth.NewRootCredentials(userns)
	user := auth.NewUserCredentials(1000, 1000, nil, nil, userns)
	// A v3 capability whose root ID is the namespace root reads back as v2.
	capV2 := vfsCapData(linux.VFS_CAP_REVISION_2)

	for _, tc := range []struct {
		name    string
		creds   *auth.Credentials
		names   []string
		trusted *errors.Error
	}{
		{
			name:  "root",
			creds: root,
			names: []string{"user.u", "trusted.t", "security.capability"},
		},
		{
			name:    "user",
			creds:   user,
			names:   []string{"user.u", "security.capability"},
			trusted: linuxerr.ENODATA,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if names, err := vfsObj.ListXattrAt(ctx, tc.creds, pop, 0); err != nil || !slices.Equal(names, tc.names) {
				t.Errorf("ListXattrAt() = %q, %v, want %q", names, err, tc.names)
			}
			for _, x := range []struct {
				name  string
				size  uint64
				value string
				err   *errors.Error
			}{
				{name: "user.u", value: "user-value"},
				{name: "trusted.t", value: "trusted-value", err: tc.trusted},
				{name: "security.capability", value: capV2},
				{name: "security.capability", size: uint64(len(capV2)), value: capV2},
				{name: "security.capability", size: uint64(len(capV2)) - 1, err: linuxerr.ERANGE},
				{name: "user.missing", err: linuxerr.ENODATA},
				{name: linux.XATTR_NAME_POSIX_ACL_ACCESS, err: linuxerr.ENODATA},
				{name: "system.other", err: linuxerr.EOPNOTSUPP},
			} {
				value, err := vfsObj.GetXattrAt(ctx, tc.creds, pop, &vfs.GetXattrOptions{Name: x.name, Size: x.size})
				if x.err != nil {
					if !linuxerr.Equals(x.err, err) {
						t.Errorf("GetXattrAt(%q, size=%d) error = %v, want %v", x.name, x.size, err, x.err)
					}
				} else if err != nil || value != x.value {
					t.Errorf("GetXattrAt(%q, size=%d) = %q, %v, want %q", x.name, x.size, value, err, x.value)
				}
			}
		})
	}

	t.Run("fd", func(t *testing.T) {
		vfsfd, err := vfsObj.OpenAt(ctx, root, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			t.Fatal(err)
		}
		defer vfsfd.DecRef(ctx)
		fd := vfsfd.Impl().(*regularFileFD)
		rootCtx := auth.ContextWithCredentials(ctx, root)
		want := []string{"user.u", "trusted.t", "security.capability"}
		if names, err := fd.ListXattr(rootCtx, 0); err != nil || !slices.Equal(names, want) {
			t.Errorf("ListXattr() = %q, %v, want %q", names, err, want)
		}
		if value, err := fd.GetXattr(rootCtx, vfs.GetXattrOptions{Name: "trusted.t"}); err != nil || value != "trusted-value" {
			t.Errorf("GetXattr(trusted.t) = %q, %v, want %q", value, err, "trusted-value")
		}
		if value, err := fd.GetXattr(rootCtx, vfs.GetXattrOptions{Name: "security.capability"}); err != nil || value != capV2 {
			t.Errorf("GetXattr(security.capability) = %q, %v, want %q", value, err, capV2)
		}
		userCtx := auth.ContextWithCredentials(ctx, user)
		want = []string{"user.u", "security.capability"}
		if names, err := fd.ListXattr(userCtx, 0); err != nil || !slices.Equal(names, want) {
			t.Errorf("ListXattr() as user = %q, %v, want %q", names, err, want)
		}
		if _, err := fd.GetXattr(userCtx, vfs.GetXattrOptions{Name: "trusted.t"}); !linuxerr.Equals(linuxerr.ENODATA, err) {
			t.Errorf("GetXattr(trusted.t) as user error = %v, want ENODATA", err)
		}
		if _, err := fd.GetXattr(userCtx, vfs.GetXattrOptions{Name: "security.capability", Size: uint64(len(capV2)) - 1}); !linuxerr.Equals(linuxerr.ERANGE, err) {
			t.Errorf("GetXattr(security.capability, size=%d) as user error = %v, want ERANGE", len(capV2)-1, err)
		}
	})
}

func TestUserXattrsNeedReadPermission(t *testing.T) {
	capV2 := vfsCapData(linux.VFS_CAP_REVISION_2)
	data := newXattrTestImage([]testXattr{
		{index: testXattrIndexUser, name: "u", value: "user-value"},
		{index: testXattrIndexSecurity, name: "capability", value: capV2},
	})
	inodeOff := testFileNid << erofs.InodeSlotBits
	var ino erofs.InodeCompact
	ino.UnmarshalUnsafe(data[inodeOff:])
	ino.Mode = linux.S_IFREG | 0400
	ino.MarshalUnsafe(data[inodeOff:])
	ctx, vfsObj, rootVD := mountTestImage(t, data)
	pop := &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("file")}
	userns := auth.CredentialsFromContext(ctx).UserNamespace
	root := auth.NewRootCredentials(userns)
	user := auth.NewUserCredentials(1000, 1000, nil, nil, userns)

	if _, err := vfsObj.GetXattrAt(ctx, user, pop, &vfs.GetXattrOptions{Name: "user.u"}); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Errorf("GetXattrAt(user.u) as user error = %v, want EACCES", err)
	}
	if value, err := vfsObj.GetXattrAt(ctx, user, pop, &vfs.GetXattrOptions{Name: "security.capability"}); err != nil || value != capV2 {
		t.Errorf("GetXattrAt(security.capability) as user = %q, %v, want %q", value, err, capV2)
	}
	if value, err := vfsObj.GetXattrAt(ctx, root, pop, &vfs.GetXattrOptions{Name: "user.u"}); err != nil || value != "user-value" {
		t.Errorf("GetXattrAt(user.u) as root = %q, %v, want %q", value, err, "user-value")
	}
}

func TestXattrsWithoutEntries(t *testing.T) {
	ctx, vfsObj, rootVD := mountTestImage(t, newXattrTestImage(nil))
	creds := auth.CredentialsFromContext(ctx)
	pop := &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("file")}
	vfsfd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt() failed: %v", err)
	}
	vfsfd.DecRef(ctx)
	if _, err := vfsObj.GetXattrAt(ctx, creds, pop, &vfs.GetXattrOptions{Name: "user.u"}); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Errorf("GetXattrAt() error = %v, want EOPNOTSUPP", err)
	}
}

func TestPosixACLRejected(t *testing.T) {
	acl := []byte{2, 0, 0, 0}
	ctx, vfsObj, rootVD := mountTestImage(t, newXattrTestImage([]testXattr{
		{index: testXattrIndexACLAccess, value: string(acl)},
	}))
	pop := &vfs.PathOperation{Root: rootVD, Start: rootVD, Path: fspath.Parse("file")}
	if _, err := vfsObj.OpenAt(ctx, auth.CredentialsFromContext(ctx), pop, &vfs.OpenOptions{Flags: linux.O_RDONLY}); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) {
		t.Errorf("OpenAt() error = %v, want EOPNOTSUPP", err)
	}
}
