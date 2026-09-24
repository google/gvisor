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

package vfs

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Permission bit shorthands.
const (
	permR   = linux.ACL_READ
	permW   = linux.ACL_WRITE
	permX   = linux.ACL_EXECUTE
	permRW  = permR | permW
	permRX  = permR | permX
	permRWX = permR | permW | permX
)

const aclUndef = uint32(linux.ACL_UNDEFINED_ID)

// aclEntry builds a single on-wire POSIX ACL entry.
func aclEntry(tag, perm uint16, id uint32) linux.PosixACLXattrEntry {
	return linux.PosixACLXattrEntry{Tag: tag, Perm: perm, ID: id}
}

// marshalACLXattr builds the userspace representation of a
// POSIX ACL.
func marshalACLXattr(version uint32, entries ...linux.PosixACLXattrEntry) []byte {
	x := linux.PosixACLXattr{Version: version, Entries: entries}
	buf := make([]byte, x.SizeBytes())
	x.MarshalBytes(buf)
	return buf
}

// aclMask returns p as a pointer.
func aclMask(p AccessTypes) *AccessTypes { return &p }

// aclEqual reports whether two PosixACLs are equal.
func aclEqual(a, b PosixACL) bool {
	if a.UGOPerms != b.UGOPerms {
		return false
	}
	if (a.Mask == nil) != (b.Mask == nil) {
		return false
	}
	if a.Mask != nil && *a.Mask != *b.Mask {
		return false
	}
	if len(a.Users) != len(b.Users) {
		return false
	}
	for i := range a.Users {
		if a.Users[i] != b.Users[i] {
			return false
		}
	}
	if len(a.Groups) != len(b.Groups) {
		return false
	}
	for i := range a.Groups {
		if a.Groups[i] != b.Groups[i] {
			return false
		}
	}
	return true
}

func TestParsePosixACL(t *testing.T) {
	ns := auth.NewRootUserNamespace()
	for _, tc := range []struct {
		name string
		src  []byte
		// wantErr is the expected error; nil means success, in which case want
		// is compared against the parsed result.
		wantErr *errors.Error
		want    *PosixACL
	}{
		{
			name: "minimal",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			want: &PosixACL{UGOPerms: 0o644},
		},
		{
			name: "named user with mask",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_USER, permR, 982),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_MASK, permRW, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			want: &PosixACL{
				UGOPerms: 0o644,
				Mask:     aclMask(permRW),
				Users:    []ACLUser{{UID: 982, Perms: permR}},
			},
		},
		{
			name: "named group with mask",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRWX, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permRX, aclUndef),
				aclEntry(linux.ACL_GROUP, permRWX, 100),
				aclEntry(linux.ACL_MASK, permRX, aclUndef),
				aclEntry(linux.ACL_OTHER, 0, aclUndef),
			),
			want: &PosixACL{
				UGOPerms: 0o750,
				Mask:     aclMask(permRX),
				Groups:   []ACLGroup{{GID: 100, Perms: permRWX}},
			},
		},
		{
			name: "duplicate named user",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_USER, permR, 982),
				aclEntry(linux.ACL_USER, permR|permW, 982),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_MASK, permRW, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			want: &PosixACL{
				UGOPerms: 0o644,
				Mask:     aclMask(permRW),
				Users: []ACLUser{
					{UID: 982, Perms: permR},
					{UID: 982, Perms: permR | permW},
				},
			},
		},
		{
			name:    "too short for header",
			src:     []byte{0x02, 0x00, 0x00},
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "unsupported version",
			src: marshalACLXattr(1,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EOPNOTSUPP,
		},
		{
			name: "trailing partial entry",
			src: append(marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			), 0xff),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "missing USER_OBJ",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "missing GROUP_OBJ",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "missing OTHER",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "duplicate USER_OBJ",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_USER_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "duplicate MASK",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_USER, permR, 982),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_MASK, permRW, aclUndef),
				aclEntry(linux.ACL_MASK, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "named user without mask",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_USER, permR, 982),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "invalid permission bits",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, 0x08, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "unknown tag",
			src: marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
				aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
				aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
				aclEntry(linux.ACL_OTHER, permR, aclUndef),
				aclEntry(0x40, permR, aclUndef),
			),
			wantErr: linuxerr.EINVAL,
		},
		{
			name: "empty string",
			src:  []byte{},
			want: nil,
		},
		{
			name: "header only",
			src:  marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION),
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePosixACL(tc.src, ns)
			if tc.wantErr != nil {
				if !linuxerr.Equals(tc.wantErr, err) {
					t.Fatalf("ParsePosixACL: %v: got error %v, want %v", tc.name, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePosixACL: %v: unexpected error: %v", tc.name, err)
			}
			if ((got == nil) != (tc.want == nil)) || (got != nil && !aclEqual(*got, *tc.want)) {
				t.Errorf("ParsePosixACL: %v: got %+v, want %+v", tc.name, got, tc.want)
			}
		})
	}
}

func TestSerializePosixACL(t *testing.T) {
	ns := auth.NewRootUserNamespace()
	acl := PosixACL{
		UGOPerms: 0o644,
		Mask:     aclMask(permRW),
		Users:    []ACLUser{{UID: 982, Perms: permR}},
	}
	// Serialize emits entries in canonical order: USER_OBJ, named users,
	// GROUP_OBJ, named groups, MASK, OTHER; base entries carry
	// ACL_UNDEFINED_ID, matching fs/posix_acl.c:posix_acl_to_xattr().
	want := marshalACLXattr(linux.POSIX_ACL_XATTR_VERSION,
		aclEntry(linux.ACL_USER_OBJ, permRW, aclUndef),
		aclEntry(linux.ACL_USER, permR, 982),
		aclEntry(linux.ACL_GROUP_OBJ, permR, aclUndef),
		aclEntry(linux.ACL_MASK, permRW, aclUndef),
		aclEntry(linux.ACL_OTHER, permR, aclUndef),
	)
	if got := acl.Serialize(ns); !bytes.Equal(got, want) {
		t.Errorf("Serialize = %x, want %x", got, want)
	}
}

func TestPosixACLRoundTrip(t *testing.T) {
	ns := auth.NewRootUserNamespace()
	for _, acl := range []PosixACL{
		{UGOPerms: 0o640},
		{UGOPerms: 0o644, Mask: aclMask(permRWX), Users: []ACLUser{{UID: 982, Perms: permR}}},
		{UGOPerms: 0o600, Mask: aclMask(permRX), Groups: []ACLGroup{{GID: 100, Perms: permRX}}},
		{
			UGOPerms: 0o750,
			Mask:     aclMask(permRW),
			Users:    []ACLUser{{UID: 1000, Perms: permRWX}, {UID: 1001, Perms: permR}},
			Groups:   []ACLGroup{{GID: 50, Perms: permR}},
		},
	} {
		got, err := ParsePosixACL(acl.Serialize(ns), ns)
		if err != nil {
			t.Fatalf("round-trip ParsePosixACL(Serialize(%+v)): unexpected error: %v", acl, err)
		}
		if !aclEqual(*got, acl) {
			t.Errorf("round-trip: got %+v, want %+v", got, acl)
		}
	}
}

// TestPosixACLModeEquivalence checks Mode(), which reports the userspace-facing
// mode bits (mask surfaced as the group bits) and whether the ACL is fully
// representable by the mode alone.
func TestPosixACLModeEquivalence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		acl       PosixACL
		wantMode  uint16
		wantEquiv bool
	}{
		{
			name:      "minimal is equivalent",
			acl:       PosixACL{UGOPerms: 0o751},
			wantMode:  0o751,
			wantEquiv: true,
		},
		{
			name:      "mask surfaces as group bits",
			acl:       PosixACL{UGOPerms: 0o644, Mask: aclMask(permRWX)},
			wantMode:  0o674,
			wantEquiv: false,
		},
		{
			name:      "named user is not equivalent",
			acl:       PosixACL{UGOPerms: 0o644, Mask: aclMask(permR), Users: []ACLUser{{UID: 1, Perms: permR}}},
			wantMode:  0o644,
			wantEquiv: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode, equiv := tc.acl.Mode()
			if mode != tc.wantMode || equiv != tc.wantEquiv {
				t.Errorf("Mode() = (%#o, %t), want (%#o, %t)", mode, equiv, tc.wantMode, tc.wantEquiv)
			}
		})
	}
}
