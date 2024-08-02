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

package user

import (
	"fmt"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// createEtcFile creates /etc/<file> with the given contents and mode. If
// mode is empty, then no file will be created. If mode is not a regular file
// mode, then contents is ignored.
func createEtcFile(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, contents string, mode linux.FileMode, filePath string) error {
	pop := vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("etc"),
	}
	if err := vfsObj.MkdirAt(ctx, creds, &pop, &vfs.MkdirOptions{
		Mode: 0755,
	}); err != nil && err != linuxerr.EEXIST { // Ignore error if it already exists.
		return fmt.Errorf("failed to create directory etc: %v", err)
	}

	pop = vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(filePath),
	}
	switch mode.FileType() {
	case 0:
		// Don't create anything.
		return nil
	case linux.S_IFREG:
		fd, err := vfsObj.OpenAt(ctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: mode})
		if err != nil {
			return err
		}
		defer fd.DecRef(ctx)
		_, err = fd.Write(ctx, usermem.BytesIOSequence([]byte(contents)), vfs.WriteOptions{})
		return err
	case linux.S_IFDIR:
		return vfsObj.MkdirAt(ctx, creds, &pop, &vfs.MkdirOptions{Mode: mode})
	case linux.S_IFIFO:
		return vfsObj.MknodAt(ctx, creds, &pop, &vfs.MknodOptions{Mode: mode})
	default:
		return fmt.Errorf("unknown file type %x", mode.FileType())
	}
}

// TestGetExecUserHome tests the getExecUserHome function.
func TestGetExecUserHome(t *testing.T) {
	tests := map[string]struct {
		uid            auth.KUID
		passwdContents string
		passwdMode     linux.FileMode
		expected       string
	}{
		"success": {
			uid:            1000,
			passwdContents: "adin::1000:1111::/home/adin:/bin/sh",
			passwdMode:     linux.S_IFREG | 0666,
			expected:       "/home/adin",
		},
		"no_perms": {
			uid:            1000,
			passwdContents: "adin::1000:1111::/home/adin:/bin/sh",
			passwdMode:     linux.S_IFREG,
			expected:       "/",
		},
		"no_passwd": {
			uid:      1000,
			expected: "/",
		},
		"directory": {
			uid:        1000,
			passwdMode: linux.S_IFDIR | 0666,
			expected:   "/",
		},
		// Currently we don't allow named pipes.
		"named_pipe": {
			uid:        1000,
			passwdMode: linux.S_IFIFO | 0666,
			expected:   "/",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				t.Fatalf("VFS init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
				AllowUserMount: true,
			})
			mns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
			if err != nil {
				t.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mns.DecRef(ctx)
			root := mns.Root(ctx)
			defer root.DecRef(ctx)

			if err := createEtcFile(ctx, &vfsObj, creds, root, tc.passwdContents, tc.passwdMode, "/etc/passwd"); err != nil {
				t.Fatalf("createEtcPasswd failed: %v", err)
			}

			got, err := getExecUserHome(ctx, mns, tc.uid)
			if err != nil {
				t.Fatalf("failed to get user home: %v", err)
			}

			if got != tc.expected {
				t.Fatalf("expected %v, got: %v", tc.expected, got)
			}
		})
	}
}

// TestFindHomeInPasswd tests the findHomeInPasswd function's passwd file parsing.
func TestFindHomeInPasswd(t *testing.T) {
	tests := map[string]struct {
		uid      uint32
		passwd   string
		expected string
		def      string
	}{
		"empty": {
			uid:      1000,
			passwd:   "",
			expected: "/",
			def:      "/",
		},
		"whitespace": {
			uid:      1000,
			passwd:   "       ",
			expected: "/",
			def:      "/",
		},
		"full": {
			uid:      1000,
			passwd:   "adin::1000:1111::/home/adin:/bin/sh",
			expected: "/home/adin",
			def:      "/",
		},
		// For better or worse, this is how runc works.
		"partial": {
			uid:      1000,
			passwd:   "adin::1000:1111:",
			expected: "",
			def:      "/",
		},
		"multiple": {
			uid:      1001,
			passwd:   "adin::1000:1111::/home/adin:/bin/sh\nian::1001:1111::/home/ian:/bin/sh",
			expected: "/home/ian",
			def:      "/",
		},
		"duplicate": {
			uid:      1000,
			passwd:   "adin::1000:1111::/home/adin:/bin/sh\nian::1000:1111::/home/ian:/bin/sh",
			expected: "/home/adin",
			def:      "/",
		},
		"empty_lines": {
			uid:      1001,
			passwd:   "adin::1000:1111::/home/adin:/bin/sh\n\n\nian::1001:1111::/home/ian:/bin/sh",
			expected: "/home/ian",
			def:      "/",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := findHomeInPasswd(tc.uid, strings.NewReader(tc.passwd), tc.def)
			if err != nil {
				t.Fatalf("error parsing passwd: %v", err)
			}
			if tc.expected != got {
				t.Fatalf("expected %v, got: %v", tc.expected, got)
			}
		})
	}
}

// TestGetExecUIDGIDFromUser tests the GetExecUIDGIDFromUser function.
func TestGetExecUIDGIDFromUser(t *testing.T) {
	tests := map[string]struct {
		user           string
		passwdContents string
		groupContents  string
		fileMode       linux.FileMode
		expectedUID    auth.KUID
		expectedGID    auth.KGID
	}{
		"user0": {
			user:           "user0",
			passwdContents: "user0::1000:1111:&:/home/user0:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"uid_only": {
			user:           "1000",
			passwdContents: "user0::1000:1111:&:/home/user0:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"uid_and_gid": {
			user:           "1000:1111",
			passwdContents: "user0::1000:1111:&:/home/user0:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"uid_and_wrong_gid": {
			user:           "1000:1112",
			passwdContents: "user0::1000:1111:&:/home/user0:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1112,
		},
		"user_missing": {
			user:           "user1",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"multiple_user_no_match": {
			user:           "user1",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"multiple_user_many_match": {
			user:           "user1",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser1::1002:1112::/home/user1:/bin/sh\nuser1::1003:1113::/home/user1:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1002,
			expectedGID:    1112,
		},
		"invalid_file": {
			user:           "user1",
			passwdContents: "user0:1000:1111::/home/user0:/bin/sh\nuser1::1001:1111::/home/user1:/bin/sh\nuser2::/home/user2:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"empty_file": {
			user:           "user1",
			passwdContents: "",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"empty_user": {
			user:           "",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"with_comments": {
			user:           "user0",
			passwdContents: "#This is a comment\nuser0::1000:1111:&:/home/user0:/bin/sh\nuser2::1002:1112:&:/home/user2:/bin/sh\nuser3:&:1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"with_comments_mid_file": {
			user:           "user0",
			passwdContents: "user0::1000:1111:&:/home/user0:/bin/sh\nuser2::1002:1112:&:/home/user2:/bin/sh\n#This is a comment\n\nuser3:&:1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"empty_gecos": {
			user:           "user0",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1111,
		},
		"numeric_user_empty_file": {
			user:           "1000",
			passwdContents: "",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    0,
		},
		"numeric_user_does_not_match": {
			user:           "1005",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1005,
			expectedGID:    0,
		},
		"numeric_user_numeric_group_does_not_match": {
			user:           "1005:1006",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1005,
			expectedGID:    1006,
		},
		"numeric_user_string_group_does_not_match": {
			user:           "1005:group10",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1005,
			expectedGID:    0,
		},
		"string_user_numeric_group_does_not_match": {
			user:           "user10:1006",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    1006,
		},
		"string_user_string_group_does_not_match": {
			user:           "user10:group10",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    0,
			expectedGID:    0,
		},
		"group_does_not_match_but_exist": {
			user:           "user0:group2",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "group1:x:1110:user0,user1,user2\ngroup2:x:1112:user0,user1,user2",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1112,
		},
		"group_does_not_match_and_does_not_exist": {
			user:           "user0:group10",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "group1:x:1110:user0,user1,user2\ngroup2:x:1112:user0,user1,user2",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    0,
		},
		"numeric_group_does_not_match_and_does_not_exist": {
			user:           "user0:1113",
			passwdContents: "user0::1000:1111::/home/user0:/bin/sh\nuser2::1002:1112::/home/user2:/bin/sh\nuser3::1003:1113::/home/user3:/bin/sh",
			groupContents:  "group1:x:1110:user0,user1,user2\ngroup2:x:1112:user0,user1,user2",
			fileMode:       linux.S_IFREG | 0666,
			expectedUID:    1000,
			expectedGID:    1113,
		}}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			creds := auth.CredentialsFromContext(ctx)

			// Create VFS.
			vfsObj := vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				t.Fatalf("VFS init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
				AllowUserMount: true,
			})
			mns, err := vfsObj.NewMountNamespace(ctx, creds, "", "tmpfs", &vfs.MountOptions{}, nil)
			if err != nil {
				t.Fatalf("failed to create tmpfs root mount: %v", err)
			}
			defer mns.DecRef(ctx)
			root := mns.Root(ctx)
			defer root.DecRef(ctx)

			if err := createEtcFile(ctx, &vfsObj, creds, root, tc.passwdContents, tc.fileMode, "etc/passwd"); err != nil {
				t.Fatalf("createEtcFile failed: %v", err)
			}
			if err := createEtcFile(ctx, &vfsObj, creds, root, tc.groupContents, tc.fileMode, "/etc/group"); err != nil {
				t.Fatalf("createEtcFile failed: %v", err)
			}

			gotUID, gotGID := GetExecUIDGIDFromUser(ctx, mns, tc.user)
			if gotUID != tc.expectedUID {
				t.Fatalf("expectedUID %v, gotUID: %v", tc.expectedUID, gotUID)
			}
			if gotGID != tc.expectedGID {
				t.Fatalf("expectedGID %v, gotGID: %v", tc.expectedGID, gotGID)
			}
		})
	}
}
