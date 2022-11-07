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
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/usermem"
)

// createEtcPasswd creates /etc/passwd with the given contents and mode. If
// mode is empty, then no file will be created. If mode is not a regular file
// mode, then contents is ignored.
func createEtcPasswd(ctx context.Context, root *fs.Dirent, contents string, mode linux.FileMode) error {
	if err := root.CreateDirectory(ctx, root, "etc", fs.FilePermsFromMode(0755)); err != nil {
		return err
	}
	etc, err := root.Walk(ctx, root, "etc")
	if err != nil {
		return err
	}
	defer etc.DecRef(ctx)
	switch mode.FileType() {
	case 0:
		// Don't create anything.
		return nil
	case linux.S_IFREG:
		passwd, err := etc.Create(ctx, root, "passwd", fs.FileFlags{Write: true}, fs.FilePermsFromMode(mode))
		if err != nil {
			return err
		}
		defer passwd.DecRef(ctx)
		if _, err := passwd.Writev(ctx, usermem.BytesIOSequence([]byte(contents))); err != nil {
			return err
		}
		return nil
	case linux.S_IFDIR:
		return etc.CreateDirectory(ctx, root, "passwd", fs.FilePermsFromMode(mode))
	case linux.S_IFIFO:
		return etc.CreateFifo(ctx, root, "passwd", fs.FilePermsFromMode(mode))
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
			msrc := fs.NewPseudoMountSource(ctx)
			rootInode, err := tmpfs.NewDir(ctx, nil, fs.RootOwner, fs.FilePermsFromMode(0777), msrc, nil /* parent */)
			if err != nil {
				t.Fatalf("tmpfs.NewDir failed: %v", err)
			}

			mns, err := fs.NewMountNamespace(ctx, rootInode)
			if err != nil {
				t.Fatalf("NewMountNamespace failed: %v", err)
			}
			defer mns.DecRef(ctx)
			root := mns.Root()
			defer root.DecRef(ctx)
			ctx = fs.WithRoot(ctx, root)

			if err := createEtcPasswd(ctx, root, tc.passwdContents, tc.passwdMode); err != nil {
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
