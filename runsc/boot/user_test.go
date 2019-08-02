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

package boot

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

func setupTempDir() (string, error) {
	tmpDir, err := ioutil.TempDir(os.TempDir(), "exec-user-test")
	if err != nil {
		return "", err
	}
	return tmpDir, nil
}

func setupPasswd(contents string, perms os.FileMode) func() (string, error) {
	return func() (string, error) {
		tmpDir, err := setupTempDir()
		if err != nil {
			return "", err
		}

		if err := os.Mkdir(filepath.Join(tmpDir, "etc"), 0777); err != nil {
			return "", err
		}

		f, err := os.Create(filepath.Join(tmpDir, "etc", "passwd"))
		if err != nil {
			return "", err
		}
		defer f.Close()

		_, err = f.WriteString(contents)
		if err != nil {
			return "", err
		}

		err = f.Chmod(perms)
		if err != nil {
			return "", err
		}
		return tmpDir, nil
	}
}

// TestGetExecUserHome tests the getExecUserHome function.
func TestGetExecUserHome(t *testing.T) {
	tests := map[string]struct {
		uid        uint32
		createRoot func() (string, error)
		expected   string
	}{
		"success": {
			uid:        1000,
			createRoot: setupPasswd("adin::1000:1111::/home/adin:/bin/sh", 0666),
			expected:   "/home/adin",
		},
		"no_passwd": {
			uid:        1000,
			createRoot: setupTempDir,
			expected:   "/",
		},
		"no_perms": {
			uid:        1000,
			createRoot: setupPasswd("adin::1000:1111::/home/adin:/bin/sh", 0000),
			expected:   "/",
		},
		"directory": {
			uid: 1000,
			createRoot: func() (string, error) {
				tmpDir, err := setupTempDir()
				if err != nil {
					return "", err
				}

				if err := os.Mkdir(filepath.Join(tmpDir, "etc"), 0777); err != nil {
					return "", err
				}

				if err := syscall.Mkdir(filepath.Join(tmpDir, "etc", "passwd"), 0666); err != nil {
					return "", err
				}

				return tmpDir, nil
			},
			expected: "/",
		},
		// Currently we don't allow named pipes.
		"named_pipe": {
			uid: 1000,
			createRoot: func() (string, error) {
				tmpDir, err := setupTempDir()
				if err != nil {
					return "", err
				}

				if err := os.Mkdir(filepath.Join(tmpDir, "etc"), 0777); err != nil {
					return "", err
				}

				if err := syscall.Mkfifo(filepath.Join(tmpDir, "etc", "passwd"), 0666); err != nil {
					return "", err
				}

				return tmpDir, nil
			},
			expected: "/",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			tmpDir, err := tc.createRoot()
			if err != nil {
				t.Fatalf("failed to create root dir: %v", err)
			}

			sandEnd, cleanup, err := startGofer(tmpDir)
			if err != nil {
				t.Fatalf("failed to create gofer: %v", err)
			}
			defer cleanup()

			ctx := contexttest.Context(t)
			conf := &Config{
				RootDir:        "unused_root_dir",
				Network:        NetworkNone,
				DisableSeccomp: true,
			}

			spec := &specs.Spec{
				Root: &specs.Root{
					Path:     tmpDir,
					Readonly: true,
				},
				// Add /proc mount as tmpfs to avoid needing a kernel.
				Mounts: []specs.Mount{
					{
						Destination: "/proc",
						Type:        "tmpfs",
					},
				},
			}

			var mns *fs.MountNamespace
			setMountNS := func(m *fs.MountNamespace) {
				mns = m
				ctx.(*contexttest.TestContext).RegisterValue(fs.CtxRoot, mns.Root())
			}
			mntr := newContainerMounter(spec, []int{sandEnd}, nil, &podMountHints{})
			if err := mntr.setupRootContainer(ctx, ctx, conf, setMountNS); err != nil {
				t.Fatalf("failed to create mount namespace: %v", err)
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
