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

package bwrap

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func appendMounts(mounts ...[]*specs.Mount) []specs.Mount {
	var result []specs.Mount
	for _, m := range mounts {
		for _, mount := range m {
			result = append(result, *mount)
		}
	}
	return result
}

func TestBuildRunscSpec(t *testing.T) {
	defaultMounts := []*specs.Mount{
		{Type: "proc", Destination: "/proc"},
		{Type: "sysfs", Destination: "/sys"},
		{Type: "devtmpfs", Destination: "/dev"},
		{Type: "devpts", Destination: "/dev/pts"},
		{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
		{Type: "tmpfs", Destination: "/tmp"},
	}

	workspaceDir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	tests := []struct {
		name          string
		cfg           *bwrapConfig
		wantRunscSpec *specs.Spec
		errContains   string
	}{
		{
			name: "WithRootMount",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []*MountOp{
					{Type: "bind", Src: "/src1", Dst: "/dst1"},
					{Type: "ro-bind", Src: "/", Dst: "/"},
					{Type: "tmpfs", Dst: "/tmp"},
				},
				UnshareNet: true,
				Args:       []string{"/bin/bash"},
			},
			wantRunscSpec: &specs.Spec{
				Process: &specs.Process{
					Args: []string{"/bin/bash"},
					Cwd:  cwd, // As `/` is binded, the cwd is picked as the container CWD.
				},
				Mounts: appendMounts(
					defaultMounts,
					[]*specs.Mount{{Type: "bind", Source: "/src1", Destination: "/dst1"}},
					[]*specs.Mount{
						{
							Destination: "/",
							Type:        "bind",
							Source:      "/",
							Options:     []string{"rbind", "rprivate", "nosuid", "nodev", "ro"},
						},
					},
					[]*specs.Mount{{Type: "tmpfs", Destination: "/tmp"}},
				),
				Linux: &specs.Linux{
					Namespaces: []specs.LinuxNamespace{
						{Type: specs.NetworkNamespace},
					},
				},
				Root: &specs.Root{
					Path:     "/",
					Readonly: true,
				},
			},
		},
		{
			name: "NoMountsNoNetNS",
			cfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"ls"},
			},
			wantRunscSpec: &specs.Spec{
				Process: &specs.Process{
					Args: []string{"ls"},
					Cwd:  "/", // No mounts, so the cwd is set to the /.
				},
				Mounts: appendMounts(
					// A tmpfs `/` is created in case no root is passed.
					[]*specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Root: &specs.Root{
					Path: workspaceDir,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.WorkspaceDir = workspaceDir
			gotSpec, err := tc.cfg.buildRunscSpec()
			if err != nil {
				t.Fatalf("BuildSpec failed: %v", err)
			}

			wantSpec := tc.wantRunscSpec
			diff := cmp.Diff(gotSpec, wantSpec,
				cmpopts.IgnoreFields(specs.Process{}, "Capabilities"),
				cmpopts.IgnoreFields(specs.Process{}, "Env"),
				cmpopts.SortSlices(func(a, b specs.LinuxNamespace) bool {
					if a.Type != b.Type {
						return a.Type < b.Type
					}
					return a.Path < b.Path
				}),
			)
			if diff != "" {
				t.Errorf("Spec mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	mntSrc, err := os.MkdirTemp("", "src")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(mntSrc)
	})

	tests := []struct {
		name        string
		args        []string
		wantArgs    []string
		errContains string
	}{
		{
			name:     "NoFlags",
			args:     []string{"bash"},
			wantArgs: []string{"bash"},
		},
		{
			name:     "WithFlags",
			args:     []string{"--unshare-net", "--chdir", "/tmp", "--bind", mntSrc, "dst", "bash"},
			wantArgs: []string{"bash"},
		},
		{
			name:     "WithDelimiter",
			args:     []string{"--unshare-net", "--", "bash", "--bash-args"},
			wantArgs: []string{"bash", "--bash-args"},
		},
		{
			name:        "UnknownFlag",
			args:        []string{"--unknown", "bash"},
			errContains: "Unknown option: --unknown",
		},
		{
			name:        "SingleDashFlag",
			args:        []string{"-u", "bash"},
			errContains: "Unknown option: -u",
		},
		{
			name:        "EmptyArgs",
			args:        []string{},
			errContains: "bwrap: no command specified",
		},
		{
			name:        "MissingArgs",
			args:        []string{""},
			errContains: "bwrap: no command specified",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseBwrapArgs(tc.args)
			wantError := tc.errContains != ""
			if wantError {
				if err == nil {
					t.Fatalf("got nil, want error containing: %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(cfg.Args) != len(tc.wantArgs) {
				t.Fatalf("Args length mismatch: got %v, want %v", len(cfg.Args), len(tc.wantArgs))
			}
			for i, arg := range cfg.Args {
				if arg != tc.wantArgs[i] {
					t.Fatalf("Args[%d] mismatch: got %v, want %v", i, arg, tc.wantArgs[i])
				}
			}
		})
	}
}

func TestSubDirPath(t *testing.T) {
	cfg := &bwrapConfig{}
	tests := []struct {
		parent string
		child  string
		want   string
		ok     bool
	}{
		// Standard
		{parent: "/a/b", child: "/a/b/c", want: "/a/b/c", ok: true},
		{parent: "/a/b", child: "/a/b", want: "/a/b", ok: true},
		{parent: "/a/b/c", child: "/a/b"},

		// Traps & Traversal
		{parent: "/app", child: "/app_backup/data"},                      // Substring, not a subpath
		{parent: "/a/b", child: "/a/b/../../c"},                          // Traverse outside of parent.
		{parent: "/a/b/../c", child: "/a/c/d", want: "/a/c/d", ok: true}, // Parent uses ..

		// Naming Edge Cases
		{parent: "/var", child: "/var/..a/file", want: "/var/..a/file", ok: true},   // Dir named ..a
		{parent: "/usr/...", child: "/usr/.../bin", want: "/usr/.../bin", ok: true}, // Dir named ...

		// Messy Formatting & Roots
		{parent: "/a///b/.", child: "/a////b/c", want: "/a/b/c", ok: true},           // Messy strings
		{parent: "/", child: "/opt/app", want: "/opt/app", ok: true},                 // Root to dir
		{parent: "/", child: "/", want: "/", ok: true},                               // Root to root
		{parent: ".", child: "testdir/file.txt", want: "testdir/file.txt", ok: true}, // Relative paths

		// Empty Cases
		{parent: "", child: "", ok: false},
		{parent: "", child: "test", ok: false},
		{parent: "/a/b", child: ""},
	}

	for _, test := range tests {
		got, ok := cfg.subDirPath(test.parent, test.child)
		if ok != test.ok || got != test.want {
			t.Errorf("cfg.subDirPath(%q, %q): got %q, %v; want %q, %v",
				test.parent, test.child, got, ok, test.want, test.ok)
		}
	}
}

// TestParseFlags tests the parsing of bwrap flags.
func TestParseFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCfg     *bwrapConfig
		errContains string
	}{
		{
			name: "ClearEnv",
			args: []string{"--clearenv", "bash"},
			wantCfg: &bwrapConfig{
				Env:  []string{"PWD=/"},
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "SetEnv",
			args: []string{"--setenv", "FOO", "bar", "bash"},
			wantCfg: &bwrapConfig{
				Env:  append(os.Environ(), "FOO=bar"),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnsetEnv",
			args: []string{"--unsetenv", "FOO", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UnsetEnv: []string{"FOO"},
				UID:      -1,
				GID:      -1,
				Args:     []string{"bash"},
			},
		},
		{
			name: "UnshareUser",
			args: []string{"--unshare-user", "bash"},
			wantCfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         -1,
				GID:         -1,
				UnshareUser: true,
				Args:        []string{"bash"},
			},
		},
		{
			name: "UID",
			args: []string{"--unshare-user", "--uid", "0", "--gid", "0", "bash"},
			wantCfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         0,
				GID:         0,
				UnshareUser: true,
				Args:        []string{"bash"},
			},
		},
		{
			name:        "Userns",
			args:        []string{"--userns", "3", "bash"},
			errContains: "--userns is currently not supported by runsc",
		},
		{
			name: "UnshareIPC",
			args: []string{"--unshare-ipc", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnsharePID",
			args: []string{"--unshare-pid", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnshareUTS",
			args: []string{"--unshare-uts", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "ValidHostname",
			args: []string{"--hostname", "test-host", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Hostname: "test-host",
				Args:     []string{"bash"},
			},
		},
		{
			name:        "MissingHostname",
			args:        []string{"--hostname"},
			errContains: "--hostname takes 1 argument",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseBwrapArgs(tc.args)
			wantError := tc.errContains != ""
			if wantError {
				if err == nil {
					t.Fatalf("got nil, want error containing %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if diff := cmp.Diff(cfg, tc.wantCfg, cmpopts.IgnoreUnexported(bwrapConfig{})); diff != "" {
				t.Errorf("bwrapConfig mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
