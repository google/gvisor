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
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// sudoUID and sudoGID are pinned into SUDO_UID and SUDO_GID so that the
// mappings --unshare-user produces are deterministic.
const (
	sudoUID = 4242
	sudoGID = 4343
)

// wantIDMappings returns the mappings bwrap is expected to build for an
// unshared user namespace that runs as containerID.
func wantIDMappings(containerID, hostID uint32) []specs.LinuxIDMapping {
	mappings := []specs.LinuxIDMapping{
		{ContainerID: containerID, HostID: hostID, Size: 1},
	}
	// Running as root, the gofer needs container 0 mapped to host 0 as well.
	if os.Getuid() == 0 && containerID != 0 {
		mappings = append(mappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
	}
	return mappings
}

// TestSandboxOptions checks the bubblewrap configuration is translated into
// the OCI specification the sandbox bindings build from it.
func TestSandboxOptions(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(sudoUID))
	t.Setenv("SUDO_GID", strconv.Itoa(sudoGID))

	// defaultMounts are the filesystems bwrap asks for in every sandbox, as
	// they appear in the specification.
	defaultMounts := []specs.Mount{
		{Type: "proc", Destination: "/proc"},
		{Type: "sysfs", Destination: "/sys"},
		{Type: "devtmpfs", Destination: "/dev"},
		{Type: "devpts", Destination: "/dev/pts"},
		{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
		{Type: "tmpfs", Destination: "/tmp"},
	}
	appendMounts := func(mounts ...[]specs.Mount) []specs.Mount {
		var result []specs.Mount
		for _, m := range mounts {
			result = append(result, m...)
		}
		return result
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	tests := []struct {
		name        string
		cfg         *bwrapConfig
		wantSpec    specs.Spec
		errContains string
	}{
		{
			name: "WithRootMount",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/dst1"},
					{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true, Recursive: true, Private: true, NoSuid: true, NoDev: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/tmp"},
				},
				UnshareNet: true,
				Args:       []string{"/bin/bash"},
			},
			wantSpec: specs.Spec{
				Root: &specs.Root{Path: "/", Readonly: true},
				// As `/` is binded, the cwd is picked as the container CWD.
				Process: &specs.Process{Cwd: cwd},
				Mounts: appendMounts(
					defaultMounts,
					[]specs.Mount{{
						Type:        "bind",
						Source:      "/src1",
						Destination: "/dst1",
					}},
					[]specs.Mount{{
						Type:        "bind",
						Source:      "/",
						Destination: "/",
						Options:     []string{"rbind", "rprivate", "nosuid", "nodev", "ro"},
					}},
					[]specs.Mount{{Type: "tmpfs", Destination: "/tmp"}},
				),
				Linux: &specs.Linux{},
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
			wantSpec: specs.Spec{
				// No root mount, so the sandbox gets an empty root directory.
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Linux: &specs.Linux{},
			},
		},
		{
			name: "UnshareUserWithUIDAndGID",
			cfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         1234,
				GID:         5678,
				UnshareUser: true,
				Args:        []string{"id"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/", User: specs.User{UID: 1234, GID: 5678}},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Linux: &specs.Linux{
					Namespaces:  []specs.LinuxNamespace{{Type: specs.UserNamespace}},
					UIDMappings: wantIDMappings(1234, sudoUID),
					GIDMappings: wantIDMappings(5678, sudoGID),
				},
			},
		},
		{
			name: "UIDWithoutUnshareUser",
			cfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  1000,
				GID:  -1,
				Args: []string{"ls"},
			},
			errContains: "--uid requires --unshare-user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.runscConfig = &config.Config{}
			opts, err := tc.cfg.sandboxOptions()
			if tc.errContains != "" {
				if err == nil {
					t.Fatalf("got nil, want error containing: %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("sandboxOptions failed: %v", err)
			}
			got, err := sandbox.DebugSpec(opts...)
			if err != nil {
				t.Fatalf("sandbox.DebugSpec failed: %v", err)
			}

			if got.Process.Capabilities == nil {
				t.Errorf("specification has no capabilities set")
			}
			if diff := cmp.Diff(got.Process.Env, tc.cfg.Env); diff != "" {
				t.Errorf("Environment mismatch (-got +want):\n%s", diff)
			}

			diff := cmp.Diff(got, &tc.wantSpec,
				cmpopts.IgnoreFields(specs.Process{}, "Capabilities", "Env", "Args"),
				cmpopts.IgnoreFields(specs.Spec{}, "Version"),
				cmpopts.SortSlices(func(a, b specs.LinuxNamespace) bool {
					if a.Type != b.Type {
						return a.Type < b.Type
					}
					return a.Path < b.Path
				}),
			)
			if diff != "" {
				t.Errorf("Specification mismatch (-got +want):\n%s", diff)
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
		{
			name: "SingleProc",
			args: []string{"--proc", "/proc1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
				},
			},
		},
		{
			name: "DeduplicatedProc",
			args: []string{"--proc", "/proc1", "--proc", "/proc1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
				},
			},
		},
		{
			name: "MultipleProc",
			args: []string{"--proc", "/proc1", "--proc", "/proc2", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
					{Type: sandbox.MountTypeProc, Destination: "/proc2"},
				},
			},
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
