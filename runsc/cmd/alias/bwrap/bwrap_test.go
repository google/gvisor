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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// sudoUID and sudoGID are pinned into SUDO_UID and SUDO_GID so that the
// mappings --unshare-user produces are deterministic.
const (
	sudoUID = 4242
	sudoGID = 4343
)

// permsPtr returns a pointer to perms, for sandbox.Mount.Mode.
func permsPtr(perms uint32) *uint32 { return &perms }

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
	// mntSrc is a host directory for --bind and --ro-bind sources.
	mntSrc := t.TempDir()
	// rootBind is the mount --ro-bind / / produces.
	rootBind := sandbox.Mount{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true, Recursive: true, Private: true, NoSuid: true, NoDev: true}

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
			name:        "ShareNet",
			args:        []string{"--share-net", "bash"},
			errContains: "--share-net is currently not supported by runsc",
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
			name: "NewSession",
			args: []string{"--new-session", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "DieWithParent",
			args: []string{"--die-with-parent", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "AsPID1",
			args: []string{"--as-pid-1", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				AsPID1: true,
				Args:   []string{"bash"},
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
		{
			name: "Dev",
			args: []string{"--dev", "/dev1/", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev1"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev1/pts"},
				},
			},
		},
		{
			name: "DeduplicatedDev",
			args: []string{"--dev", "/dev1", "--dev", "/dev1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev1"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev1/pts"},
				},
			},
		},
		{
			name:        "MissingDevArg",
			args:        []string{"--dev"},
			errContains: "--dev takes 1 argument",
		},
		{
			name: "CapDrop",
			args: []string{"--cap-drop", "all", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				CapOps: []*CapOp{
					{Type: CapOpDrop, Cap: "all"},
				},
			},
		},
		{
			name: "CapAddAndDrop",
			args: []string{"--cap-drop", "all", "--cap-add", "net_admin", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				CapOps: []*CapOp{
					{Type: CapOpDrop, Cap: "all"},
					{Type: CapOpAdd, Cap: "net_admin"},
				},
			},
		},
		{
			name:        "MissingCapAddArg",
			args:        []string{"--cap-add"},
			errContains: "--cap-add takes 1 argument",
		},
		{
			name:        "MissingCapDropArg",
			args:        []string{"--cap-drop"},
			errContains: "--cap-drop takes 1 argument",
		},
		{
			name: "Argv0",
			args: []string{"--argv0", "custom-sh", "bash"},
			wantCfg: &bwrapConfig{
				Env:   os.Environ(),
				UID:   -1,
				GID:   -1,
				Argv0: "custom-sh",
				Args:  []string{"bash"},
			},
		},
		{
			name:        "MissingArgv0Arg",
			args:        []string{"--argv0"},
			errContains: "--argv0 takes one argument",
		},
		{
			name:        "DuplicateArgv0",
			args:        []string{"--argv0", "foo", "--argv0", "bar", "bash"},
			errContains: "--argv0 used multiple times",
		},
		{
			name:        "EmptyArgv0",
			args:        []string{"--argv0", "", "bash"},
			errContains: "--argv0 does not support an empty value",
		},
		{
			name: "PermsTmpfs",
			args: []string{"--perms", "0700", "--tmpfs", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			// Without --perms the mount carries no mode, leaving gVisor's tmpfs
			// default of 01777 in place.
			name: "TmpfsDefaultPerms",
			args: []string{"--tmpfs", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "PermsDir",
			args: []string{"--perms", "0700", "--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			// With no bind mount behind it, --dir becomes a tmpfs mount. Without
			// --perms it carries no mode, leaving gVisor's tmpfs default of 01777
			// in place.
			name: "DirDefaultPerms",
			args: []string{"--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A bind mount behind DEST makes --dir a host directory with
			// bubblewrap's default mode rather than a tmpfs mount.
			name: "DirUnderBind",
			args: []string{"--bind", mntSrc, "/mnt", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
		{
			name: "PermsDirUnderBind",
			args: []string{"--bind", mntSrc, "/mnt", "--perms", "0700", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", Perms: 0700}},
				Args:     []string{"bash"},
			},
		},
		{
			name: "DirUnderReadOnlyBind",
			args: []string{"--ro-bind", "/", "/", "--dir", "/usr", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{rootBind},
				HostDirs: []HostDir{{Dest: "/usr", Path: "/usr", ReadOnly: true, Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
		{
			// A tmpfs mounted over the bind hides it, so DEST lives in the
			// sandbox again and --dir falls back to a tmpfs mount.
			name: "DirUnderTmpfsOverBind",
			args: []string{"--bind", mntSrc, "/mnt", "--tmpfs", "/mnt", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/new"},
				},
				Args: []string{"bash"},
			},
		},
		{
			// An earlier tmpfs at DEST is the directory already, so --dir
			// leaves it, and its mode, alone.
			name: "DirOnTmpfs",
			args: []string{"--perms", "0700", "--tmpfs", "/mnt", "--dir", "/mnt/", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "DirOnProc",
			args: []string{"--proc", "/proc", "--dir", "/proc", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeProc, Destination: "/proc"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A mount point's parents exist once the mount is in place.
			name: "DirAboveMount",
			args: []string{"--tmpfs", "/mnt/a/b", "--dir", "/mnt/a", "--dir", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/a/b"}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "RepeatedDir",
			args: []string{"--dir", "/foo", "--perms", "0700", "--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A path next to a mount, rather than above it, does not exist yet.
			name: "DirNextToMount",
			args: []string{"--tmpfs", "/mnt/a", "--dir", "/mnt/ab", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/a"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/ab"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name: "DirRoot",
			args: []string{"--dir", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name:        "MissingDirArg",
			args:        []string{"--dir"},
			errContains: "--dir takes 1 argument",
		},
		{
			name:        "MissingPermsArg",
			args:        []string{"--perms"},
			errContains: "--perms takes 1 argument",
		},
		{
			name:        "NonOctalPerms",
			args:        []string{"--perms", "0799", "--tmpfs", "/foo", "bash"},
			errContains: "--perms takes an octal argument",
		},
		{
			name:        "PermsTooLarge",
			args:        []string{"--perms", "10000", "--tmpfs", "/foo", "bash"},
			errContains: "--perms takes an octal argument",
		},
		{
			name:        "DuplicatePerms",
			args:        []string{"--perms", "0700", "--perms", "0700", "--tmpfs", "/foo", "bash"},
			errContains: "--perms given twice",
		},
		{
			name:        "PermsWithoutOperation",
			args:        []string{"--perms", "0700", "--ro-bind", "/", "/", "--", "bash"},
			errContains: "--perms must be followed by",
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

// TestHostPath checks which mount, if any, backs a sandbox path.
func TestHostPath(t *testing.T) {
	cfg := &bwrapConfig{Mounts: []sandbox.Mount{
		{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true},
		{Type: sandbox.MountTypeBind, Source: "/host/data", Destination: "/data"},
		{Type: sandbox.MountTypeTmpfs, Destination: "/data/tmp"},
		{Type: sandbox.MountTypeBind, Source: "/host/cache", Destination: "/data/tmp/cache", ReadOnly: true},
		{Type: sandbox.MountTypeBind, Source: "/host/old", Destination: "/old"},
		{Type: sandbox.MountTypeTmpfs, Destination: "/old"},
	}}
	tests := []struct {
		path     string
		wantHost string
		wantRO   bool
		wantOK   bool
	}{
		// The root bind backs everything no other mount covers.
		{path: "/usr/lib", wantHost: "/usr/lib", wantRO: true, wantOK: true},
		{path: "/", wantHost: "/", wantRO: true, wantOK: true},
		// A bind maps its destination and anything below it.
		{path: "/data", wantHost: "/host/data", wantOK: true},
		{path: "/data/a/b", wantHost: "/host/data/a/b", wantOK: true},
		{path: "/data//a/../b/", wantHost: "/host/data/b", wantOK: true},
		// A tmpfs under the bind takes its subtree out of the host.
		{path: "/data/tmp"},
		{path: "/data/tmp/x"},
		// A bind under that tmpfs puts its subtree back on the host.
		{path: "/data/tmp/cache/x", wantHost: "/host/cache/x", wantRO: true, wantOK: true},
		// A tmpfs mounted over a bind hides the bind.
		{path: "/old/x"},
		// Prefix matches are on path components, not characters.
		{path: "/database", wantHost: "/database", wantRO: true, wantOK: true},
		// A relative path matches no mount.
		{path: "data/x"},
	}
	for _, tc := range tests {
		bind, host, ok := cfg.hostPath(tc.path)
		if ok != tc.wantOK || host != tc.wantHost || bind.ReadOnly != tc.wantRO {
			t.Errorf("hostPath(%q) = %q, readOnly=%v, %v; want %q, readOnly=%v, %v",
				tc.path, host, bind.ReadOnly, ok, tc.wantHost, tc.wantRO, tc.wantOK)
		}
	}
}

// TestMakeHostDirs checks that --dir behaves on the host as bubblewrap's
// --dir does inside the sandbox.
func TestMakeHostDirs(t *testing.T) {
	// bubblewrap clears its umask while it sets up the sandbox, so a
	// restrictive one must not change the modes below.
	oldMask := unix.Umask(077)
	t.Cleanup(func() { unix.Umask(oldMask) })

	tests := []struct {
		name string
		// setup prepares the host directory root and returns the --dir path
		// under it, relative to root.
		setup func(t *testing.T, root string) string
		ro    bool
		perms uint32
		// wantMode is the mode of the directory afterwards, 0 when no directory
		// may exist at the path.
		wantMode os.FileMode
		// wantParentMode is the mode of the directory's parent afterwards.
		wantParentMode os.FileMode
		errContains    string
	}{
		{
			name:           "Creates",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          0755,
			wantMode:       0755,
			wantParentMode: 0700,
		},
		{
			name:           "CreatesWithPerms",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          0710,
			wantMode:       0710,
			wantParentMode: 0700,
		},
		{
			name:           "CreatesWithStickyBit",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          01777,
			wantMode:       0777 | os.ModeSticky,
			wantParentMode: 0700,
		},
		{
			// mkdir(2) passes a parent's setgid bit on to the new directory.
			name: "CreatesUnderSetgidParent",
			setup: func(t *testing.T, root string) string {
				if err := os.Chmod(root, 0700|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
				return "new"
			},
			perms:          0755,
			wantMode:       0755 | os.ModeSetgid,
			wantParentMode: 0700,
		},
		{
			// Parents get 0755, less the group and other bits the directory
			// itself withholds.
			name:           "CreatesParents",
			setup:          func(t *testing.T, root string) string { return "a/b/c" },
			perms:          0750,
			wantMode:       0750,
			wantParentMode: 0750,
		},
		{
			name:           "CreatesPrivateParents",
			setup:          func(t *testing.T, root string) string { return "a/b/c" },
			perms:          0700,
			wantMode:       0700,
			wantParentMode: 0700,
		},
		{
			// An existing directory keeps its mode and contents.
			name: "Exists",
			setup: func(t *testing.T, root string) string {
				mkdirMode(t, filepath.Join(root, "keep"), 0711)
				if err := os.WriteFile(filepath.Join(root, "keep", "marker"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				return "keep"
			},
			perms:          0755,
			wantMode:       0711,
			wantParentMode: 0700,
		},
		{
			name: "ExistsUnderReadOnlyBind",
			setup: func(t *testing.T, root string) string {
				mkdirMode(t, filepath.Join(root, "keep"), 0711)
				return "keep"
			},
			ro:             true,
			perms:          0755,
			wantMode:       0711,
			wantParentMode: 0700,
		},
		{
			name:           "MissingUnderReadOnlyBind",
			setup:          func(t *testing.T, root string) string { return "new" },
			ro:             true,
			perms:          0755,
			wantParentMode: 0700,
			errContains:    "Can't mkdir /mnt/new: read-only file system",
		},
		{
			name: "ExistsAsFile",
			setup: func(t *testing.T, root string) string {
				if err := os.WriteFile(filepath.Join(root, "file"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				return "file"
			},
			perms:          0755,
			wantParentMode: 0700,
			errContains:    "Can't mkdir /mnt/file: not a directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			rel := tc.setup(t, root)
			path := filepath.Join(root, rel)
			cfg := &bwrapConfig{HostDirs: []HostDir{{
				Dest:     filepath.Join("/mnt", rel),
				Path:     path,
				ReadOnly: tc.ro,
				Perms:    tc.perms,
			}}}

			err := cfg.makeHostDirs()
			if tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("makeHostDirs() = %v, want error containing %q", err, tc.errContains)
				}
			} else if err != nil {
				t.Fatalf("makeHostDirs() = %v, want nil", err)
			}

			info, err := os.Stat(path)
			if tc.wantMode == 0 {
				if err == nil && info.IsDir() {
					t.Errorf("%q is a directory, want none", path)
				}
			} else if err != nil {
				t.Errorf("os.Stat(%q) = %v, want a directory", path, err)
			} else if !info.IsDir() || info.Mode()&(os.ModePerm|os.ModeSticky|os.ModeSetgid) != tc.wantMode {
				t.Errorf("%q is %v, want a directory with mode %v", path, info.Mode(), tc.wantMode)
			}
			if tc.name == "Exists" {
				if _, err := os.Stat(filepath.Join(path, "marker")); err != nil {
					t.Errorf("existing directory lost its contents: %v", err)
				}
			}
			parent, err := os.Stat(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if got := parent.Mode() & os.ModePerm; got != tc.wantParentMode {
				t.Errorf("parent of %q has mode %v, want %v", path, got, tc.wantParentMode)
			}
		})
	}
}

// mkdirMode creates the directory path with exactly mode, whatever the umask.
func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
