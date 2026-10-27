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
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// newRunRootDir returns a runtime root directory, deleted at test cleanup.
func newRunRootDir(t *testing.T) string {
	t.Helper()
	runRootDir := t.TempDir()
	t.Cleanup(func() { specutils.UnmountNullNetNS(runRootDir) })
	return runRootDir
}

func TestEnvVars(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}

	hostEnvVar := "BWRAP_TEST_ENV_VAR"
	hostEnvVal := "BWRAP_TEST_ENV_VALUE"

	baseEnv := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}

	tests := []struct {
		name      string
		bwrapArgs []string
		wantEnv   []string
	}{
		{
			name: "SetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"="+hostEnvVal, "FOO=bar"),
		},
		{
			name: "ResetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", hostEnvVar, "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"=bar"),
		},
		{
			name: "ClearEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--clearenv",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: []string{"PWD=" + cwd, "FOO=bar", "HOME=/root"},
		},
		{
			name: "UnsetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--unsetenv", hostEnvVar,
				"--",
				"/usr/bin/env",
			},
			wantEnv: baseEnv,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)
			cmd.Env = append(baseEnv, hostEnvVar+"="+hostEnvVal)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			actualEnv := strings.Split(strings.TrimSpace(stdout.String()), "\n")

			// 2. Sort both slices alphabetically so order is 100% ignored!
			slices.Sort(tc.wantEnv)
			slices.Sort(actualEnv)

			if diff := cmp.Diff(tc.wantEnv, actualEnv); diff != "" {
				t.Errorf("runsc bwrap env mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBind(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat("/mnt"); err != nil || !info.IsDir() {
		t.Fatalf("bind destination /mnt is not a directory: %v", err)
	}
	stop := testutil.StartReaper()
	defer stop()

	workDir := t.TempDir()
	const contents = "bind mount contents\n"
	if err := os.WriteFile(filepath.Join(workDir, "input"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(specutils.ExePath,
		"--root", newRunRootDir(t), "bwrap",
		"--ro-bind", "/", "/", "--bind", workDir, "/mnt",
		"--", "/bin/sh", "-ec", "cat /mnt/input; cp /mnt/input /mnt/output")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
	}
	if got := stdout.String(); got != contents {
		t.Errorf("bind mount contents = %q, want %q", got, contents)
	}
	output, err := os.ReadFile(filepath.Join(workDir, "output"))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != contents {
		t.Errorf("written bind mount contents = %q, want %q", output, contents)
	}
}

func TestUserAndGroup(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantUID   string
		wantGID   string
	}{
		{
			name: "DefaultUser",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: fmt.Sprintf("%d", os.Getuid()),
		},
		{
			name: "CustomUID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: "12345",
		},
		{
			name: "CustomGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-g",
			},
			wantGID: "54321",
		},
		{
			name: "CustomUIDAndGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id",
			},
			wantUID: "uid=12345",
			wantGID: "gid=54321",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantUID != "" && !strings.Contains(output, tc.wantUID) {
				t.Errorf("output = %q, want UID %q", output, tc.wantUID)
			}
			if tc.wantGID != "" && !strings.Contains(output, tc.wantGID) {
				t.Errorf("output = %q, want GID %q", output, tc.wantGID)
			}
		})
	}
}

// TODO: b/518882196 - Support joining existing user namespaces.
func TestUserns(t *testing.T) {
	t.Skip("Skipping userns joining due to runsc doesn't support joining existing user namespaces")
}

func TestHostname(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "Hostname",
			bwrapArgs: []string{
				"--hostname", "test-host",
				"--ro-bind", "/", "/",
				"--",
				"/bin/hostname",
			},
			wantOutput: "test-host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestProc(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "Proc",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--proc", "/proc1",
				"--",
				"/bin/ls", "/proc1",
			},
			wantOutput: "cpuinfo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestCapabilities(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "CapDropAll",
			bwrapArgs: []string{
				"--unshare-all",
				"--ro-bind", "/", "/",
				"--cap-drop", "ALL",
				"--",
				"/bin/cat", "/proc/self/status",
			},
			// All bits zeroed out after dropping ALL capabilities.
			wantOutput: "CapEff:\t0000000000000000",
		},
		{
			name: "CapDropAllAndAddNetAdmin",
			bwrapArgs: []string{
				"--unshare-all",
				"--ro-bind", "/", "/",
				"--cap-drop", "ALL",
				"--cap-add", "NET_ADMIN",
				"--",
				"/bin/cat", "/proc/self/status",
			},
			// CAP_NET_ADMIN is bit 12 (1 << 12 = 0x1000).
			wantOutput: "CapEff:\t0000000000001000",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output missing expected capability mask:\ngot:\n%s\nwant to contain: %q", output, tc.wantOutput)
			}
		})
	}
}

func TestArgv0(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "CustomArgv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--argv0", "my-custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0",
			},
			wantOutput: "my-custom-sh",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestPerms(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "TmpfsPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /foo",
			},
			wantOutput: "700",
		},
		{
			// Without --perms the tmpfs keeps gVisor's default mode, which is
			// 0777 plus the sticky bit.
			name: "TmpfsDefaultPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /foo",
			},
			wantOutput: "1777",
		},
		{
			// --perms is consumed by the mount that follows it, so /b falls back
			// to the tmpfs default instead of inheriting the 0700.
			name: "PermsDoNotApplyToNextTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/a",
				"--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "700 1777",
		},
		{
			name: "PermsApplyIndependentlyPerTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/a",
				"--perms", "0500", "--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "700 500",
		},
		{
			// --perms only ever affects what follows it, so the mount declared
			// before it keeps the default mode.
			name: "PermsDoNotApplyToEarlierTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/a",
				"--perms", "0700", "--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "1777 700",
		},
		// The --dir cases below sit under a tmpfs, where --dir is itself a tmpfs
		// mount and --perms sets its mode.
		{
			name: "DirPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/foo",
			},
			wantOutput: "700",
		},
		{
			// Without --perms the directory keeps gVisor's tmpfs default mode,
			// which is 0777 plus the sticky bit.
			name: "DirDefaultPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/foo",
			},
			wantOutput: "1777",
		},
		{
			// --perms is consumed by the directory that follows it, so /mnt/b
			// falls back to the tmpfs default instead of inheriting the 0700.
			name: "PermsDoNotApplyToNextDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/a",
				"--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "700 1777",
		},
		{
			name: "PermsApplyIndependentlyPerDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/a",
				"--perms", "0500", "--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "700 500",
		},
		{
			// --perms only ever affects what follows it, so the directory
			// declared before it keeps the default mode.
			name: "PermsDoNotApplyToEarlierDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/a",
				"--perms", "0700", "--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "1777 700",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestDir(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	// hostDir is bind mounted at /mnt in the cases that need a writable host
	// directory. Each case gets a fresh one.
	const hostDir = "HOST_DIR"
	tests := []struct {
		name string
		// setup prepares hostDir before the run.
		setup func(t *testing.T, hostDir string)
		// bwrapArgs are the arguments, with hostDir standing in for the host
		// directory.
		bwrapArgs  []string
		wantOutput string
		// wantErr, if set, is text the failed run's stderr must contain.
		wantErr string
		// wantHostMode is the mode of hostDir/new afterwards, 0 if it must not
		// exist.
		wantHostMode os.FileMode
		// wantHostFile is a path under hostDir that must exist afterwards.
		wantHostFile string
	}{
		// Without a bind mount behind DEST, --dir is a tmpfs stand-in.
		{
			name: "CreatesParents",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/a/b/c",
				"--",
				"/bin/sh", "-c", "test -d /mnt/a/b/c && echo ok",
			},
			wantOutput: "ok",
		},
		{
			name: "Writable",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "touch /mnt/foo/file && echo ok",
			},
			wantOutput: "ok",
		},
		// Under a bind mount, --dir works on the host as bubblewrap's mkdir
		// does through the bind.
		{
			name: "MissingInWritableBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "echo data > /mnt/new/file && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0755,
			wantHostFile: "new/file",
		},
		{
			name: "MissingInWritableBindWithPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--perms", "0700", "--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/new",
			},
			wantOutput:   "700",
			wantHostMode: 0700,
		},
		{
			name: "MissingParentsInWritableBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new/a/b",
				"--",
				"/bin/sh", "-c", "touch /mnt/new/a/b/file && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0755,
			wantHostFile: "new/a/b/file",
		},
		{
			// An existing directory keeps its mode and contents rather than
			// being hidden behind an empty mount. 0751 differs from the 0755
			// a new directory would get, and still lets a sandbox user that
			// does not own it, as under sudo, reach the marker.
			name: "ExistingInWritableBind",
			setup: func(t *testing.T, hostDir string) {
				newDir := filepath.Join(hostDir, "new")
				if err := os.Mkdir(newDir, 0751); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(newDir, 0751); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(newDir, "marker"), nil, 0644); err != nil {
					t.Fatal(err)
				}
			},
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "test -f /mnt/new/marker && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0751,
			wantHostFile: "new/marker",
		},
		{
			name: "ExistingInReadOnlyBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--dir", "/usr",
				"--",
				"/bin/sh", "-c", "test -d /usr/bin && echo ok",
			},
			wantOutput: "ok",
		},
		{
			// bubblewrap's mkdir fails with EROFS inside a read-only bind, and
			// so does runsc, without touching the host.
			name: "MissingInReadOnlyBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "echo unreachable",
			},
			wantErr: "Can't mkdir /mnt/new: read-only file system",
		},
		// A directory that an earlier mount provides already exists, so --dir
		// leaves the mount alone rather than hiding it.
		{
			name: "ExistingTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/mnt",
				"--dir", "/mnt",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt",
			},
			wantOutput: "700",
		},
		{
			name: "ExistingProc",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--proc", "/proc",
				"--dir", "/proc",
				"--",
				"/bin/sh", "-c", "test -e /proc/self/status && echo ok",
			},
			wantOutput: "ok",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)
			// Under sudo, the sandbox user that SUDO_UID maps to must be able
			// to enter the directory, whatever the umask of the test.
			dir := t.TempDir()
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			args := []string{"--root", runRootDir, "bwrap"}
			for _, arg := range tc.bwrapArgs {
				if arg == hostDir {
					arg = dir
				}
				args = append(args, arg)
			}
			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			// bubblewrap clears its umask while it sets up the sandbox, so a
			// restrictive one inherited by runsc must not change the host modes
			// below. Only runsc gets it: under sudo, a 0700 dir from t.TempDir()
			// would shut out the sandbox user that SUDO_UID maps to.
			oldMask := unix.Umask(077)
			err := testutil.RunCmd(cmd)
			unix.Umask(oldMask)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("runsc bwrap succeeded, want failure with %q\nStdout: %s", tc.wantErr, stdout.String())
				}
				if !strings.Contains(stderr.String(), tc.wantErr) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}

			newDir := filepath.Join(dir, "new")
			info, err := os.Stat(newDir)
			if tc.wantHostMode == 0 {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("os.Stat(%q) = %v, want %v", newDir, err, os.ErrNotExist)
				}
			} else if err != nil {
				t.Errorf("os.Stat(%q) = %v, want a directory", newDir, err)
			} else if !info.IsDir() || info.Mode().Perm() != tc.wantHostMode {
				t.Errorf("%q is %v, want a directory with mode %v", newDir, info.Mode(), tc.wantHostMode)
			}
			if tc.wantHostFile != "" {
				if _, err := os.Stat(filepath.Join(dir, tc.wantHostFile)); err != nil {
					t.Errorf("host file missing after the run: %v", err)
				}
			}
		})
	}
}

func TestAsPID1(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantPID1  bool
	}{
		{
			name: "AsPID1",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--",
				"/bin/sh", "-c", "echo $$",
			},
			wantPID1: true,
		},
		{
			// Without --as-pid-1 the /bin/sleep placeholder is PID 1.
			name: "NotPID1ByDefault",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/bin/sh", "-c", "echo $$",
			},
			wantPID1: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			pid := strings.TrimSpace(stdout.String())
			if gotPID1 := pid == "1"; gotPID1 != tc.wantPID1 {
				t.Errorf("COMMAND ran as PID %q, want PID 1: %t", pid, tc.wantPID1)
			}
		})
	}
}

// TestAsPID1ExitStatus checks that runsc bwrap exits with COMMAND's exit status
// when COMMAND runs as PID 1.
func TestAsPID1ExitStatus(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap",
		"--unshare-user",
		"--ro-bind", "/", "/",
		"--as-pid-1",
		"--",
		"/bin/sh", "-c", "exit 7",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := testutil.RunCmd(cmd)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Errorf("runsc bwrap = %v, want exit status 7\nStderr: %s", err, stderr.String())
	}
}

// TestAsPID1Argv0 checks --as-pid-1 and --argv0 alone and together. --as-pid-1
// decides whether COMMAND is PID 1, and --argv0 decides its argv[0]. Neither
// flag changes what the other does.
func TestAsPID1Argv0(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantArgv0 string
		wantPID1  bool
	}{
		{
			name: "Default",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "/bin/sh",
			wantPID1:  false,
		},
		{
			name: "Argv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--argv0", "custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  false,
		},
		{
			name: "AsPID1",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "/bin/sh",
			wantPID1:  true,
		},
		{
			name: "AsPID1AndArgv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--argv0", "custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  true,
		},
		{
			// COMMAND has no slash, so the Sentry looks it up in PATH by its
			// name, sh, not by argv[0].
			name: "AsPID1AndArgv0PathLookup",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--argv0", "custom-sh",
				"--",
				"sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			argv0, pid, ok := strings.Cut(strings.TrimSpace(stdout.String()), " ")
			if !ok {
				t.Fatalf(`output = %q, want "<argv0> <pid>"`, stdout.String())
			}
			if argv0 != tc.wantArgv0 {
				t.Errorf("COMMAND ran with argv[0] %q, want %q", argv0, tc.wantArgv0)
			}
			if gotPID1 := pid == "1"; gotPID1 != tc.wantPID1 {
				t.Errorf("COMMAND ran as PID %q, want PID 1: %t", pid, tc.wantPID1)
			}
		})
	}
}

func TestDev(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	// check succeeds if DIR holds working device nodes, the standard symlinks
	// and a devpts at DIR/pts.
	check := func(dir string) string {
		return fmt.Sprintf("test -c %[1]s/null && echo x > %[1]s/null && "+
			"test -c %[1]s/urandom && test -L %[1]s/stdin && "+
			"test -c %[1]s/pts/ptmx && echo ok", dir)
	}

	tests := []struct {
		name      string
		bwrapArgs []string
	}{
		{
			name: "NewDest",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dev", "/mnt/dev",
				"--",
				"/bin/sh", "-c", check("/mnt/dev"),
			},
		},
		{
			name: "ReplaceDev",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--dev", "/dev",
				"--",
				"/bin/sh", "-c", check("/dev"),
			},
		},
		{
			// runsc always serves /dev from its dev filesystem, so a tmpfs
			// at /dev still holds the device nodes.
			name: "TmpfsAtDev",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/dev",
				"--",
				"/bin/sh", "-c", check("/dev"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			if got := strings.TrimSpace(stdout.String()); got != "ok" {
				t.Errorf("output = %q, want %q", got, "ok")
			}
		})
	}
}
