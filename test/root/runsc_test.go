// Copyright 2020 The gVisor Authors.
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

package root

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestCreateFailureRemovesCgroup(t *testing.T) {
	parentPath := "/" + testutil.RandomID("runsc-create-")
	parent, err := cgroup.NewFromPath(parentPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Install(&specs.LinuxResources{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := parent.Uninstall(); err != nil {
			t.Errorf("removing test parent cgroup: %v", err)
		}
	})
	childPath := filepath.Join(parentPath, "child")
	child, err := cgroup.NewFromPath(childPath, false)
	if err != nil {
		t.Fatal(err)
	}
	// Retain ownership of these test paths so cleanup can remove a leaked group
	// on failure, including all controller paths on cgroup v1.
	if err := child.Install(&specs.LinuxResources{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := child.Uninstall(); err != nil {
			t.Errorf("removing test child cgroup: %v", err)
		}
	})
	if err := child.Uninstall(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(child.MakePath("memory")); !os.IsNotExist(err) {
		t.Fatalf("child cgroup before creation: got %v, want not-exist", err)
	}

	testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
	config.RegisterFlags(testFlags)
	conf, err := config.NewFromFlags(testFlags)
	if err != nil {
		t.Fatal(err)
	}
	conf.Network = config.NetworkNone
	conf.Overlay2.Set("none")
	// Fail after the gofer starts, without requiring a working KVM device.
	conf.Platform = "kvm"
	conf.PlatformDevicePath = filepath.Join(t.TempDir(), "missing-kvm")
	spec := testutil.NewSpecWithArgs("/bin/true")
	spec.Linux = &specs.Linux{CgroupsPath: childPath}
	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	c, err := container.New(conf, container.Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if c != nil {
		t.Cleanup(func() {
			if err := c.Destroy(); err != nil {
				t.Errorf("destroying unexpected container: %v", err)
			}
		})
	}
	if want := fmt.Sprintf("error opening KVM device file (%s): %v", conf.PlatformDevicePath, unix.ENOENT); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("container creation: got %v, want %q", err, want)
	}
	if _, err := os.Stat(child.MakePath("memory")); !os.IsNotExist(err) {
		t.Errorf("child cgroup after failed creation: got %v, want not-exist", err)
	}
	if _, err := os.Stat(parent.MakePath("memory")); err != nil {
		t.Errorf("pre-existing parent cgroup was not preserved: %v", err)
	}
}

func TestCreateContainerHooksRootFS(t *testing.T) {
	rootLink := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink("/", rootLink); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		root      string
		wantError bool
	}{
		{name: "process-root", root: "/", wantError: true},
		{name: "dot", root: "/./", wantError: true},
		{name: "parent", root: "/..", wantError: true},
		{name: "symlink", root: rootLink, wantError: true},
		{name: "named-root", root: t.TempDir()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFlags := flag.NewFlagSet("test", flag.ContinueOnError)
			config.RegisterFlags(testFlags)
			conf, err := config.NewFromFlags(testFlags)
			if err != nil {
				t.Fatal(err)
			}
			conf.Network = config.NetworkNone
			conf.IgnoreCgroups = true
			conf.Overlay2.Set("none")
			logDir := t.TempDir()
			conf.DebugLog = filepath.Join(logDir, "%COMMAND%.log")
			spec := testutil.NewSpecWithArgs("/bin/true")
			spec.Root = &specs.Root{Path: tc.root}
			spec.Mounts = nil
			marker := filepath.Join(t.TempDir(), "hook-ran")
			if !tc.wantError {
				marker = filepath.Join(tc.root, "hook-ran")
			}
			spec.Hooks = &specs.Hooks{CreateContainer: []specs.Hook{{
				Path: "/bin/sh",
				Args: []string{"/bin/sh", "-c", `echo hook > "$1"`, "hook", marker},
			}}}
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			c, err := container.New(conf, container.Args{
				ID:        testutil.RandomContainerID(),
				Spec:      spec,
				BundleDir: bundleDir,
			})
			if c != nil {
				defer func() {
					if err := c.Destroy(); err != nil {
						t.Errorf("destroying container: %v", err)
					}
				}()
			}
			if tc.wantError {
				if err == nil {
					t.Fatal("container creation succeeded with hooks at the process root")
				}
				// Creation reports a synchronization failure when the gofer exits;
				// check its log to distinguish rejection from unrelated failures.
				out, err := os.ReadFile(filepath.Join(logDir, "gofer.log"))
				if err != nil {
					t.Fatal(err)
				}
				if want := "createContainer hooks are not supported with rootfs"; !strings.Contains(string(out), want) {
					t.Fatalf("gofer log does not contain %q:\n%s", want, out)
				}
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatalf("hook marker stat: got %v, want not-exist", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("creating container with hooks at a named root: %v", err)
			}
			if out, err := os.ReadFile(marker); err != nil || string(out) != "hook\n" {
				t.Errorf("hook marker: got %q, err %v; want %q", out, err, "hook\n")
			}
		})
	}
}

// TestDoKill checks that when "runsc do..." is killed, the sandbox process is
// also terminated. This ensures that parent death signal is propagate to the
// sandbox process correctly.
func TestDoKill(t *testing.T) {
	// Make the sandbox process be reparented here when it's killed, so we can
	// wait for it.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatalf("prctl(PR_SET_CHILD_SUBREAPER): %v", err)
	}

	cmd := exec.Command(specutils.ExePath, "do", "sleep", "10000")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	cmd.Start()

	var pid int
	findSandbox := func() error {
		var err error
		pid, err = sandboxPid(cmd.Process.Pid)
		if err != nil {
			return &backoff.PermanentError{Err: err}
		}
		if pid == 0 {
			return fmt.Errorf("sandbox process not found")
		}
		return nil
	}
	if err := testutil.Poll(findSandbox, 10*time.Second); err != nil {
		t.Fatalf("failed to find sandbox: %v", err)
	}
	t.Logf("Found sandbox, pid: %d", pid)

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("failed to kill run process: %v", err)
	}
	cmd.Wait()
	t.Logf("Parent process killed (%d). Output: %s", cmd.Process.Pid, buf.String())

	ch := make(chan struct{})
	go func() {
		defer func() { ch <- struct{}{} }()
		t.Logf("Waiting for sandbox process (%d) termination", pid)
		if _, err := unix.Wait4(pid, nil, 0, nil); err != nil {
			t.Errorf("error waiting for sandbox process (%d): %v", pid, err)
		}
	}()
	select {
	case <-ch:
		// Done
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for sandbox process (%d) to exit", pid)
	}
}

// sandboxPid looks for the sandbox process inside the process tree starting
// from "pid". It returns 0 and no error if no sandbox process is found. It
// returns error if anything failed.
func sandboxPid(pid int) (int, error) {
	cmd := exec.Command("pgrep", "-P", strconv.Itoa(pid))
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	ps, err := cmd.Process.Wait()
	if err != nil {
		return 0, err
	}
	if ps.ExitCode() == 1 {
		// pgrep returns 1 when no process is found.
		return 0, nil
	}

	var children []int
	for _, line := range strings.Split(buf.String(), "\n") {
		if len(line) == 0 {
			continue
		}
		child, err := strconv.Atoi(line)
		if err != nil {
			return 0, err
		}

		cmdline, err := os.ReadFile(filepath.Join("/proc", line, "cmdline"))
		if err != nil {
			if os.IsNotExist(err) {
				// Raced with process exit.
				continue
			}
			return 0, err
		}
		args := strings.SplitN(string(cmdline), "\x00", 2)
		if len(args) == 0 {
			return 0, fmt.Errorf("malformed cmdline file: %q", cmdline)
		}
		// The sandbox process has the first argument set to "runsc-sandbox".
		if args[0] == "runsc-sandbox" {
			return child, nil
		}

		children = append(children, child)
	}

	// Sandbox process wasn't found, try another level down.
	for _, pid := range children {
		sand, err := sandboxPid(pid)
		if err != nil {
			return 0, err
		}
		if sand != 0 {
			return sand, nil
		}
		// Not found, continue the search.
	}
	return 0, nil
}

// Tests that the sandbox process is running with no environment variables
// except the small allowlist required for sandbox setup. We don't want to leak
// env vars from the caller to the sandbox process.
func TestSandboxProcessEnv(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	runOpts := dockerutil.RunOpts{Image: "basic/alpine"}
	if err := d.Spawn(ctx, runOpts, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		t.Fatal(err)
	}
	got = regexp.MustCompile("(^|\x00)RUNSC_START_TIME_NANOS=\\d+\x00").ReplaceAll(got, []byte("$1"))
	got = regexp.MustCompile("(^|\x00)GVISOR_ENFORCE_RELEASE=[^\x00]*\x00").ReplaceAll(got, []byte("$1"))
	got = regexp.MustCompile("(^|\x00)TMPDIR=[^\x00]*\x00").ReplaceAll(got, []byte("$1"))
	if len(got) != 0 && string(got) != "GLIBC_TUNABLES=glibc.pthread.rseq=0\x00" {
		t.Errorf("sandbox process's environment is not empty: got %s (%v)", string(got), got)
	}
}
