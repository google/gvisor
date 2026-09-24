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

package root

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/sandboxposture"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// postureConfig returns the `runsc` configuration the sandbox under test is
// expected to have been started with.
func postureConfig(t *testing.T) *config.Config {
	t.Helper()
	conf, err := config.NewFromFlags(flag.CommandLine)
	if err != nil {
		t.Fatalf("Building a configuration from flags: %v", err)
	}
	return conf
}

// extraFDClasses returns the host descriptors the configuration's platform
// holds open beyond the ones every sandbox has.
func extraFDClasses(conf *config.Config) []string {
	if conf.Platform != "kvm" {
		return nil
	}
	return sandboxposture.KVMFDClasses()
}

// TestSandboxPostureDocker checks the posture of a sandbox started by Docker.
func TestSandboxPostureDocker(t *testing.T) {
	if missing := sandboxposture.UnsupportedFeatures(); len(missing) > 0 {
		t.Skipf("This kernel cannot report %s, so a collected posture would not be exhaustive", strings.Join(missing, ", "))
	}
	conf := postureConfig(t)
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatalf("Docker.SandboxPid(): %v", err)
	}
	key, err := d.NetworkSandboxKey(ctx)
	if err != nil {
		t.Fatalf("Docker.NetworkSandboxKey(): %v", err)
	}
	if key == "" {
		t.Fatalf("Container has no network sandbox key; cannot tell which network namespace the sandbox should be in")
	}
	const netnsTarget = "container-netns"
	targets := map[string]string{netnsTarget: key}
	shimPID, err := getParentPID(pid)
	if err != nil {
		t.Fatalf("Finding the sandbox's parent: %v", err)
	}
	t.Logf("Sandbox is PID %d; its parent, the runsc shim, is PID %d", pid, shimPID)

	ref, err := sandboxposture.ReferenceOf(shimPID, procPath())
	if err != nil {
		t.Fatalf("Describing the reference process %d: %v", shimPID, err)
	}

	want := sandboxposture.Expected(sandboxposture.ExpectedOpts{
		DirectFS:             conf.DirectFS,
		NetworkMode:          conf.Network.String(),
		EnableRaw:            conf.EnableRaw,
		RequiresCapSysPtrace: sandboxposture.PlatformCapSysPtrace[conf.Platform],
		GoDebug:              sandboxposture.PlatformGoDebug[conf.Platform],
		ExtraFDClasses:       extraFDClasses(conf),
		CgoEnabled:           config.CgoEnabled,
		NetNamespaceTarget:   netnsTarget,
		ChildOfRef:           true, // Ref is shim
		Ref:                  ref,
	})

	collect := func() *sandboxposture.Posture {
		t.Helper()
		got, err := sandboxposture.Collect(sandboxposture.Opts{
			PID:              pid,
			RefPID:           shimPID,
			NamespaceTargets: targets,
			ProcRoot:         procPath(),
		})
		if err != nil {
			t.Fatalf("Collecting posture of sandbox %d: %v", pid, err)
		}
		return got
	}

	got := collect()
	if d := sandboxposture.Diff(want, got); d != "" {
		t.Errorf("Sandbox %d: %s", pid, d)
	}
	checkThreads(t, "after start", pid, got)

	// Check the threads a second time after forcing the sandbox to create more
	// of them. The processes are backgrounded with their stdio redirected so
	// that they outlive the exec rather than holding its output pipe open.
	const spawned = 4
	if out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c",
		fmt.Sprintf("for i in $(seq %d); do sleep 10000 </dev/null >/dev/null 2>/dev/null & done", spawned)); err != nil {
		t.Fatalf("docker exec failed: %v, out: %s", err, out)
	}
	// Wait for threads to appear.
	if err := testutil.Poll(func() error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "pgrep -x sleep | wc -l")
		if err != nil {
			return fmt.Errorf("counting the sandbox's processes: %w", err)
		}
		if n, err := strconv.Atoi(strings.TrimSpace(out)); err != nil || n < spawned+1 {
			return errNotYet
		}
		return nil
	}, 30*time.Second); err != nil {
		t.Fatalf("The %d processes spawned in the sandbox did not all come up: %v", spawned, err)
	}
	afterMoreThreads := collect()
	checkThreads(t, "after spawning more in-sandbox threads", pid, afterMoreThreads)
	if d := sandboxposture.Diff(want, afterMoreThreads); d != "" {
		t.Errorf("Sandbox %d after exec: %s", pid, d)
	}
}

// checkThreads requires that every thread of the sandbox is uniform.
func checkThreads(t *testing.T, when string, pid int, p *sandboxposture.Posture) {
	t.Helper()
	if p.Threads.Uniform {
		return
	}
	t.Errorf("Sandbox %d has threads whose posture differs from the process's, %s:\n  %s",
		pid, when, strings.Join(p.Threads.Divergences, "\n  "))
}

// errNotYet is returned by a poll check that hasn't been satisfied.
var errNotYet = errors.New("not yet")

// TestSandboxPostureDo checks the posture of a sandbox started by `runsc do`.
func TestSandboxPostureDo(t *testing.T) {
	if missing := sandboxposture.UnsupportedFeatures(); len(missing) > 0 {
		t.Skipf("This kernel cannot report %s, so a collected posture would not be exhaustive", strings.Join(missing, ", "))
	}
	conf := postureConfig(t)
	runsc, err := dockerutil.RuntimePath()
	if err != nil {
		t.Fatalf("Cannot find the runsc binary: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rootDir, err := os.MkdirTemp(testutil.TmpDir(), "posture-do")
	if err != nil {
		t.Fatalf("Creating a root directory: %v", err)
	}
	defer os.RemoveAll(rootDir)
	const readyMarker = "sandbox-posture-ready"
	cmd := exec.CommandContext(ctx, runsc,
		"--network=none",
		"--platform="+conf.Platform,
		"--directfs="+strconv.FormatBool(conf.DirectFS),
		"--root", rootDir,
		"do", "/bin/sh", "-c", "echo "+readyMarker+"; exec sleep 300")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Opening the stdout of `runsc do`: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("Starting `runsc do`: %v", err)
	}
	killed := false
	defer func() {
		if !killed {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == readyMarker {
				ready <- nil // Process must have started in the sandbox by now.
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- fmt.Errorf("reading stdout: %w", err)
			return
		}
		ready <- fmt.Errorf("stdout ended before %q appeared", readyMarker)
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("Waiting for the command in the sandbox to report itself running: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("The command in the sandbox did not print %q within 30s", readyMarker)
	}

	pid, err := findSandboxUnder(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Finding the sandbox under `runsc do` (PID %d): %v", cmd.Process.Pid, err)
	}

	ref, err := sandboxposture.ReferenceOf(os.Getpid(), procPath())
	if err != nil {
		t.Fatalf("Describing the reference process: %v", err)
	}
	got, err := sandboxposture.Collect(sandboxposture.Opts{
		PID:      pid,
		RefPID:   os.Getpid(),
		ProcRoot: procPath(),
	})
	if err != nil {
		t.Fatalf("Collecting posture of sandbox %d: %v", pid, err)
	}
	d := sandboxposture.Diff(sandboxposture.Expected(sandboxposture.ExpectedOpts{
		DirectFS:             conf.DirectFS,
		EnableRaw:            conf.EnableRaw,
		RequiresCapSysPtrace: sandboxposture.PlatformCapSysPtrace[conf.Platform],
		GoDebug:              sandboxposture.PlatformGoDebug[conf.Platform],
		ExtraFDClasses:       extraFDClasses(conf),
		CgoEnabled:           config.CgoEnabled,
		// The sandbox is a child of the `runsc do` process this test spawned,
		// not of the test itself.
		ChildOfRef: false,
		Ref:        ref,
	}), got)
	if d != "" {
		t.Errorf("Sandbox %d started by `runsc do`: %s", pid, d)
	}
	checkThreads(t, "under `runsc do`", pid, got)
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("Killing the `runsc do` process: %v", err)
	}
	killed = true
	cmd.Wait()
	if err := testutil.Poll(func() error {
		if err := unix.Kill(pid, 0); err == unix.ESRCH {
			return nil
		}
		state, err := os.ReadFile(procPath(strconv.Itoa(pid), "stat"))
		if err != nil {
			return nil // Gone.
		}
		if isZombie(string(state)) {
			return nil
		}
		return errNotYet
	}, 30*time.Second); err != nil {
		t.Errorf("Sandbox %d outlived the `runsc do` process that owned it", pid)
	}
}

// isZombie reports whether a `/proc/<pid>/stat` line describes an exited but
// unreaped process.
func isZombie(stat string) bool {
	i := strings.LastIndex(stat, ")")
	if i < 0 {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(stat[i+1:]), "Z")
}

// findSandboxUnder returns the PID of the sandbox process descended from the
// given process.
func findSandboxUnder(root int) (int, error) {
	entries, err := os.ReadDir(procPath())
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmdline, err := os.ReadFile(procPath(e.Name(), "cmdline"))
		if err != nil {
			continue // The process went away.
		}
		if argv0, _, _ := strings.Cut(string(cmdline), "\x00"); argv0 != "runsc-sandbox" {
			continue
		}
		if descendsFrom(pid, root) {
			return pid, nil
		}
	}
	return 0, errNotYet
}

// descendsFrom reports whether `pid` is `root` or a descendant of it.
func descendsFrom(pid, root int) bool {
	const maxDepth = 32
	for i := 0; pid > 1 && i < maxDepth; i++ {
		if pid == root {
			return true
		}
		parent, err := getParentPID(pid)
		if err != nil {
			return false
		}
		pid = parent
	}
	return false
}
