// Copyright 2018 The gVisor Authors.
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

// Package integration provides end-to-end integration tests for runsc. These
// tests require docker and runsc to be installed on the machine.
//
// Each test calls docker commands to start up a container, and tests that it
// is behaving properly, with various runsc commands. The container is killed
// and deleted at the end.

package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Test that exec uses the exact same capability set as the container.
func TestExecCapabilities(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sh", "-c", "cat /proc/self/status; sleep 100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check that capability.
	matches, err := d.WaitForOutputSubmatch(ctx, "CapEff:\t([0-9a-f]+)\n", 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForOutputSubmatch() timeout: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("There should be a match for the whole line and the capability bitmask")
	}
	want := fmt.Sprintf("CapEff:\t%s\n", matches[1])
	t.Log("Root capabilities:", want)

	// Now check that exec'd process capabilities match the root.
	got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "grep", "CapEff:", "/proc/self/status")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	t.Logf("CapEff: %v", got)
	if got != want {
		t.Errorf("wrong capabilities, got: %q, want: %q", got, want)
	}
}

// Test that 'exec --privileged' adds all capabilities, except for CAP_NET_RAW
// which is removed from the container when --net-raw=false.
func TestExecPrivileged(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Container will drop all capabilities.
	opts := dockerutil.RunOpts{
		Image:   "basic/alpine",
		CapDrop: []string{"all"},
	}

	// But if we are running with host network stack and raw sockets, then
	// we require CAP_NET_RAW, so add that back.
	if testutil.IsRunningWithHostNet() && testutil.IsRunningWithNetRaw() {
		opts.CapAdd = []string{"NET_RAW"}
	}

	// Start the container.
	if err := d.Spawn(ctx, opts, "sh", "-c", "cat /proc/self/status; sleep 100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Grab the capabilities from inside container.
	matches, err := d.WaitForOutputSubmatch(ctx, "CapEff:\t([0-9a-f]+)\n", 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForOutputSubmatch() timeout: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("There should be a match for the whole line and the capability bitmask")
	}
	containerCaps, err := strconv.ParseUint(matches[1], 16, 64)
	if err != nil {
		t.Fatalf("failed to convert capabilities %q: %v", matches[1], err)
	}
	t.Logf("Container capabilities: %#x", containerCaps)

	// Expect no capabilities, unless raw sockets configured.
	var wantContainerCaps uint64
	if testutil.IsRunningWithNetRaw() {
		wantContainerCaps |= bits.MaskOf64(int(linux.CAP_NET_RAW))
	}
	if containerCaps != wantContainerCaps {
		t.Fatalf("Container caps got %x want %x", containerCaps, wantContainerCaps)
	}

	// Check that 'exec --privileged' adds all capabilities except
	// CAP_NET_RAW, unless raw sockets configured.
	got, err := d.Exec(ctx, dockerutil.ExecOpts{
		Privileged: true,
	}, "grep", "CapEff:", "/proc/self/status")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	t.Logf("Exec CapEff: %v", got)
	wantCaps := specutils.AllCapabilitiesUint64()
	if !testutil.IsRunningWithNetRaw() {
		wantCaps &= ^bits.MaskOf64(int(linux.CAP_NET_RAW))
	}
	wantStr := fmt.Sprintf("CapEff:\t%016x\n", wantCaps)
	if got == wantStr {
		// All good.
		return
	}
	// Older versions of Docker don't support CAP_PERFMON, _BPF, or
	// _CHECKPOINT_RESTORE. Mask those and see if we are equal.
	oldWantCaps := wantCaps
	for _, cap := range []linux.Capability{linux.CAP_PERFMON, linux.CAP_BPF, linux.CAP_CHECKPOINT_RESTORE} {
		oldWantCaps = oldWantCaps &^ bits.MaskOf64(int(cap))
	}
	oldWantStr := fmt.Sprintf("CapEff:\t%016x\n", oldWantCaps)
	if got != oldWantStr {
		t.Errorf("Wrong capabilities, got: %q, want: %q or %q. Make sure runsc is not using '--net-raw'", got, wantStr, oldWantStr)
	}
}

func TestExecJobControl(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	p, err := d.ExecProcess(ctx, dockerutil.ExecOpts{UseTTY: true}, "/bin/sh")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	if _, err = p.Write(time.Second, []byte("sleep 100 | cat\n")); err != nil {
		t.Fatalf("error exit: %v", err)
	}
	time.Sleep(time.Second)

	if _, err = p.Write(time.Second, []byte{0x03}); err != nil {
		t.Fatalf("error exit: %v", err)
	}

	if _, err = p.Write(time.Second, []byte("exit $(expr $? + 10)\n")); err != nil {
		t.Fatalf("error exit: %v", err)
	}

	want := 140
	got, err := p.WaitExitStatus(ctx)
	if err != nil {
		t.Fatalf("wait for exit failed with: %v", err)
	} else if got != want {
		t.Fatalf("wait for exit returned: %d want: %d", got, want)
	}
}

// Test that failure to exec returns proper error message.
func TestExecError(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Attempt to exec a binary that doesn't exist.
	out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "no_can_find")
	if err == nil {
		t.Fatalf("docker exec didn't fail")
	}
	if want := `error finding executable "no_can_find" in PATH`; !strings.Contains(out, want) {
		t.Fatalf("docker exec wrong error, got: %s, want: .*%s.*", out, want)
	}
}

// Test that exec inherits environment from run.
func TestExecEnv(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container with env FOO=BAR.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
		Env:   []string{"FOO=BAR"},
	}, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Exec "echo $FOO".
	got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo $FOO")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if got, want := strings.TrimSpace(got), "BAR"; got != want {
		t.Errorf("bad output from 'docker exec'. Got %q; Want %q.", got, want)
	}
}

// TestRunEnvHasHome tests that run always has HOME environment set.
func TestRunEnvHasHome(t *testing.T) {
	// Base alpine image does not have any environment variables set.
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Exec "echo $HOME". The 'bin' user's home dir is '/bin'.
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
		User:  "bin",
	}, "/bin/sh", "-c", "echo $HOME")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check that the directory matches.
	if got, want := strings.TrimSpace(got), "/bin"; got != want {
		t.Errorf("bad output from 'docker run'. Got %q; Want %q.", got, want)
	}
}

// Test that exec always has HOME environment set, even when not set in run.
func TestExecEnvHasHome(t *testing.T) {
	// Base alpine image does not have any environment variables set.
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Exec "echo $HOME", and expect to see "/root".
	got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo $HOME")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if want := "/root"; !strings.Contains(got, want) {
		t.Errorf("wanted exec output to contain %q, got %q", want, got)
	}

	// Create a new user with a home directory.
	newUID := 1234
	newHome := "/foo/bar"
	cmd := fmt.Sprintf("mkdir -p -m 777 %q && adduser foo -D -u %d -h %q", newHome, newUID, newHome)
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", cmd); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// Execute the same as the new user and expect newHome.
	got, err = d.Exec(ctx, dockerutil.ExecOpts{
		User: strconv.Itoa(newUID),
	}, "/bin/sh", "-c", "echo $HOME")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if want := newHome; !strings.Contains(got, want) {
		t.Errorf("wanted exec output to contain %q, got %q", want, got)
	}
}
