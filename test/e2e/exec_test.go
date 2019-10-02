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
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bits"
	"gvisor.dev/gvisor/runsc/dockerutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Test that exec uses the exact same capability set as the container.
func TestExecCapabilities(t *testing.T) {
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-capabilities-test")

	// Start the container.
	if err := d.Run("alpine", "sh", "-c", "cat /proc/self/status; sleep 100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	matches, err := d.WaitForOutputSubmatch("CapEff:\t([0-9a-f]+)\n", 5*time.Second)
	if err != nil {
		t.Fatalf("WaitForOutputSubmatch() timeout: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("There should be a match for the whole line and the capability bitmask")
	}
	want := fmt.Sprintf("CapEff:\t%s\n", matches[1])
	t.Log("Root capabilities:", want)

	// Now check that exec'd process capabilities match the root.
	got, err := d.Exec("grep", "CapEff:", "/proc/self/status")
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
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-privileged-test")

	// Start the container with all capabilities dropped.
	if err := d.Run("--cap-drop=all", "alpine", "sh", "-c", "cat /proc/self/status; sleep 100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Check that all capabilities where dropped from container.
	matches, err := d.WaitForOutputSubmatch("CapEff:\t([0-9a-f]+)\n", 5*time.Second)
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
	if containerCaps != 0 {
		t.Fatalf("Container should have no capabilities: %x", containerCaps)
	}

	// Check that 'exec --privileged' adds all capabilities, except
	// for CAP_NET_RAW.
	got, err := d.ExecWithFlags([]string{"--privileged"}, "grep", "CapEff:", "/proc/self/status")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	t.Logf("Exec CapEff: %v", got)
	want := fmt.Sprintf("CapEff:\t%016x\n", specutils.AllCapabilitiesUint64()&^bits.MaskOf64(int(linux.CAP_NET_RAW)))
	if got != want {
		t.Errorf("wrong capabilities, got: %q, want: %q", got, want)
	}
}

func TestExecJobControl(t *testing.T) {
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-job-control-test")

	// Start the container.
	if err := d.Run("alpine", "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Exec 'sh' with an attached pty.
	cmd, ptmx, err := d.ExecWithTerminal("sh")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	defer ptmx.Close()

	// Call "sleep 100 | cat" in the shell.  We pipe to cat so that there
	// will be two processes in the foreground process group.
	if _, err := ptmx.Write([]byte("sleep 100 | cat\n")); err != nil {
		t.Fatalf("error writing to pty: %v", err)
	}

	// Give shell a few seconds to start executing the sleep.
	time.Sleep(2 * time.Second)

	// Send a ^C to the pty, which should kill sleep and cat, but not the
	// shell.  \x03 is ASCII "end of text", which is the same as ^C.
	if _, err := ptmx.Write([]byte{'\x03'}); err != nil {
		t.Fatalf("error writing to pty: %v", err)
	}

	// The shell should still be alive at this point. Sleep should have
	// exited with code 2+128=130. We'll exit with 10 plus that number, so
	// that we can be sure that the shell did not get signalled.
	if _, err := ptmx.Write([]byte("exit $(expr $? + 10)\n")); err != nil {
		t.Fatalf("error writing to pty: %v", err)
	}

	// Exec process should exit with code 10+130=140.
	ps, err := cmd.Process.Wait()
	if err != nil {
		t.Fatalf("error waiting for exec process: %v", err)
	}
	ws := ps.Sys().(syscall.WaitStatus)
	if !ws.Exited() {
		t.Errorf("ws.Exited got false, want true")
	}
	if got, want := ws.ExitStatus(), 140; got != want {
		t.Errorf("ws.ExitedStatus got %d, want %d", got, want)
	}
}

// Test that failure to exec returns proper error message.
func TestExecError(t *testing.T) {
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-error-test")

	// Start the container.
	if err := d.Run("alpine", "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	_, err := d.Exec("no_can_find")
	if err == nil {
		t.Fatalf("docker exec didn't fail")
	}
	if want := `error finding executable "no_can_find" in PATH`; !strings.Contains(err.Error(), want) {
		t.Fatalf("docker exec wrong error, got: %s, want: .*%s.*", err.Error(), want)
	}
}

// Test that exec inherits environment from run.
func TestExecEnv(t *testing.T) {
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-env-test")

	// Start the container with env FOO=BAR.
	if err := d.Run("-e", "FOO=BAR", "alpine", "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Exec "echo $FOO".
	got, err := d.Exec("/bin/sh", "-c", "echo $FOO")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if want := "BAR"; !strings.Contains(got, want) {
		t.Errorf("wanted exec output to contain %q, got %q", want, got)
	}
}

// Test that exec always has HOME environment set, even when not set in run.
func TestExecEnvHasHome(t *testing.T) {
	// Base alpine image does not have any environment variables set.
	if err := dockerutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := dockerutil.MakeDocker("exec-env-home-test")

	// We will check that HOME is set for root user, and also for a new
	// non-root user we will create.
	newUID := 1234
	newHome := "/foo/bar"

	// Create a new user with a home directory, and then sleep.
	script := fmt.Sprintf(`
	mkdir -p -m 777 %s && \
	adduser foo -D -u %d -h %s && \
	sleep 1000`, newHome, newUID, newHome)
	if err := d.Run("alpine", "/bin/sh", "-c", script); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Exec "echo $HOME", and expect to see "/root".
	got, err := d.Exec("/bin/sh", "-c", "echo $HOME")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if want := "/root"; !strings.Contains(got, want) {
		t.Errorf("wanted exec output to contain %q, got %q", want, got)
	}

	// Execute the same as uid 123 and expect newHome.
	got, err = d.ExecAsUser(strconv.Itoa(newUID), "/bin/sh", "-c", "echo $HOME")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if want := newHome; !strings.Contains(got, want) {
		t.Errorf("wanted exec output to contain %q, got %q", want, got)
	}
}
