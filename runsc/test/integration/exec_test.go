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

// Package image provides end-to-end integration tests for runsc. These tests require
// docker and runsc to be installed on the machine. To set it up, run:
//
//     ./runsc/test/install.sh [--runtime <name>]
//
// The tests expect the runtime name to be provided in the RUNSC_RUNTIME
// environment variable (default: runsc-test).
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, with various runsc commands. The container is killed and deleted
// at the end.

package integration

import (
	"fmt"
	"strconv"
	"syscall"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

func TestExecCapabilities(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("exec-test")

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
	capString := matches[1]
	t.Log("Root capabilities:", capString)

	// CAP_NET_RAW was in the capability set for the container, but was
	// removed. However, `exec` does not remove it. Verify that it's not
	// set in the container, then re-add it for comparison.
	caps, err := strconv.ParseUint(capString, 16, 64)
	if err != nil {
		t.Fatalf("failed to convert capabilities %q: %v", capString, err)
	}
	if caps&(1<<uint64(linux.CAP_NET_RAW)) != 0 {
		t.Fatalf("CAP_NET_RAW should be filtered, but is set in the container: %x", caps)
	}
	caps |= 1 << uint64(linux.CAP_NET_RAW)
	want := fmt.Sprintf("CapEff:\t%016x\n", caps)

	// Now check that exec'd process capabilities match the root.
	got, err := d.Exec("grep", "CapEff:", "/proc/self/status")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if got != want {
		t.Errorf("wrong capabilities, got: %q, want: %q", got, want)
	}
}

func TestExecJobControl(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("exec-job-control-test")

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
