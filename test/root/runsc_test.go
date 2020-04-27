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
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

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

		cmdline, err := ioutil.ReadFile(filepath.Join("/proc", line, "cmdline"))
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
