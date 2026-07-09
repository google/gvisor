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

package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	systemdBootTimeout = time.Minute
	daemonPollTimeout  = 30 * time.Second
)

func pollWithTimeout(ctx context.Context, timeout time.Duration, cb func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return testutil.PollContext(ctx, func() error {
		return cb(ctx)
	})
}

// waitForSystemdBoot polls `systemctl status` until systemd reports "running".
func waitForSystemdBoot(ctx context.Context, d *dockerutil.Container) error {
	isSystemdRunning := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "status", "--no-pager")
		// systemctl status returns non-zero when degraded or starting,
		// but still produces useful output. Check the output regardless.
		if strings.Contains(out, "State: running") {
			return nil
		}
		if err != nil {
			return fmt.Errorf("systemctl status failed: %v (output: %s)", err, out)
		}
		return fmt.Errorf("systemd not yet running, output: %s", out)
	}

	return pollWithTimeout(ctx, systemdBootTimeout, isSystemdRunning)
}

// systemdExec runs a command inside the systemd container and returns its
// output. It fatals on error.
func systemdExec(ctx context.Context, t *testing.T, d *dockerutil.Container, args ...string) string {
	t.Helper()
	out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, args...)
	if err != nil {
		t.Fatalf("exec %v failed: %v (output: %s)", args, err, out)
	}
	return out
}

// TestSystemdBoot verifies that systemd boots to a "running" state and that
// core services (journald, logind) are active.
func TestSystemdBoot(t *testing.T) {
	ctx := t.Context()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-cgroupv2")
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:      "systemd-integ",
		Privileged: true,
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	if err := waitForSystemdBoot(ctx, d); err != nil {
		t.Fatalf("systemd did not boot: %v", err)
	}

	wantJournaldActive := "active (running)"
	out := systemdExec(ctx, t, d, "systemctl", "status", "systemd-journald.service", "--no-pager")
	if !strings.Contains(out, wantJournaldActive) {
		t.Errorf("After systemd boot, systemd-journald service is not active (output does not contain %q):\n%s", wantJournaldActive, out)
	}

	wantLogindActive := "active (running)"
	out = systemdExec(ctx, t, d, "systemctl", "status", "systemd-logind.service", "--no-pager")
	if !strings.Contains(out, wantLogindActive) {
		t.Errorf("After systemd boot, systemd-logind service is not active (output does not contain %q):\n%s", wantLogindActive, out)
	}
}

// TestSystemdSimpleDaemon verifies that a custom systemd service can be enabled, started,
// stopped, and restarted by systemd after an out-of-band kill.
func TestSystemdSimpleDaemon(t *testing.T) {
	ctx := t.Context()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-cgroupv2")
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:      "systemd-integ",
		Privileged: true,
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	if err := waitForSystemdBoot(ctx, d); err != nil {
		t.Fatalf("systemd did not boot: %v", err)
	}

	systemdExec(ctx, t, d, "systemctl", "enable", "test-daemon.service")
	systemdExec(ctx, t, d, "systemctl", "start", "test-daemon.service")

	checkDaemonActive := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "is-active", "test-daemon.service")
		if err != nil || strings.TrimSpace(out) != "active" {
			return fmt.Errorf("test-daemon not active: %v (output: %s)", err, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkDaemonActive); err != nil {
		t.Fatalf("test-daemon did not start: %v", err)
	}

	wantDaemonActive := "active (running)"
	out := systemdExec(ctx, t, d, "systemctl", "status", "test-daemon.service", "--no-pager")
	if !strings.Contains(out, wantDaemonActive) {
		t.Fatalf("After starting test-daemon.service, status is not active (output does not contain %q):\n%s", wantDaemonActive, out)
	}

	// Get the main PID.
	pidStr := strings.TrimSpace(systemdExec(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid1, err := strconv.Atoi(pidStr)
	if err != nil || pid1 == 0 {
		t.Fatalf("unexpected MainPID %q: %v", pidStr, err)
	}
	t.Logf("test-daemon started with PID %d", pid1)

	// Verify journalctl has output from the daemon.
	wantJournalOutput := "Hello from test daemon"
	out = systemdExec(ctx, t, d, "journalctl", "-u", "test-daemon.service", "--no-pager")
	if !strings.Contains(out, wantJournalOutput) {
		t.Errorf("After starting test-daemon.service, journalctl is missing expected output (output does not contain %q):\n%s", wantJournalOutput, out)
	}

	// Stop the daemon and verify it is inactive.
	wantInactiveState := "inactive"
	systemdExec(ctx, t, d, "systemctl", "stop", "test-daemon.service")
	out = systemdExec(ctx, t, d, "systemctl", "show", "-p", "ActiveState", "--value", "test-daemon.service")
	if state := strings.TrimSpace(out); state != wantInactiveState {
		t.Errorf("After stopping test-daemon.service, ActiveState is wrong (got %q, want %q):\n%s", state, wantInactiveState, out)
	}

	// Start the daemon again, and grab its PID.
	systemdExec(ctx, t, d, "systemctl", "start", "test-daemon.service")
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkDaemonActive); err != nil {
		t.Fatalf("test-daemon did not restart: %v", err)
	}
	pidStr = strings.TrimSpace(systemdExec(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid2, err := strconv.Atoi(pidStr)
	if err != nil || pid2 == 0 {
		t.Fatalf("unexpected MainPID after restart %q: %v", pidStr, err)
	}
	t.Logf("test-daemon restarted with PID %d, killing it", pid2)

	// Kill the daemon out-of-band.
	systemdExec(ctx, t, d, "kill", "-9", strconv.Itoa(pid2))

	checkDaemonRestartedWithNewPID := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "is-active", "test-daemon.service")
		if err != nil || strings.TrimSpace(out) != "active" {
			return fmt.Errorf("test-daemon not restarted yet: %v (output: %s)", err, out)
		}
		pidStr, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service")
		if err != nil {
			return fmt.Errorf("cannot get MainPID: %v", err)
		}
		pid3, err := strconv.Atoi(strings.TrimSpace(pidStr))
		if err != nil || pid3 == 0 {
			return fmt.Errorf("unexpected MainPID %q", pidStr)
		}
		if pid3 == pid2 {
			return fmt.Errorf("PID has not changed yet (still %d)", pid2)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkDaemonRestartedWithNewPID); err != nil {
		t.Fatalf("systemd did not restart the daemon after kill: %v", err)
	}

	// Final verification: the daemon is running with a new PID.
	pidStr = strings.TrimSpace(systemdExec(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid3, _ := strconv.Atoi(pidStr)
	t.Logf("systemd restarted daemon with new PID %d (was %d)", pid3, pid2)
	if pid3 == pid2 {
		t.Errorf("After out-of-band kill (kill -9 %d), systemctl reports test-daemon.service restarted but did not get a new PID (got same PID %d)", pid2, pid3)
	}
}
