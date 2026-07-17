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

	"gvisor.dev/gvisor/pkg/cleanup"
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

// execOrFatal runs a command inside the systemd container and returns its
// output. It fatals on error.
func execOrFatal(ctx context.Context, t *testing.T, d *dockerutil.Container, args ...string) string {
	t.Helper()
	out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, args...)
	if err != nil {
		t.Fatalf("exec %v failed: %v (output: %s)", args, err, out)
	}
	return out
}

// spawnSystemdContainer starts a container booting systemd from the given
// image and waits until systemd reports a "running" state. The returned
// container must be cleaned up by the caller.
func spawnSystemdContainer(ctx context.Context, t *testing.T, image string) *dockerutil.Container {
	t.Helper()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-cgroupv2")
	cu := cleanup.Make(func() { d.CleanUp(ctx) })
	defer cu.Clean()

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:      image,
		Privileged: true,
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if err := waitForSystemdBoot(ctx, d); err != nil {
		t.Fatalf("systemd did not boot: %v", err)
	}
	cu.Release()
	return d
}

// startService starts the given unit and waits for it to become active,
// dumping the unit's journal on failure.
func startService(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) {
	t.Helper()
	execOrFatal(ctx, t, d, "systemctl", "start", unit)
	checkUnitActive := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "is-active", unit)
		if err != nil || strings.TrimSpace(out) != "active" {
			return fmt.Errorf("%s not active: %v (output: %s)", unit, err, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkUnitActive); err != nil {
		journal, _ := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "journalctl", "-u", unit, "--no-pager")
		t.Fatalf("%s did not become active: %v\njournal:\n%s", unit, err, journal)
	}
}

// stopService stops the given unit and verifies that it becomes inactive.
func stopService(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) {
	t.Helper()
	wantInactiveState := "inactive"
	execOrFatal(ctx, t, d, "systemctl", "stop", unit)
	out := execOrFatal(ctx, t, d, "systemctl", "show", "-p", "ActiveState", "--value", unit)
	if state := strings.TrimSpace(out); state != wantInactiveState {
		t.Errorf("After stopping %s, ActiveState is wrong (got %q, want %q)", unit, state, wantInactiveState)
	}
}

// TestSystemdBoot verifies that systemd boots to a "running" state and that
// core services (journald, logind) are active.
func TestSystemdBoot(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	wantJournaldActive := "active (running)"
	out := execOrFatal(ctx, t, d, "systemctl", "status", "systemd-journald.service", "--no-pager")
	if !strings.Contains(out, wantJournaldActive) {
		t.Errorf("After systemd boot, systemd-journald service is not active (output does not contain %q):\n%s", wantJournaldActive, out)
	}

	wantLogindActive := "active (running)"
	out = execOrFatal(ctx, t, d, "systemctl", "status", "systemd-logind.service", "--no-pager")
	if !strings.Contains(out, wantLogindActive) {
		t.Errorf("After systemd boot, systemd-logind service is not active (output does not contain %q):\n%s", wantLogindActive, out)
	}
}

// TestSystemdSimpleDaemon verifies that a custom systemd service can be enabled, started,
// stopped, and restarted by systemd after an out-of-band kill.
func TestSystemdSimpleDaemon(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	execOrFatal(ctx, t, d, "systemctl", "enable", "test-daemon.service")
	startService(ctx, t, d, "test-daemon.service")

	wantDaemonActive := "active (running)"
	out := execOrFatal(ctx, t, d, "systemctl", "status", "test-daemon.service", "--no-pager")
	if !strings.Contains(out, wantDaemonActive) {
		t.Fatalf("After starting test-daemon.service, status is not active (output does not contain %q):\n%s", wantDaemonActive, out)
	}

	// Get the main PID.
	pidStr := strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid1, err := strconv.Atoi(pidStr)
	if err != nil || pid1 == 0 {
		t.Fatalf("unexpected MainPID %q: %v", pidStr, err)
	}
	t.Logf("test-daemon started with PID %d", pid1)

	// Verify journalctl has output from the daemon.
	wantJournalOutput := "Hello from test daemon"
	out = execOrFatal(ctx, t, d, "journalctl", "-u", "test-daemon.service", "--no-pager")
	if !strings.Contains(out, wantJournalOutput) {
		t.Errorf("After starting test-daemon.service, journalctl is missing expected output (output does not contain %q):\n%s", wantJournalOutput, out)
	}

	// Stop the daemon and verify it is inactive.
	stopService(ctx, t, d, "test-daemon.service")

	// Start the daemon again, and grab its PID.
	startService(ctx, t, d, "test-daemon.service")
	pidStr = strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid2, err := strconv.Atoi(pidStr)
	if err != nil || pid2 == 0 {
		t.Fatalf("unexpected MainPID after restart %q: %v", pidStr, err)
	}
	t.Logf("test-daemon restarted with PID %d, killing it", pid2)

	// Kill the daemon out-of-band.
	execOrFatal(ctx, t, d, "kill", "-9", strconv.Itoa(pid2))

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
	pidStr = strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", "test-daemon.service"))
	pid3, err := strconv.Atoi(pidStr)
	if err != nil || pid3 == 0 {
		t.Fatalf("unexpected MainPID after restart %q: %v", pidStr, err)
	}
	t.Logf("systemd restarted daemon with new PID %d (was %d)", pid3, pid2)
	if pid3 == pid2 {
		t.Errorf("After out-of-band kill (kill -9 %d), systemctl reports test-daemon.service restarted but did not get a new PID (got same PID %d)", pid2, pid3)
	}
}

// The tests below verify that popular software installed as systemd services
// runs under systemd inside gVisor. Each test boots the "systemd-services"
// image (where all service packages are installed but disabled), starts only
// the service under test, and exercises it end-to-end.

// TestSystemdNginx verifies that nginx serves HTTP as a systemd service and
// survives a `systemctl reload` (SIGHUP to the master process).
func TestSystemdNginx(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "nginx.service")
	// Check the Server header: nginx and apache share the /var/www/html
	// docroot, so the page content does not identify the server.
	wantServerHeader := "Server: nginx"
	out := execOrFatal(ctx, t, d, "curl", "-fsSI", "http://127.0.0.1/")
	if !strings.Contains(out, wantServerHeader) {
		t.Errorf("nginx response does not contain %q:\n%s", wantServerHeader, out)
	}

	// Reload and verify it still serves.
	execOrFatal(ctx, t, d, "systemctl", "reload", "nginx.service")
	out = execOrFatal(ctx, t, d, "curl", "-fsSI", "http://127.0.0.1/")
	if !strings.Contains(out, wantServerHeader) {
		t.Errorf("nginx response after reload does not contain %q:\n%s", wantServerHeader, out)
	}

	stopService(ctx, t, d, "nginx.service")
}

// TestSystemdApache verifies that Apache httpd serves HTTP as a systemd service.
func TestSystemdApache(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "apache2.service")
	wantServerHeader := "Server: Apache"
	out := execOrFatal(ctx, t, d, "curl", "-fsSI", "http://127.0.0.1/")
	if !strings.Contains(out, wantServerHeader) {
		t.Errorf("apache response does not contain %q:\n%s", wantServerHeader, out)
	}

	// Graceful reload.
	execOrFatal(ctx, t, d, "systemctl", "reload", "apache2.service")
	out = execOrFatal(ctx, t, d, "curl", "-fsSI", "http://127.0.0.1/")
	if !strings.Contains(out, wantServerHeader) {
		t.Errorf("apache response after reload does not contain %q:\n%s", wantServerHeader, out)
	}

	stopService(ctx, t, d, "apache2.service")
}

// TestSystemdSSH verifies that sshd accepts a key-authenticated session as a
// systemd service. This also exercises PAM and the pam_systemd/logind interaction.
func TestSystemdSSH(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	// Generate any missing sshd host keys, and a root keypair authorized for
	// login to self.
	execOrFatal(ctx, t, d, "bash", "-c", `
		ssh-keygen -A &&
		mkdir -p /root/.ssh &&
		rm -f /root/.ssh/id_ed25519 /root/.ssh/id_ed25519.pub &&
		ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 &&
		cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
	`)

	startService(ctx, t, d, "ssh.service")

	// Retry the ssh handshake: sshd can take a moment to accept connections
	// after the unit reports active.
	wantEcho := "ssh-ok"
	checkSSH := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"},
			"ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
			"root@127.0.0.1", "echo", wantEcho)
		if err != nil || !strings.Contains(out, wantEcho) {
			return fmt.Errorf("ssh failed: %v (output does not contain %q): %s", err, wantEcho, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkSSH); err != nil {
		t.Fatalf("could not ssh to localhost: %v", err)
	}

	// Verify the login was registered with logind, i.e. that pam_systemd ran:
	// from inside the ssh session, the caller's own logind session ("self")
	// must exist and have class "user".
	wantClass := "Class=user"
	out := execOrFatal(ctx, t, d,
		"ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
		"root@127.0.0.1", "loginctl", "show-session", "self", "-p", "Class")
	if !strings.Contains(out, wantClass) {
		t.Errorf("ssh session not registered with logind (output does not contain %q):\n%s", wantClass, out)
	}

	stopService(ctx, t, d, "ssh.service")
}

// TestSystemdPostgreSQL verifies that PostgreSQL runs as a systemd service
// and can execute a create/insert/select round trip.
func TestSystemdPostgreSQL(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "postgresql.service")

	// postgresql.service is a wrapper unit; wait until the cluster actually
	// accepts connections.
	wantReady := "accepting connections"
	checkPostgresReady := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "sudo", "-u", "postgres", "pg_isready")
		if err != nil || !strings.Contains(out, wantReady) {
			return fmt.Errorf("postgres not ready: %v (output does not contain %q): %s", err, wantReady, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, time.Minute, checkPostgresReady); err != nil {
		t.Fatalf("postgres did not accept connections: %v", err)
	}

	execOrFatal(ctx, t, d, "sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", "CREATE TABLE gv (i int)")
	execOrFatal(ctx, t, d, "sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c", "INSERT INTO gv VALUES (42)")
	wantValue := "42"
	out := execOrFatal(ctx, t, d, "sudo", "-u", "postgres", "psql", "-tA", "-c", "SELECT i FROM gv")
	if !strings.Contains(out, wantValue) {
		t.Errorf("select output does not contain %q:\n%s", wantValue, out)
	}

	stopService(ctx, t, d, "postgresql.service")
}

// TestSystemdMariaDB verifies that MariaDB runs as a systemd service and can
// execute a create/insert/select round trip.
func TestSystemdMariaDB(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "mariadb.service")

	execOrFatal(ctx, t, d, "mysql", "-e", "CREATE DATABASE gv; CREATE TABLE gv.t (i INT); INSERT INTO gv.t VALUES (42);")
	wantValue := "42"
	out := execOrFatal(ctx, t, d, "mysql", "-Ne", "SELECT i FROM gv.t")
	if !strings.Contains(out, wantValue) {
		t.Errorf("select output does not contain %q:\n%s", wantValue, out)
	}

	stopService(ctx, t, d, "mariadb.service")
}

// TestSystemdRedis verifies that Redis runs as a systemd service (Type=notify)
// and that a background save (which fork()s the server) succeeds.
func TestSystemdRedis(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "redis-server.service")

	wantPing := "PONG"
	if out := execOrFatal(ctx, t, d, "redis-cli", "ping"); !strings.Contains(out, wantPing) {
		t.Errorf("ping output does not contain %q: %s", wantPing, out)
	}
	wantValue := "42"
	execOrFatal(ctx, t, d, "redis-cli", "set", "gv", wantValue)
	if out := execOrFatal(ctx, t, d, "redis-cli", "get", "gv"); !strings.Contains(out, wantValue) {
		t.Errorf("get output does not contain %q: %s", wantValue, out)
	}

	// Force a background save to exercise the fork() path.
	execOrFatal(ctx, t, d, "redis-cli", "bgsave")
	wantBgsaveDone := "rdb_bgsave_in_progress:0"
	wantBgsaveOK := "rdb_last_bgsave_status:ok"
	checkBgsave := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "redis-cli", "info", "persistence")
		if err != nil {
			return fmt.Errorf("redis-cli info failed: %v", err)
		}
		if !strings.Contains(out, wantBgsaveDone) {
			return fmt.Errorf("bgsave still in progress (output does not contain %q)", wantBgsaveDone)
		}
		if !strings.Contains(out, wantBgsaveOK) {
			return fmt.Errorf("bgsave did not succeed (output does not contain %q):\n%s", wantBgsaveOK, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkBgsave); err != nil {
		t.Fatalf("redis background save failed: %v", err)
	}

	stopService(ctx, t, d, "redis-server.service")
}

const alpineImageRef = "mirror.gcr.io/library/alpine:3.22"

// TestSystemdDocker verifies that dockerd runs as a systemd service: the unit
// becomes active, the daemon answers API requests, and it can pull images.
func TestSystemdDocker(t *testing.T) {
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	startService(ctx, t, d, "docker.service")

	// The daemon must be responsive.
	execOrFatal(ctx, t, d, "docker", "info")

	// Pull an image and verify it is stored.
	execOrFatal(ctx, t, d, "docker", "pull", alpineImageRef)
	wantImage := "mirror.gcr.io/library/alpine"
	out := execOrFatal(ctx, t, d, "docker", "image", "ls", alpineImageRef)
	if !strings.Contains(out, wantImage) {
		t.Errorf("pulled image not listed (output does not contain %q):\n%s", wantImage, out)
	}

	stopService(ctx, t, d, "docker.service")
}
