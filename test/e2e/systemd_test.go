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
	// These timeouts bound polls whose expected wait is a few seconds at
	// most. They are sized generously because on small, oversubscribed CI
	// machines a single docker exec round trip has been observed to take
	// tens of seconds.
	systemdBootTimeout = 2 * time.Minute
	daemonPollTimeout  = time.Minute
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
	if state := unitState(ctx, t, d, unit); state != wantInactiveState {
		t.Errorf("After stopping %s, ActiveState is wrong (got %q, want %q)", unit, state, wantInactiveState)
	}
}

// unitState returns the ActiveState of the given unit.
func unitState(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) string {
	t.Helper()
	return strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "show", "-p", "ActiveState", "--value", unit))
}

// TestSystemdBoot verifies that systemd boots to a "running" state and that
// core services (journald, logind) are active.
func TestSystemdBoot(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// setupSSHKeys generates any missing sshd host keys, and a root keypair
// authorized for login to self.
func setupSSHKeys(ctx context.Context, t *testing.T, d *dockerutil.Container) {
	t.Helper()
	execOrFatal(ctx, t, d, "bash", "-c", `
		ssh-keygen -A &&
		mkdir -p /root/.ssh &&
		rm -f /root/.ssh/id_ed25519 /root/.ssh/id_ed25519.pub &&
		ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519 &&
		cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
	`)
}

// waitForSSH retries a key-authenticated ssh round trip to localhost until it
// succeeds: sshd can take a moment to accept connections.
func waitForSSH(ctx context.Context, t *testing.T, d *dockerutil.Container) {
	t.Helper()
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
}

// TestSystemdSSH verifies that sshd accepts a key-authenticated session as a
// systemd service. This also exercises PAM and the pam_systemd/logind interaction.
func TestSystemdSSH(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	setupSSHKeys(ctx, t, d)
	startService(ctx, t, d, "ssh.service")
	waitForSSH(ctx, t, d)

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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// The tests below exercise systemd's event-driven activation mechanisms
// (timers, D-Bus, sockets) and the sd_notify watchdog protocol.

// TestSystemdTimer verifies that timer units fire repeatedly on both the
// monotonic clock (OnActiveSec/OnUnitActiveSec) and the realtime clock
// (OnCalendar).
func TestSystemdTimer(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	// Two transient timers, each appending a line to its file on every fire.
	// The default timer accuracy is 1 minute, so tighten it to keep the test
	// fast.
	execOrFatal(ctx, t, d, "systemd-run", "--unit=gv-timer-mono",
		"--on-active=1", "--on-unit-active=1", "--timer-property=AccuracySec=100ms",
		"/bin/sh", "-c", "echo fired >> /run/gv-timer-mono")
	execOrFatal(ctx, t, d, "systemd-run", "--unit=gv-timer-cal",
		"--on-calendar=*-*-* *:*:*", "--timer-property=AccuracySec=100ms",
		"/bin/sh", "-c", "echo fired >> /run/gv-timer-cal")

	// Each timer must fire at least twice: this proves both the initial fire
	// and the rescheduling of a repeating timer.
	for _, file := range []string{"/run/gv-timer-mono", "/run/gv-timer-cal"} {
		checkFiredTwice := func(ctx context.Context) error {
			out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "/bin/sh", "-c", "wc -l < "+file)
			if err != nil {
				return fmt.Errorf("cannot count timer fires: %v (output: %s)", err, out)
			}
			fires, err := strconv.Atoi(strings.TrimSpace(out))
			if err != nil {
				return fmt.Errorf("unexpected wc output %q: %v", out, err)
			}
			if fires < 2 {
				return fmt.Errorf("%s timer fired %d times, want at least 2", file, fires)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkFiredTwice); err != nil {
			t.Errorf("timer writing to %s did not fire repeatedly: %v", file, err)
		}
	}
}

// TestSystemdDBusActivation verifies that sending a message to a well-known
// bus name starts the service that owns it. systemd-hostnamed is D-Bus
// activated: it is started on demand when org.freedesktop.hostname1 is called.
func TestSystemdDBusActivation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	wantInactive := "inactive"
	if state := unitState(ctx, t, d, "systemd-hostnamed.service"); state != wantInactive {
		t.Fatalf("Before the bus call, systemd-hostnamed.service ActiveState is %q, want %q", state, wantInactive)
	}

	hostname := strings.TrimSpace(execOrFatal(ctx, t, d, "hostname"))
	out := execOrFatal(ctx, t, d, "busctl", "call", "org.freedesktop.hostname1",
		"/org/freedesktop/hostname1", "org.freedesktop.DBus.Properties", "Get",
		"ss", "org.freedesktop.hostname1", "Hostname")
	if wantReply := fmt.Sprintf("%q", hostname); !strings.Contains(out, wantReply) {
		t.Errorf("bus call reply does not contain the hostname %s:\n%s", wantReply, out)
	}

	wantActive := "active"
	if state := unitState(ctx, t, d, "systemd-hostnamed.service"); state != wantActive {
		t.Errorf("After the bus call, systemd-hostnamed.service ActiveState is %q, want %q", state, wantActive)
	}
}

// TestSystemdSocketActivation verifies socket activation: with only
// ssh.socket started, systemd starts ssh.service upon the first connection,
// and sshd serves that connection on the inherited listening socket.
func TestSystemdSocketActivation(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	setupSSHKeys(ctx, t, d)
	startService(ctx, t, d, "ssh.socket")

	// The socket is listening, but the service must only start upon the
	// first connection.
	wantInactive := "inactive"
	if state := unitState(ctx, t, d, "ssh.service"); state != wantInactive {
		t.Fatalf("After starting ssh.socket, ssh.service ActiveState is %q, want %q", state, wantInactive)
	}

	waitForSSH(ctx, t, d)

	wantActive := "active"
	if state := unitState(ctx, t, d, "ssh.service"); state != wantActive {
		t.Errorf("After connecting to the socket, ssh.service ActiveState is %q, want %q", state, wantActive)
	}
}

// TestSystemdWatchdog verifies the sd_notify watchdog protocol: a service
// that pings the watchdog stays up, and systemd kills it with Result=watchdog
// once the pings stop.
func TestSystemdWatchdog(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	// A transient notify service with a 5s watchdog: it pings the watchdog
	// every 0.5s until the stop file appears, then stops pinging while
	// staying alive.
	const stopFile = "/run/gv-watchdog-stop"
	execOrFatal(ctx, t, d, "systemd-run", "--unit=gv-watchdog",
		"-p", "Type=notify", "-p", "NotifyAccess=all", "-p", "WatchdogSec=5",
		"/bin/bash", "-c",
		"systemd-notify --ready; while [ ! -e "+stopFile+" ]; do systemd-notify WATCHDOG=1; sleep 0.5; done; sleep infinity")

	dumpJournal := func() string {
		journal, _ := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "journalctl", "-u", "gv-watchdog.service", "--no-pager")
		return journal
	}
	checkActive := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "is-active", "gv-watchdog.service")
		if err != nil || strings.TrimSpace(out) != "active" {
			return fmt.Errorf("gv-watchdog not active: %v (output: %s)", err, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkActive); err != nil {
		t.Fatalf("gv-watchdog did not start: %v\njournal:\n%s", err, dumpJournal())
	}

	// Well past WatchdogSec, the service must still be alive: the pings are
	// keeping the watchdog at bay.
	time.Sleep(6 * time.Second)
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkActive); err != nil {
		t.Fatalf("gv-watchdog died while still pinging the watchdog: %v\njournal:\n%s", err, dumpJournal())
	}

	// Tell the service to stop pinging. It stays alive (sleep infinity),
	// so any state change from here on is the watchdog's doing.
	execOrFatal(ctx, t, d, "touch", stopFile)

	// With the pings stopped, systemd must kill the service and record
	// the watchdog as the failure reason.
	wantState := "ActiveState=failed"
	wantResult := "Result=watchdog"
	checkWatchdogFired := func(ctx context.Context) error {
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "systemctl", "show", "-p", "ActiveState,Result", "gv-watchdog.service")
		if err != nil {
			return fmt.Errorf("systemctl show failed: %v (output: %s)", err, out)
		}
		if !strings.Contains(out, wantState) || !strings.Contains(out, wantResult) {
			return fmt.Errorf("gv-watchdog not yet killed by the watchdog (want %s and %s): %s", wantState, wantResult, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkWatchdogFired); err != nil {
		t.Errorf("systemd did not kill gv-watchdog after pings stopped: %v\njournal:\n%s", err, dumpJournal())
	}
}
