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

// waitForUnitActive polls until the given unit becomes active, dumping the
// unit's journal on failure.
func waitForUnitActive(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) {
	t.Helper()
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

// startService starts the given unit and waits for it to become active,
// dumping the unit's journal on failure.
func startService(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) {
	t.Helper()
	execOrFatal(ctx, t, d, "systemctl", "start", unit)
	waitForUnitActive(ctx, t, d, unit)
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

// unitCgroupDir returns the cgroupfs directory of the given unit's main
// process, derived from /proc rather than hardcoded: the container may share
// the host's cgroup namespace (docker's default on cgroup-v1 hosts), which
// prefixes every cgroup path with the container's own.
func unitCgroupDir(ctx context.Context, t *testing.T, d *dockerutil.Container, unit string) string {
	t.Helper()
	pid := strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "show", "-p", "MainPID", "--value", unit))
	cg := strings.TrimSpace(execOrFatal(ctx, t, d, "cat", "/proc/"+pid+"/cgroup"))
	return "/sys/fs/cgroup" + strings.TrimPrefix(cg, "0::")
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

// TestSystemdUBI10Init boots Red Hat's UBI 10 init image: a second systemd
// lineage (RHEL 10, systemd v257, which mandates cgroup v2).
func TestSystemdUBI10Init(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "ubi10-init")
	defer d.CleanUp(ctx)

	if out := strings.TrimSpace(execOrFatal(ctx, t, d, "systemctl", "--failed", "--no-legend", "--plain")); out != "" {
		t.Errorf("failed units after boot (want none):\n%s", out)
	}
	wantEcho := "gv-ubi10-ok"
	out, err := transientRun(ctx, d, nil, "/bin/echo", wantEcho)
	if err != nil || !strings.Contains(out, wantEcho) {
		t.Errorf("transient unit failed: %v (output does not contain %q): %s", err, wantEcho, out)
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

// TestSystemdDocker verifies that dockerd runs as a systemd service and can
// pull images and run containers.
func TestSystemdDocker(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-services")
	defer d.CleanUp(ctx)

	// Overlay upper layers cannot sit on runsc's sandbox-internal overlay
	// rootfs, so back the state directories with tmpfs.
	execOrFatal(ctx, t, d, "mkdir", "-p", "/var/lib/docker", "/var/lib/containerd")
	execOrFatal(ctx, t, d, "mount", "-t", "tmpfs", "tmpfs", "/var/lib/docker")
	execOrFatal(ctx, t, d, "mount", "-t", "tmpfs", "tmpfs", "/var/lib/containerd")

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

	// Run a command in a container from the pulled image (--network=none:
	// the image disables dockerd's iptables integration).
	wantRelease := "Alpine Linux"
	out = execOrFatal(ctx, t, d, "docker", "run", "--network=none", "--rm", alpineImageRef, "cat", "/etc/os-release")
	if !strings.Contains(out, wantRelease) {
		t.Errorf("running a container did not produce its output (output does not contain %q):\n%s", wantRelease, out)
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

// The tests below exercise kernel functionality that core PID1 machinery
// depends on. They are patterned after systemd's own integration tests
// (test/units/TEST-* in the systemd repo).

// transientRun runs a command synchronously in a transient unit via
// `systemd-run --pipe` with the given unit properties.
func transientRun(ctx context.Context, d *dockerutil.Container, props []string, argv ...string) (string, error) {
	args := []string{"systemd-run", "--quiet", "--collect", "--wait", "--pipe"}
	for _, p := range props {
		args = append(args, "--property="+p)
	}
	args = append(args, "--")
	args = append(args, argv...)
	return d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, args...)
}

// TestSystemdExecSandboxing verifies per-service sandboxing knobs:
// PrivateTmp=, ProtectSystem=strict, User=, and NoNewPrivileges=.
func TestSystemdExecSandboxing(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	defer d.CleanUp(ctx)

	// A marker in the host /tmp must be invisible under PrivateTmp=yes.
	hostMarker := "gv-host-marker"
	execOrFatal(ctx, t, d, "touch", "/tmp/"+hostMarker)
	out, err := transientRun(ctx, d, []string{"PrivateTmp=yes"}, "/bin/ls", "/tmp")
	if err != nil {
		t.Fatalf("systemd-run with PrivateTmp=yes failed: %v (output: %s)", err, out)
	}
	if strings.Contains(out, hostMarker) {
		t.Errorf("PrivateTmp=yes service sees the host /tmp (output contains %q):\n%s", hostMarker, out)
	}
	// And a file created in the private /tmp must not leak to the host /tmp.
	if out, err := transientRun(ctx, d, []string{"PrivateTmp=yes"}, "/usr/bin/touch", "/tmp/gv-private-marker"); err != nil {
		t.Fatalf("touch in the private /tmp failed: %v (output: %s)", err, out)
	}
	if out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "test", "-e", "/tmp/gv-private-marker"); err == nil {
		t.Errorf("file created under PrivateTmp=yes leaked to the host /tmp (output: %s)", out)
	}

	// ProtectSystem=strict must make /usr read-only.
	wantEROFS := "Read-only file system"
	out, _ = transientRun(ctx, d, []string{"ProtectSystem=strict"}, "/bin/bash", "-c", "touch /usr/gv-protected 2>&1")
	if !strings.Contains(out, wantEROFS) {
		t.Errorf("writing /usr under ProtectSystem=strict did not fail with EROFS (output does not contain %q):\n%s", wantEROFS, out)
	}
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "test", "-e", "/usr/gv-protected"); err == nil {
		t.Errorf("ProtectSystem=strict did not prevent creating /usr/gv-protected")
	}

	// User= must run the payload as the requested user.
	wantUser := "nobody"
	out, err = transientRun(ctx, d, []string{"User=nobody"}, "/usr/bin/id", "-un")
	if err != nil {
		t.Fatalf("systemd-run with User=nobody failed: %v (output: %s)", err, out)
	}
	if got := strings.TrimSpace(out); got != wantUser {
		t.Errorf("User=nobody service runs as the wrong user (got %q, want %q)", got, wantUser)
	}

	// NoNewPrivileges= must set the no_new_privs bit.
	nnpProbe := `awk '/^NoNewPrivs:/{print $2}' /proc/self/status`
	wantNNP := "1"
	out, err = transientRun(ctx, d, []string{"NoNewPrivileges=yes"}, "/bin/bash", "-c", nnpProbe)
	if err != nil {
		t.Fatalf("systemd-run with NoNewPrivileges=yes failed: %v (output: %s)", err, out)
	}
	if got := strings.TrimSpace(out); got != wantNNP {
		t.Errorf("NoNewPrivileges=yes service has the wrong no_new_privs bit (got %q, want %q)", got, wantNNP)
	}
	// Control: without the property the bit must be unset, proving the
	// probe does not always report 1.
	wantNoNNP := "0"
	out, err = transientRun(ctx, d, nil, "/bin/bash", "-c", nnpProbe)
	if err != nil {
		t.Fatalf("systemd-run for the no_new_privs control failed: %v (output: %s)", err, out)
	}
	if got := strings.TrimSpace(out); got != wantNoNNP {
		t.Errorf("service without NoNewPrivileges has the wrong no_new_privs bit (got %q, want %q)", got, wantNoNNP)
	}
}

// userExec runs a command as the given user, as a transient unit in the
// user's service manager (systemd-run --machine=<user>@.host --user).
// Unlike `docker exec --user`, the user is resolved inside the sandbox.
// The command line is parsed as an ExecStart= value, so "$$" escapes a
// literal "$".
func userExec(ctx context.Context, d *dockerutil.Container, user string, args ...string) (string, error) {
	fullArgs := append([]string{"systemd-run", "--machine=" + user + "@.host", "--user",
		"--quiet", "--collect", "--wait", "--pipe", "--"}, args...)
	return d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, fullArgs...)
}

// userExecOrFatal is userExec, fataling on error.
func userExecOrFatal(ctx context.Context, t *testing.T, d *dockerutil.Container, user string, args ...string) string {
	t.Helper()
	out, err := userExec(ctx, d, user, args...)
	if err != nil {
		t.Fatalf("exec %v as %s failed: %v (output: %s)", args, user, err, out)
	}
	return out
}

// TestSystemdMultiUser proves multiuser operation: unprivileged per-user
// managers in delegated cgroup subtrees, per-user daemons and journals, and
// enforcement between users. The subtests share one container and run in
// parallel, so cleanup is registered with t.Cleanup rather than deferred.
func TestSystemdMultiUser(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	d := spawnSystemdContainer(ctx, t, "systemd-integ")
	t.Cleanup(func() { d.CleanUp(context.Background()) })

	const (
		aliceUID = 1001
		bobUID   = 1002
	)
	aliceUnit := fmt.Sprintf("user@%d.service", aliceUID)
	bobUnit := fmt.Sprintf("user@%d.service", bobUID)

	// Fixture: two users, persistent journal, both managers booted via
	// lingering (no login needed).
	execOrFatal(ctx, t, d, "useradd", "-m", "-u", strconv.Itoa(aliceUID), "alice")
	execOrFatal(ctx, t, d, "useradd", "-m", "-u", strconv.Itoa(bobUID), "bob")
	// journald only splits out per-user journal files (and ACLs them) when
	// /var/log/journal exists.
	execOrFatal(ctx, t, d, "mkdir", "-p", "/var/log/journal")
	execOrFatal(ctx, t, d, "systemctl", "restart", "systemd-journald")
	execOrFatal(ctx, t, d, "journalctl", "--flush")
	execOrFatal(ctx, t, d, "loginctl", "enable-linger", "alice", "bob")
	waitForUnitActive(ctx, t, d, aliceUnit)
	waitForUnitActive(ctx, t, d, bobUnit)
	checkManagerRunning := func(ctx context.Context) error {
		out, err := userExec(ctx, d, "alice", "systemctl", "--user", "is-system-running")
		if err != nil || strings.TrimSpace(out) != "running" {
			return fmt.Errorf("alice's manager not running: %v (output: %s)", err, out)
		}
		return nil
	}
	if err := pollWithTimeout(ctx, daemonPollTimeout, checkManagerRunning); err != nil {
		t.Fatalf("alice's user manager did not reach the running state: %v", err)
	}
	aliceCgroup := strings.TrimSuffix(unitCgroupDir(ctx, t, d, aliceUnit), "/init.scope")

	t.Run("RuntimeDir", func(t *testing.T) {
		t.Parallel()
		// The per-user runtime directory must be a private tmpfs owned by
		// the user.
		runtimeDir := fmt.Sprintf("/run/user/%d", aliceUID)
		wantFstype := "tmpfs"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "findmnt", "-n", "-o", "FSTYPE", runtimeDir)); got != wantFstype {
			t.Errorf("%s has the wrong filesystem type (got %q, want %q)", runtimeDir, got, wantFstype)
		}
		wantOwnerMode := "alice 700"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U %a", runtimeDir)); got != wantOwnerMode {
			t.Errorf("%s has the wrong owner/mode (got %q, want %q)", runtimeDir, got, wantOwnerMode)
		}
	})

	t.Run("MachinedShell", func(t *testing.T) {
		t.Parallel()
		// machinectl shell asks systemd-machined to allocate a pty and
		// spawn the command as the target user.
		wantUser := "alice"
		out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root", UseTTY: true},
			"machinectl", "--quiet", "shell", "alice@.host", "/usr/bin/id", "-un")
		if err != nil {
			t.Fatalf("machinectl shell failed: %v (output: %s)", err, out)
		}
		if !strings.Contains(out, wantUser) {
			t.Errorf("machinectl shell ran as the wrong user (output does not contain %q):\n%s", wantUser, out)
		}
	})

	t.Run("CgroupDelegation", func(t *testing.T) {
		t.Parallel()
		// The delegated subtree must be chowned to the user...
		wantOwner := "alice"
		for _, path := range []string{aliceCgroup, aliceCgroup + "/cgroup.procs", aliceCgroup + "/cgroup.subtree_control"} {
			if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U", path)); got != wantOwner {
				t.Errorf("%s has the wrong owner (got %q, want %q)", path, got, wantOwner)
			}
		}
		// ...the unprivileged manager must have built its own hierarchy
		// inside it...
		execOrFatal(ctx, t, d, "test", "-d", aliceCgroup+"/init.scope")
		// ...and controllers must be available for delegation.
		out := execOrFatal(ctx, t, d, "cat", aliceCgroup+"/cgroup.controllers")
		for _, want := range []string{"memory", "pids"} {
			if !strings.Contains(out, want) {
				t.Errorf("delegated cgroup.controllers is missing %q: %s", want, out)
			}
		}
	})

	t.Run("UserUnits", func(t *testing.T) {
		t.Parallel()
		// A transient user unit must run as the user, inside the
		// delegated subtree, with limits written by its manager.
		userExecOrFatal(ctx, t, d, "alice", "systemd-run", "--user", "--quiet", "--collect",
			"--unit=gv-user-svc", "--property=MemoryMax=64M", "/bin/sleep", "infinity")
		checkActive := func(ctx context.Context) error {
			out, err := userExec(ctx, d, "alice", "systemctl", "--user", "is-active", "gv-user-svc.service")
			if err != nil || strings.TrimSpace(out) != "active" {
				return fmt.Errorf("gv-user-svc not active: %v (output: %s)", err, out)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkActive); err != nil {
			t.Fatalf("alice's transient unit did not become active: %v", err)
		}

		pidStr := strings.TrimSpace(userExecOrFatal(ctx, t, d, "alice",
			"systemctl", "--user", "show", "-p", "MainPID", "--value", "gv-user-svc.service"))
		wantOwner := "alice"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U", "/proc/"+pidStr)); got != wantOwner {
			t.Errorf("the user unit's main process runs as the wrong user (got %q, want %q)", got, wantOwner)
		}

		// The unit's cgroup must live inside the delegated subtree.
		cgOut := strings.TrimSpace(execOrFatal(ctx, t, d, "cat", "/proc/"+pidStr+"/cgroup"))
		cgPath := strings.TrimPrefix(cgOut, "0::")
		wantSubtree := fmt.Sprintf("/user@%d.service/", aliceUID)
		if !strings.Contains(cgPath, wantSubtree) || !strings.Contains(cgPath, "gv-user-svc.service") {
			t.Errorf("the user unit's cgroup %q is not inside the delegated subtree (want it to contain %q and %q)", cgPath, wantSubtree, "gv-user-svc.service")
		}
		// And MemoryMax= must have been written through by the unprivileged
		// manager.
		wantMemMax := "67108864"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "cat", "/sys/fs/cgroup"+cgPath+"/memory.max")); got != wantMemMax {
			t.Errorf("the user unit's memory.max is wrong (got %q, want %q)", got, wantMemMax)
		}

		userExecOrFatal(ctx, t, d, "alice", "systemctl", "--user", "stop", "gv-user-svc.service")
	})

	t.Run("UserDaemon", func(t *testing.T) {
		t.Parallel()
		// gpg-agent's socket unit sits in the user manager; the first
		// gpg invocation must socket-activate the daemon.
		userExecOrFatal(ctx, t, d, "alice", "systemctl", "--user", "start", "gpg-agent.socket")
		wantInactive := "inactive"
		out, _ := userExec(ctx, d, "alice", "systemctl", "--user", "is-active", "gpg-agent.service")
		if got := strings.TrimSpace(out); got != wantInactive {
			t.Fatalf("before first use, gpg-agent.service state is wrong (got %q, want %q)", got, wantInactive)
		}

		// First use: key generation connects to the listening socket.
		userExecOrFatal(ctx, t, d, "alice", "gpg", "--batch", "--pinentry-mode", "loopback",
			"--passphrase", "", "--quick-gen-key", "alice@gvisor.test", "default", "default")
		wantActive := "active"
		if out, err := userExec(ctx, d, "alice", "systemctl", "--user", "is-active", "gpg-agent.service"); err != nil || strings.TrimSpace(out) != wantActive {
			t.Fatalf("after first gpg use, gpg-agent.service was not socket-activated: %v (output: %s)", err, out)
		}

		// The agent gpg talks to must be the systemd-supervised process...
		mainPID := strings.TrimSpace(userExecOrFatal(ctx, t, d, "alice",
			"systemctl", "--user", "show", "-p", "MainPID", "--value", "gpg-agent.service"))
		agentPID := strings.TrimSpace(userExecOrFatal(ctx, t, d, "alice", "/bin/sh", "-c",
			"gpg-connect-agent 'getinfo pid' /bye | awk '/^D/{print $2}'"))
		if mainPID == "0" || mainPID != agentPID {
			t.Errorf("the agent serving gpg is not the systemd-supervised one (unit MainPID %q, agent reports pid %q)", mainPID, agentPID)
		}
		// ...running as alice inside her delegated cgroup subtree.
		wantOwner := "alice"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U", "/proc/"+mainPID)); got != wantOwner {
			t.Errorf("gpg-agent runs as the wrong user (got %q, want %q)", got, wantOwner)
		}
		wantSubtree := fmt.Sprintf("/user@%d.service/", aliceUID)
		if cg := strings.TrimSpace(execOrFatal(ctx, t, d, "cat", "/proc/"+mainPID+"/cgroup")); !strings.Contains(cg, wantSubtree) {
			t.Errorf("gpg-agent's cgroup %q is outside the delegated subtree (want it to contain %q)", cg, wantSubtree)
		}

		// End-to-end: sign and verify through the daemon.
		wantGood := "Good signature"
		out = userExecOrFatal(ctx, t, d, "alice", "/bin/sh", "-c",
			"echo gv-sign-payload > /tmp/gv-msg && gpg --batch --yes -u alice@gvisor.test --output /tmp/gv-msg.sig --sign /tmp/gv-msg && gpg --verify /tmp/gv-msg.sig 2>&1")
		if !strings.Contains(out, wantGood) {
			t.Errorf("sign/verify through gpg-agent failed (output does not contain %q):\n%s", wantGood, out)
		}
	})

	t.Run("PackagedUserDaemon", func(t *testing.T) {
		t.Parallel()
		// The image ships test-daemon.service only as a system unit;
		// enable with a full path links it into alice's own manager.
		unitPath := "/etc/systemd/system/test-daemon.service"
		userExecOrFatal(ctx, t, d, "alice", "systemctl", "--user", "enable", "--now", unitPath)
		defer userExec(ctx, d, "alice", "systemctl", "--user", "disable", "--now", "test-daemon.service")
		wantLink := "/home/alice/.config/systemd/user/default.target.wants/test-daemon.service"
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "test", "-L", wantLink); err != nil {
			t.Errorf("enabling the linked unit did not create the wants symlink %q: %v", wantLink, err)
		}

		checkActive := func(ctx context.Context) error {
			out, err := userExec(ctx, d, "alice", "systemctl", "--user", "is-active", "test-daemon.service")
			if err != nil || strings.TrimSpace(out) != "active" {
				return fmt.Errorf("test-daemon not active in alice's manager: %v (output: %s)", err, out)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkActive); err != nil {
			t.Fatalf("alice's test-daemon did not become active: %v", err)
		}

		// The daemon must run as alice inside her delegated subtree.
		mainPID := strings.TrimSpace(userExecOrFatal(ctx, t, d, "alice",
			"systemctl", "--user", "show", "-p", "MainPID", "--value", "test-daemon.service"))
		wantOwner := "alice"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U", "/proc/"+mainPID)); got != wantOwner {
			t.Errorf("test-daemon runs as the wrong user (got %q, want %q)", got, wantOwner)
		}
		wantSubtree := fmt.Sprintf("/user@%d.service/", aliceUID)
		if cg := strings.TrimSpace(execOrFatal(ctx, t, d, "cat", "/proc/"+mainPID+"/cgroup")); !strings.Contains(cg, wantSubtree) || !strings.Contains(cg, "test-daemon.service") {
			t.Errorf("test-daemon's cgroup %q is outside the delegated subtree (want it to contain %q and %q)", cg, wantSubtree, "test-daemon.service")
		}

		// Its stdout must flow into alice's own journal.
		wantMsg := "Hello from test daemon"
		checkJournal := func(ctx context.Context) error {
			out, err := userExec(ctx, d, "alice", "journalctl", "--user", "-u", "test-daemon.service", "--no-pager")
			if err != nil || !strings.Contains(out, wantMsg) {
				return fmt.Errorf("alice's journal has no test-daemon output yet: %v (output does not contain %q): %s", err, wantMsg, out)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkJournal); err != nil {
			t.Errorf("test-daemon's stdout did not reach alice's user journal: %v", err)
		}

		// Restart= supervision by the unprivileged manager: an
		// out-of-band SIGKILL must produce a fresh main process.
		execOrFatal(ctx, t, d, "kill", "-9", mainPID)
		checkRestarted := func(ctx context.Context) error {
			if err := checkActive(ctx); err != nil {
				return err
			}
			out, err := userExec(ctx, d, "alice",
				"systemctl", "--user", "show", "-p", "MainPID", "--value", "test-daemon.service")
			if err != nil {
				return fmt.Errorf("cannot get test-daemon's MainPID: %v (output: %s)", err, out)
			}
			if pid := strings.TrimSpace(out); pid == "0" || pid == mainPID {
				return fmt.Errorf("test-daemon not respawned yet (MainPID %q)", pid)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkRestarted); err != nil {
			t.Errorf("alice's manager did not restart the killed daemon: %v", err)
		}
	})

	t.Run("Sandboxing", func(t *testing.T) {
		t.Parallel()
		// PrivateTmp= in a user unit is built entirely without privileges
		// (user namespace + mount namespace as the user).
		hostMarker := "gv-user-host-marker"
		execOrFatal(ctx, t, d, "touch", "/tmp/"+hostMarker)
		out, err := userExec(ctx, d, "alice", "systemd-run", "--user", "--quiet", "--collect", "--wait", "--pipe",
			"--property=PrivateTmp=yes", "/bin/ls", "/tmp")
		if err != nil {
			t.Fatalf("user unit with PrivateTmp=yes failed: %v (output: %s)", err, out)
		}
		if strings.Contains(out, hostMarker) {
			t.Errorf("user PrivateTmp service sees the host /tmp (output contains %q):\n%s", hostMarker, out)
		}
		if out, err := userExec(ctx, d, "alice", "systemd-run", "--user", "--quiet", "--collect", "--wait", "--pipe",
			"--property=PrivateTmp=yes", "/usr/bin/touch", "/tmp/gv-user-priv-marker"); err != nil {
			t.Fatalf("touch in the user's private /tmp failed: %v (output: %s)", err, out)
		}
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "test", "-e", "/tmp/gv-user-priv-marker"); err == nil {
			t.Errorf("file created under user PrivateTmp leaked to the host /tmp")
		}
	})

	t.Run("JournalACL", func(t *testing.T) {
		t.Parallel()
		// alice's entry must land in her per-user journal file, made
		// readable to her alone via a POSIX ACL.
		wantMsg := "gv-alice-journal-msg"
		userExecOrFatal(ctx, t, d, "alice", "systemd-cat", "-t", "gv-alice-tag", "echo", wantMsg)
		execOrFatal(ctx, t, d, "journalctl", "--sync")

		journalGlob := fmt.Sprintf("/var/log/journal/*/user-%d.journal", aliceUID)
		var journalPath string
		checkJournalFile := func(ctx context.Context) error {
			out, err := d.Exec(ctx, dockerutil.ExecOpts{User: "root"}, "bash", "-c", "ls "+journalGlob)
			if err != nil {
				return fmt.Errorf("per-user journal file not created yet: %v (output: %s)", err, out)
			}
			journalPath = strings.TrimSpace(out)
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkJournalFile); err != nil {
			t.Fatalf("journald did not create alice's per-user journal: %v", err)
		}

		// Base permissions alone must NOT grant alice access...
		wantPerms := "root systemd-journal 640"
		if got := strings.TrimSpace(execOrFatal(ctx, t, d, "stat", "-c", "%U %G %a", journalPath)); got != wantPerms {
			t.Errorf("alice's journal file has the wrong base permissions (got %q, want %q)", got, wantPerms)
		}
		// ...the access must come from an ACL entry for alice.
		wantACL := "user:alice:r"
		if out := execOrFatal(ctx, t, d, "getfacl", "-p", journalPath); !strings.Contains(out, wantACL) {
			t.Errorf("alice's journal file is missing her ACL entry (output does not contain %q):\n%s", wantACL, out)
		}

		// Enforcement, positive: alice can read her own message back.
		checkAliceReads := func(ctx context.Context) error {
			out, err := userExec(ctx, d, "alice", "journalctl", "-t", "gv-alice-tag", "--no-pager")
			if err != nil || !strings.Contains(out, wantMsg) {
				return fmt.Errorf("alice cannot read her journal entry yet: %v (output: %s)", err, out)
			}
			return nil
		}
		if err := pollWithTimeout(ctx, daemonPollTimeout, checkAliceReads); err != nil {
			t.Errorf("alice cannot read her own journal through the ACL: %v", err)
		}

		// Enforcement, negative: bob must not be able to open alice's
		// journal file.
		wantDenied := "Permission denied"
		out, err := userExec(ctx, d, "bob", "cat", journalPath)
		if err == nil {
			t.Errorf("bob unexpectedly opened alice's journal file %s", journalPath)
		} else if !strings.Contains(out, wantDenied) {
			t.Errorf("bob's read of alice's journal failed for the wrong reason (output does not contain %q): %s", wantDenied, out)
		}
	})

	t.Run("CrossUserIsolation", func(t *testing.T) {
		t.Parallel()
		// Both managers must be alive simultaneously.
		wantActive := "active"
		for _, unit := range []string{aliceUnit, bobUnit} {
			if state := unitState(ctx, t, d, unit); state != wantActive {
				t.Errorf("%s ActiveState is wrong (got %q, want %q)", unit, state, wantActive)
			}
		}

		// bob must not see into alice's runtime directory...
		wantDenied := "Permission denied"
		out, err := userExec(ctx, d, "bob", "ls", fmt.Sprintf("/run/user/%d", aliceUID))
		if err == nil {
			t.Errorf("bob unexpectedly listed alice's runtime directory (output: %s)", out)
		} else if !strings.Contains(out, wantDenied) {
			t.Errorf("bob's access to alice's runtime dir failed for the wrong reason (output does not contain %q): %s", wantDenied, out)
		}

		// ...and must not be able to write into alice's delegated cgroup
		// subtree (the open for writing is what must fail).
		targetFile := aliceCgroup + "/init.scope/cgroup.procs"
		out, err = userExec(ctx, d, "bob", "bash", "-c", `echo 0 > "$$1"`, "--", targetFile)
		if err == nil {
			t.Errorf("bob unexpectedly migrated a process into alice's cgroup subtree (output: %s)", out)
		} else if !strings.Contains(out, wantDenied) {
			t.Errorf("bob's write to alice's cgroup failed for the wrong reason (output does not contain %q): %s", wantDenied, out)
		}
	})
}
