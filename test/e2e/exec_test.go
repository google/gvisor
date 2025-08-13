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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	noCap           = "0000000000000000"
	netAdminOnlyCap = "0000000000001000"
)

// Test that exec uses the exact same capability set as the container.
func TestExecCapabilities(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sh", "-c", "cat /proc/self/status; sleep 200"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check that capability.
	caps := []string{"CapInh", "CapPrm", "CapEff", "CapBnd"}
	// Expected capabilities for non-root usres.
	wantCaps := map[string]string{}
	// For the root user.
	for _, cap := range caps {
		pattern := fmt.Sprintf("%s:\t([0-9a-f]+)\n", cap)
		matches, err := d.WaitForOutputSubmatch(ctx, pattern, 5*time.Second)
		if err != nil {
			t.Fatalf("WaitForOutputSubmatch() timeout: %v", err)
		}
		if len(matches) != 2 {
			t.Fatalf("There should be a match for the whole line and the capability bitmask")
		}
		want := fmt.Sprintf("%s:\t%s\n", cap, matches[1])
		t.Log("root capabilities:", want)

		// Now check that exec'd process capabilities match the root.
		got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "grep", fmt.Sprintf("%s:", cap), "/proc/self/status")
		if err != nil {
			t.Fatalf("docker exec failed: %v", err)
		}
		if got != want {
			t.Errorf("wrong %s, got: %q, want: %q", cap, got, want)
		}
		// CapBnd and CpaInh are unchanged, other capabilities will
		// be transformed for non-root users.
		wantCaps[cap] = fmt.Sprintf("%s:\t%s\n", cap, noCap)
		if cap == "CapBnd" || cap == "CapInh" {
			wantCaps[cap] = got
		}
	}
	gid, uid, groupname, username := "1001", "1002", "gvisor-test", "gvisor-test"
	// Add a new group.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "addgroup", groupname, "--gid", gid); err != nil {
		t.Fatalf("failed to create a new group: %v", err)
	}
	// Add a new user.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "adduser", "--no-create-home", "--disabled-password", "--gecos", "", "--ingroup", groupname, username); err != nil {
		t.Fatalf("failed to create a new user: %v", err)
	}
	for cap, want := range wantCaps {
		got, err := d.Exec(ctx, dockerutil.ExecOpts{User: uid}, "grep", fmt.Sprintf("%s:", cap), "/proc/self/status")
		if err != nil {
			t.Fatalf("docker exec failed: %v", err)
		}
		t.Logf("%s: %v", cap, got)
		// Format the matched capability.
		if got != want {
			t.Errorf("wrong %s, got: %q, want: %q", cap, got, want)
		}
	}
}

func TestFileCap(t *testing.T) {
	netAdminOnlyStatusCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n", noCap, netAdminOnlyCap, netAdminOnlyCap)
	// In Docker, when running without --privileged, the root user has the
	// following capabilities.
	rootCap := auth.CapabilitySetOfMany([]linux.Capability{
		linux.CAP_CHOWN,
		linux.CAP_DAC_OVERRIDE,
		linux.CAP_FOWNER,
		linux.CAP_FSETID,
		linux.CAP_KILL,
		linux.CAP_SETGID,
		linux.CAP_SETUID,
		linux.CAP_SETPCAP,
		linux.CAP_NET_BIND_SERVICE,
		linux.CAP_NET_RAW,
		linux.CAP_SYS_CHROOT,
		linux.CAP_MKNOD,
		linux.CAP_AUDIT_WRITE,
		linux.CAP_SETFCAP,
	})
	if !testutil.IsRunningWithNetRaw() {
		rootCap.Clear(linux.CAP_NET_RAW)
	}
	rootCap.Add(linux.CAP_NET_ADMIN) // CAP_NET_ADMIN is added below.
	rootCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%016x\nCapEff:\t%016x\n", noCap, rootCap, rootCap)
	for _, success := range []bool{true, false} {
		for _, useTmpfs := range []bool{true, false} {
			for _, rootUser := range []bool{true, false} {
				tcName := "success"
				if !success {
					tcName = "fail"
				}
				if useTmpfs {
					tcName += "_tmpfs"
				} else {
					tcName += "_gofer"
				}
				if rootUser {
					tcName += "_root"
				} else {
					tcName += "_non_root"
				}
				t.Run(tcName, func(t *testing.T) {
					ctx := context.Background()
					d := dockerutil.MakeContainer(ctx, t)
					defer d.CleanUp(ctx)

					// Start the sleep container.
					var capAdd []string
					if success {
						capAdd = []string{"NET_ADMIN"}
					}
					if err := d.Spawn(ctx, dockerutil.RunOpts{
						Image:  "basic/filecap",
						CapAdd: capAdd,
					}, "sleep", "infinity"); err != nil {
						t.Fatalf("docker run failed: %v", err)
					}

					// In basic/filecap image, /mnt/cat has file cap set to cap_net_admin+ep.
					catPath := "/mnt/cat"
					if useTmpfs {
						// Copy /bin/cat to /tmp/cat.
						if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cp", "/bin/cat", "/tmp/cat"); err != nil {
							t.Fatalf("failed to copy /bin/cat to /tmp/cat: %v", err)
						}
						// Set file cap on /tmp/cat.
						if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "setcap", "cap_net_admin+ep", "/tmp/cat"); err != nil {
							t.Fatalf("failed to set file cap on /tmp/cat: %v", err)
						}
						catPath = "/tmp/cat"
					}

					// Check getcap output.
					output, err := d.Exec(ctx, dockerutil.ExecOpts{}, "getcap", catPath)
					if err != nil {
						t.Fatalf("failed to getcap %s: %v", catPath, err)
					}
					if !strings.Contains(output, "cap_net_admin=ep") {
						t.Errorf("can't find expected cap_net_admin=ep in output: %q", output)
					}

					// Check that process credentials are properly configured.
					var user string
					if !rootUser {
						user = "1001"
					}
					output, err = d.Exec(ctx, dockerutil.ExecOpts{User: user}, catPath, "/proc/self/status")
					if (err == nil) != success {
						t.Fatalf("wanted success=%t, got err=%v", success, err)
					}
					wantOut := "operation not permitted"
					if success {
						if rootUser {
							wantOut = rootCaps
						} else {
							wantOut = netAdminOnlyStatusCaps
						}
					}
					if !strings.Contains(output, wantOut) {
						t.Errorf("can't find expected output %q in output: %q", wantOut, output)
					}
				})
			}
		}
	}
}

func TestNon0RootIdFileCap(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:  "basic/filecap",
		CapAdd: []string{"NET_ADMIN"},
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Copy /bin/cat to /tmp/cat.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cp", "/bin/cat", "/tmp/cat"); err != nil {
		t.Fatalf("failed to copy /bin/cat to /tmp/cat: %v", err)
	}
	// Set file cap on /tmp/cat for CAP_NET_ADMIN with rootid=1001.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "setcap", "-n", "1001", "cap_net_admin+ep", "/tmp/cat"); err != nil {
		t.Fatalf("failed to set file cap on /tmp/cat: %v", err)
	}

	// Try to execute /tmp/cat as user 1001. Since we are not in a userns for
	// which the rootid is 1001, the file cap should not be applied.
	output, err := d.Exec(ctx, dockerutil.ExecOpts{User: "1001"}, "/tmp/cat", "/proc/self/status")
	if err != nil {
		t.Fatalf("failed to execute /tmp/cat: %v", err)
	}
	noCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n", noCap, noCap, noCap)
	if !strings.Contains(output, noCaps) {
		t.Errorf("can't find expected output %q in output: %q", noCaps, output)
	}
}

func TestFileCapWithNoNewPrivs(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:  "basic/sudo",
		CapAdd: []string{"NET_ADMIN"}, // we need this in the bounding set
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	if output, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"cp", "/bin/cat", "/tmp/catWithNetadmin"); err != nil {
		t.Fatalf("failed to copy /bin/cat to /tmp/catWithNetadmin; err: %v output: %v", err, output)
	}
	if output, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"sudo", "setcap", "cap_net_admin+ep", "/tmp/catWithNetadmin"); err != nil {
		t.Fatalf("failed to set file cap on /tmp/catWithNetadmin; err: %v, output: %v", err, output)
	}

	// Fails to gain file caps with NO_NEW_PRIVS.
	noStatusCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n", noCap, noCap, noCap)
	output, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"setpriv", "--no-new-privs", "/tmp/catWithNetadmin", "/proc/self/status")
	if err != nil || !strings.Contains(output, noStatusCaps) {
		t.Errorf("failed to get expected status caps; err: %v, output: %v", err, output)
	}
	// But succeeds otherwise
	netAdminOnlyStatusCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n", noCap, netAdminOnlyCap, netAdminOnlyCap)
	output, err = d.Exec(ctx, dockerutil.ExecOpts{User: "alice"}, "/tmp/catWithNetadmin", "/proc/self/status")
	if err != nil || !strings.Contains(output, netAdminOnlyStatusCaps) {
		t.Errorf("failed to get expected status caps; err: %v, output: %v", err, output)
	}
}

func TestNoEpermFileCap(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/filecap",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Copy /bin/cat to /tmp/cat.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cp", "/bin/cat", "/tmp/cat"); err != nil {
		t.Fatalf("failed to copy /bin/cat to /tmp/cat: %v", err)
	}
	// Set file cap on /tmp/cat for CAP_NET_ADMIN without the effective flag.
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "setcap", "cap_net_admin+p", "/tmp/cat"); err != nil {
		t.Fatalf("failed to set file cap on /tmp/cat: %v", err)
	}

	// Try to execute /tmp/cat as user 1001. Since the container was not run with
	// CAP_NET_ADMIN, the file cap should not be applied. Since the effective bit
	// is not set, we should not receive an EPERM either.
	output, err := d.Exec(ctx, dockerutil.ExecOpts{User: "1001"}, "/tmp/cat", "/proc/self/status")
	if err != nil {
		t.Fatalf("failed to execute /tmp/cat: %v", err)
	}
	noCaps := fmt.Sprintf("CapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n", noCap, noCap, noCap)
	if !strings.Contains(output, noCaps) {
		t.Errorf("can't find expected output %q in output: %q", noCaps, output)
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
	addNetRaw := testutil.IsRunningWithHostNet() && testutil.IsRunningWithNetRaw()
	if addNetRaw {
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

	// Expect no capabilities, unless CAP_NET_RAW was added above.
	var wantContainerCaps auth.CapabilitySet
	if addNetRaw {
		wantContainerCaps.Add(linux.CAP_NET_RAW)
	}
	if containerCaps != uint64(wantContainerCaps) {
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
	wantCaps := specutils.AllCapabilitiesSet()
	if !testutil.IsRunningWithNetRaw() {
		wantCaps.Clear(linux.CAP_NET_RAW)
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
		oldWantCaps.Clear(cap)
	}
	oldWantStr := fmt.Sprintf("CapEff:\t%016x\n", oldWantCaps)
	if got != oldWantStr {
		t.Errorf("Wrong capabilities, got: %q, want: %q or %q. Make sure runsc is not using '--net-raw'", got, wantStr, oldWantStr)
	}
}

func TestSetUserId(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/sudo",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"cp", "/bin/whoami", "/tmp/alices_whomai"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"cp", "/bin/whoami", "/tmp/alices_whoami_suid"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"chmod", "u+s", "/tmp/alices_whoami_suid"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// bob should become alice with suid bit set.
	who, err := d.Exec(ctx, dockerutil.ExecOpts{User: "bob"}, "/tmp/alices_whoami_suid")
	if err != nil || strings.TrimSpace(who) != "alice" {
		t.Errorf("suid bit did not change the effective uid; err: %v, who: %v", err, who)
	}
	// bob should stay bob with suid bit unset.
	who, err = d.Exec(ctx, dockerutil.ExecOpts{User: "bob"}, "/tmp/alices_whomai")
	if err != nil || strings.TrimSpace(who) != "bob" {
		t.Errorf("non-suid exec changed the effective uid; err: %v, who: %v", err, who)
	}
	// When NO_NEW_PRIVS is set, bob should stay bob even if the suid bit is set.
	who, err = d.Exec(ctx, dockerutil.ExecOpts{User: "bob"},
		"setpriv", "--no-new-privs", "/tmp/alices_whoami_suid")
	if err != nil || strings.TrimSpace(who) != "bob" {
		t.Errorf("suid bit caused euid change when NO_NEW_PRIVS is set; err: %v, who: %v", err, who)
	}
	// In a user namespace owned by bob, bob should not become alice even if the suid bit is set
	// (for alice isn't mapped in the new userns).
	who, err = d.Exec(ctx, dockerutil.ExecOpts{User: "bob"},
		"unshare", "--user", "--map-current-user", "/tmp/alices_whoami_suid")
	if err != nil || strings.TrimSpace(who) != "bob" {
		t.Errorf("suid bit caused euid change even though the userns has no mapping; err: %v, who: %v", err, who)
	}
}

func TestSetUserIdInFsWithNosuid(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Tmpfs: map[string]string{"/nosuidtmp": "nosuid,exec"},
		Image: "basic/sudo",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"cp", "/bin/whoami", "/nosuidtmp/alices_whoami_suid"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if _, err := d.Exec(ctx, dockerutil.ExecOpts{User: "alice"},
		"chmod", "u+s", "/nosuidtmp/alices_whoami_suid"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// bob should stay bob even if suid bit is set, for the executable lives on a nosuid tmpfs mount.
	who, err := d.Exec(ctx, dockerutil.ExecOpts{User: "bob"}, "/nosuidtmp/alices_whoami_suid")
	if err != nil || strings.TrimSpace(who) != "bob" {
		t.Errorf("exec of a suid file in a nosuid fs changed the euid; err: %v, who: %v", err, who)
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
