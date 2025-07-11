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

// Package integration provides end-to-end integration tests for runsc.
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, with various runsc commands. The container is killed and
// deleted at the end.
//
// Setup instruction in test/README.md.
package integration

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// defaultWait is the default wait time used for tests.
	defaultWait = time.Minute

	memInfoCmd = "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'"
)

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}

// httpRequestSucceeds sends a request to a given url and checks that the status is OK.
func httpRequestSucceeds(client http.Client, server string, port int) error {
	url := fmt.Sprintf("http://%s:%d", server, port)
	// Ensure that content is being served.
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		return fmt.Errorf("wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
	return nil
}

// TestLifeCycle tests a basic Create/Start/Stop docker container life cycle.
func TestLifeCycle(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 80
	if err := d.Create(ctx, dockerutil.RunOpts{
		Image: "basic/nginx",
	}); err != nil {
		t.Fatalf("docker create failed: %v", err)
	}
	if err := d.Start(ctx); err != nil {
		t.Fatalf("docker start failed: %v", err)
	}

	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Errorf("http request failed: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Fatalf("docker stop failed: %v", err)
	}
	if err := d.Remove(ctx); err != nil {
		t.Fatalf("docker rm failed: %v", err)
	}
}

func TestPauseResume(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/python",
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check that container is working.
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}

	if err := d.Pause(ctx); err != nil {
		t.Fatalf("docker pause failed: %v", err)
	}

	// Check if container is paused.
	client = http.Client{Timeout: 10 * time.Millisecond} // Don't wait a minute.
	switch _, err := client.Get(fmt.Sprintf("http://%s:%d", ip.String(), port)); v := err.(type) {
	case nil:
		t.Errorf("http req expected to fail but it succeeded")
	case net.Error:
		if !v.Timeout() {
			t.Errorf("http req got error %v, wanted timeout", v)
		}
	default:
		t.Errorf("http req got unexpected error %v", v)
	}

	if err := d.Unpause(ctx); err != nil {
		t.Fatalf("docker unpause failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client = http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}

func TestCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/python",
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Create a snapshot.
	const ckptName = "test"
	if err := d.Checkpoint(ctx, ckptName); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := d.WaitTimeout(ctx, defaultWait); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	d.RestoreInTest(ctx, t, ckptName)

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client := http.Client{Timeout: defaultWait}
	if err := httpRequestSucceeds(client, ip.String(), port); err != nil {
		t.Error("http request failed:", err)
	}
}

// Create client and server that talk to each other using the local IP.
func TestConnectToSelf(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Creates server that replies "server" and exits. Sleeps at the end because
	// 'docker exec' gets killed if the init process exits before it can finish.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}, "/bin/sh", "-c", "echo server | nc -l -p 8080 && sleep 1"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Finds IP address for host.
	ip, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "cat /etc/hosts | grep ${HOSTNAME} | awk '{print $1}'")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	ip = strings.TrimRight(ip, "\n")

	// Runs client that sends "client" to the server and exits.
	reply, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", fmt.Sprintf("echo client | nc %s 8080", ip))
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// Ensure both client and server got the message from each other.
	if want := "server\n"; reply != want {
		t.Errorf("Error on server, want: %q, got: %q", want, reply)
	}
	if _, err := d.WaitForOutput(ctx, "^client\n$", defaultWait); err != nil {
		t.Fatalf("docker.WaitForOutput(client) timeout: %v", err)
	}
}

func TestMemory(t *testing.T) {
	// Find total amount of memory in the host.
	host, err := exec.Command("sh", "-c", memInfoCmd).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	want, err := strconv.ParseUint(strings.TrimSpace(string(host)), 10, 64)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", host, err)
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	out, err := d.Run(ctx, dockerutil.RunOpts{Image: "basic/alpine"}, "sh", "-c", memInfoCmd)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Get memory from inside the container and ensure it matches the host.
	got, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

func TestMemLimit(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	allocMemoryKb := 128 * 1024
	opts := dockerutil.RunOpts{
		Image:  "basic/alpine",
		Memory: allocMemoryKb * 1024, // In bytes.
	}
	out, err := d.Run(ctx, opts, "sh", "-c", memInfoCmd)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Remove warning message that swap isn't present.
	if strings.HasPrefix(out, "WARNING") {
		lines := strings.Split(out, "\n")
		if len(lines) != 3 {
			t.Fatalf("invalid output: %s", out)
		}
		out = lines[1]
	}

	// Ensure the memory matches what we want.
	got, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if want := uint64(allocMemoryKb); got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

func TestNumCPU(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Read how many cores are in the container.
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image:      "basic/alpine",
		CpusetCpus: "0",
	}, "sh", "-c", "cat /proc/cpuinfo | grep 'processor.*:' | wc -l")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Ensure it matches what we want.
	got, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if want := 1; got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

// TestJobControl tests that job control characters are handled properly.
func TestJobControl(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container with an attached PTY.
	p, err := d.SpawnProcess(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sh", "-c", "sleep 100 | cat")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	// Give shell a few seconds to start executing the sleep.
	time.Sleep(2 * time.Second)

	if _, err := p.Write(time.Second, []byte{0x03}); err != nil {
		t.Fatalf("error exit: %v", err)
	}

	if err := d.WaitTimeout(ctx, 3*time.Second); err != nil {
		t.Fatalf("WaitTimeout failed: %v", err)
	}

	want := 130
	got, err := p.WaitExitStatus(ctx)
	if err != nil {
		t.Fatalf("wait for exit failed with: %v", err)
	} else if got != want {
		t.Fatalf("got: %d want: %d", got, want)
	}
}

// TestWorkingDirCreation checks that working dir is created if it doesn't exit.
func TestWorkingDirCreation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		workingDir string
	}{
		{name: "root", workingDir: "/foo"},
		{name: "tmp", workingDir: "/tmp/foo"},
	} {
		for _, readonly := range []bool{true, false} {
			name := tc.name
			if readonly {
				name += "-readonly"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				d := dockerutil.MakeContainer(ctx, t)
				defer d.CleanUp(ctx)

				opts := dockerutil.RunOpts{
					Image:    "basic/alpine",
					WorkDir:  tc.workingDir,
					ReadOnly: readonly,
				}
				got, err := d.Run(ctx, opts, "sh", "-c", "echo ${PWD}")
				if err != nil {
					t.Fatalf("docker run failed: %v", err)
				}
				if want := tc.workingDir + "\n"; want != got {
					t.Errorf("invalid working dir, want: %q, got: %q", want, got)
				}
			})
		}
	}
}

// TestTmpFile checks that files inside '/tmp' are not overridden.
func TestTmpFile(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{Image: "basic/tmpfile"}
	got, err := d.Run(ctx, opts, "cat", "/tmp/foo/file.txt")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want := "123\n"; want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// TestTmpMount checks that mounts inside '/tmp' are not overridden.
func TestTmpMount(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "tmp-mount")
	if err != nil {
		t.Fatalf("TempDir(): %v", err)
	}
	const want = "123"
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("123"), 0666); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/tmp/foo",
			},
		},
	}
	got, err := d.Run(ctx, opts, "cat", "/tmp/foo/file.txt")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// Test that it is allowed to mount a file on top of /dev files, e.g.
// /dev/random.
func TestMountOverDev(t *testing.T) {
	random, err := os.CreateTemp(testutil.TmpDir(), "random")
	if err != nil {
		t.Fatal("os.CreateTemp() failed:", err)
	}
	const want = "123"
	if _, err := random.WriteString(want); err != nil {
		t.Fatalf("WriteString() to %q: %v", random.Name(), err)
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: random.Name(),
				Target: "/dev/random",
			},
		},
	}
	cmd := "dd count=1 bs=5 if=/dev/random 2> /dev/null"
	got, err := d.Run(ctx, opts, "sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// TestSyntheticDirs checks that submounts can be created inside a readonly
// mount even if the target path does not exist.
func TestSyntheticDirs(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		// Make the root read-only to force use of synthetic dirs
		// inside the root gofer mount.
		ReadOnly: true,
		Mounts: []mount.Mount{
			// Mount inside read-only gofer-backed root.
			{
				Type:   mount.TypeTmpfs,
				Target: "/foo/bar/baz",
			},
			// Mount inside sysfs, which always uses synthetic dirs
			// for submounts.
			{
				Type:   mount.TypeTmpfs,
				Target: "/sys/foo/bar/baz",
			},
		},
	}
	// Make sure the directories exist.
	if _, err := d.Run(ctx, opts, "ls", "/foo/bar/baz", "/sys/foo/bar/baz"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

}

// TestHostOverlayfsCopyUp tests that the --overlayfs-stale-read option causes
// runsc to hide the incoherence of FDs opened before and after overlayfs
// copy-up on the host.
func TestHostOverlayfsCopyUp(t *testing.T) {
	runIntegrationTest(t, nil, "./test_copy_up")
}

// TestHostOverlayfsRewindDir tests that rewinddir() "causes the directory
// stream to refer to the current state of the corresponding directory, as a
// call to opendir() would have done" as required by POSIX, when the directory
// in question is host overlayfs.
//
// This test specifically targets host overlayfs because, per POSIX, "if a file
// is removed from or added to the directory after the most recent call to
// opendir() or rewinddir(), whether a subsequent call to readdir() returns an
// entry for that file is unspecified"; the host filesystems used by other
// automated tests yield newly-added files from readdir() even if the fsgofer
// does not explicitly rewinddir(), but overlayfs does not.
func TestHostOverlayfsRewindDir(t *testing.T) {
	runIntegrationTest(t, nil, "./test_rewinddir")
}

// Basic test for linkat(2). Syscall tests requires CAP_DAC_READ_SEARCH and it
// cannot use tricks like userns as root. For this reason, run a basic link test
// to ensure some coverage.
func TestLink(t *testing.T) {
	runIntegrationTest(t, nil, "./link_test")
}

// This test ensures we can run ping without errors.
func TestPing4Loopback(t *testing.T) {
	runIntegrationTest(t, nil, "./ping4.sh")
}

// This test ensures we can enable ipv6 on loopback and run ping6 without
// errors.
func TestPing6Loopback(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		// TODO(gvisor.dev/issue/5011): support ICMP sockets in hostnet and enable
		// this test.
		t.Skip("hostnet only supports TCP/UDP sockets, so ping6 is not supported.")
	}

	// The CAP_NET_ADMIN capability is required to use the `ip` utility, which
	// we use to enable ipv6 on loopback.
	//
	// By default, ipv6 loopback is not enabled by runsc, because docker does
	// not assign an ipv6 address to the test container.
	runIntegrationTest(t, []string{"NET_ADMIN"}, "./ping6.sh")
}

// This test checks that the owner of the sticky directory can delete files
// inside it belonging to other users. It also checks that the owner of a file
// can always delete its file when the file is inside a sticky directory owned
// by another user.
func TestStickyDir(t *testing.T) {
	runIntegrationTest(t, nil, "./test_sticky")
}

func TestHostFD(t *testing.T) {
	t.Run("regular", func(t *testing.T) {
		runIntegrationTest(t, nil, "./host_fd")
	})
	t.Run("tty", func(t *testing.T) {
		ctx := context.Background()
		d := dockerutil.MakeContainer(ctx, t)
		defer d.CleanUp(ctx)

		// Start the container with an attached PTY.
		p, err := d.SpawnProcess(ctx, dockerutil.RunOpts{
			Image:   "basic/integrationtest",
			WorkDir: "/root",
		}, "./host_fd", "-t")
		if err != nil {
			t.Fatalf("docker run failed: %v", err)
		}

		if err := d.Wait(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
		if out, err := p.Logs(); err != nil {
			t.Fatal(err)
		} else if len(out) > 0 {
			t.Errorf("test failed:\n%s", out)
		}
	})
}

func runIntegrationTest(t *testing.T, capAdd []string, args ...string) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		WorkDir: "/root",
		CapAdd:  capAdd,
	}
	if got, err := d.Run(ctx, opts, args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	} else if got != "" {
		t.Errorf("test failed:\n%s", got)
	}
}

// Test that UDS can be created using overlay when parent directory is in lower
// layer only (b/134090485).
//
// Prerequisite: the directory where the socket file is created must not have
// been open for write before bind(2) is called.
func TestBindOverlay(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Run the container.
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}, "bash", "-c", "nc -q -1 -l -U /var/run/sock & p=$! && sleep 1 && echo foobar-asdf | nc -q 0 -U /var/run/sock && wait $p")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check the output contains what we want.
	if want := "foobar-asdf"; !strings.Contains(got, want) {
		t.Fatalf("docker run output is missing %q: %s", want, got)
	}
}

func TestStdios(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	testStdios(t, func(user string, args ...string) (string, error) {
		defer d.CleanUp(ctx)
		opts := dockerutil.RunOpts{
			Image: "basic/alpine",
			User:  user,
		}
		return d.Run(ctx, opts, args...)
	})
}

func TestStdiosExec(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	runOpts := dockerutil.RunOpts{Image: "basic/alpine"}
	if err := d.Spawn(ctx, runOpts, "sleep", "100"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	testStdios(t, func(user string, args ...string) (string, error) {
		opts := dockerutil.ExecOpts{User: user}
		return d.Exec(ctx, opts, args...)
	})
}

func testStdios(t *testing.T, run func(string, ...string) (string, error)) {
	const cmd = "stat -L /proc/self/fd/0 /proc/self/fd/1 /proc/self/fd/2 | grep 'Uid:'"
	got, err := run("123", "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if len(got) == 0 {
		t.Errorf("Unexpected empty output from %q", cmd)
	}
	re := regexp.MustCompile(`Uid: \(\s*(\w+)\/.*\)`)
	for _, line := range strings.SplitN(got, "\n", 3) {
		t.Logf("stat -L: %s", line)
		matches := re.FindSubmatch([]byte(line))
		if len(matches) != 2 {
			t.Fatalf("wrong output format: %q: matches: %v", line, matches)
		}
		if want, got := "123", string(matches[1]); want != got {
			t.Errorf("wrong user, want: %q, got: %q", want, got)
		}
	}

	// Check that stdout and stderr can be open and written to. This checks
	// that ownership and permissions are correct inside gVisor.
	got, err = run("456", "/bin/sh", "-c", "echo foobar | tee /proc/self/fd/1 > /proc/self/fd/2")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	t.Logf("echo foobar: %q", got)
	// Check it repeats twice, once for stdout and once for stderr.
	if want := "foobar\nfoobar\n"; want != got {
		t.Errorf("Wrong echo output, want: %q, got: %q", want, got)
	}

	// Check that timestamps can be changed. Setting timestamps require an extra
	// write check _after_ the file was opened, and may fail if the underlying
	// host file is not setup correctly.
	if _, err := run("789", "touch", "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
}

func TestStdiosChown(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{Image: "basic/alpine"}
	if _, err := d.Run(ctx, opts, "chown", "123", "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
}

func TestUnmount(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "sub-mount")
	if err != nil {
		t.Fatalf("TempDir(): %v", err)
	}
	opts := dockerutil.RunOpts{
		Image:      "basic/alpine",
		Privileged: true, // Required for umount
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/foo",
			},
		},
	}
	if _, err := d.Run(ctx, opts, "umount", "/foo"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
}

func TestDeleteInterface(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image:  "basic/alpine",
		CapAdd: []string{"NET_ADMIN"},
	}
	if err := d.Spawn(ctx, opts, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// We should be able to remove eth0.
	output, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "ip link del dev eth0")
	if err != nil {
		t.Fatalf("failed to remove eth0: %s, output: %s", err, output)
	}
	// Verify that eth0 is no longer there.
	output, err = d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "ip link show")
	if err != nil {
		t.Fatalf("docker exec ip link show failed: %s, output: %s", err, output)
	}
	if strings.Contains(output, "eth0") {
		t.Fatalf("failed to remove eth0")
	}

	// Loopback device can't be removed.
	output, err = d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "ip link del dev lo")
	if err == nil {
		t.Fatalf("should not remove the loopback device: %v", output)
	}
	// Verify that lo is still there.
	output, err = d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "ip link show")
	if err != nil {
		t.Fatalf("docker exec ip link show failed: %s, output: %s", err, output)
	}
	if !strings.Contains(output, "lo") {
		t.Fatalf("loopback interface is removed")
	}
}

func TestProductName(t *testing.T) {
	want, err := os.ReadFile("/sys/devices/virtual/dmi/id/product_name")
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{Image: "basic/alpine"}
	got, err := d.Run(ctx, opts, "cat", "/sys/devices/virtual/dmi/id/product_name")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if string(want) != got {
		t.Errorf("invalid product name, want: %q, got: %q", want, got)
	}
}

// TestRevalidateSymlinkChain tests that when a symlink in the middle of chain
// gets updated externally, the change is noticed and the internal cache is
// updated accordingly.
func TestRevalidateSymlinkChain(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Create the following structure:
	// dir
	//  + gen1
	//  |  + file [content: 123]
	//  |
	//  + gen2
	//  |  + file [content: 456]
	//  |
	//  + file -> sym1/file
	//  + sym1 -> sym2
	//  + sym2 -> gen1
	//
	dir, err := os.MkdirTemp(testutil.TmpDir(), "sub-mount")
	if err != nil {
		t.Fatalf("TempDir(): %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "gen1"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "gen2"), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gen1", "file"), []byte("123"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gen2", "file"), []byte("456"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sym1/file", filepath.Join(dir, "file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sym2", filepath.Join(dir, "sym1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("gen1", filepath.Join(dir, "sym2")); err != nil {
		t.Fatal(err)
	}

	// Mount dir inside the container so that external changes are propagated to
	// the container.
	opts := dockerutil.RunOpts{
		Image:      "basic/alpine",
		Privileged: true, // Required for umount
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/foo",
			},
		},
	}
	if err := d.Create(ctx, opts, "sleep", "1000"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if err := d.Start(ctx); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Read and cache symlinks pointing to gen1/file.
	got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/foo/file")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want := "123"; got != want {
		t.Fatalf("Read wrong file, want: %q, got: %q", want, got)
	}

	// Change the symlink to point to gen2 file.
	if err := os.Remove(filepath.Join(dir, "sym2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("gen2", filepath.Join(dir, "sym2")); err != nil {
		t.Fatal(err)
	}

	// Read symlink chain again and check that it got updated to gen2/file.
	got, err = d.Exec(ctx, dockerutil.ExecOpts{}, "cat", "/foo/file")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want := "456"; got != want {
		t.Fatalf("Read wrong file, want: %q, got: %q", want, got)
	}
}

// TestTmpMountWithSize checks when 'tmpfs' is mounted
// with size option the limit is not exceeded.
func TestTmpMountWithSize(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeTmpfs,
				Target: "/tmp/foo",
				TmpfsOptions: &mount.TmpfsOptions{
					SizeBytes: 4096,
				},
			},
		},
	}
	if err := d.Create(ctx, opts, "sleep", "1000"); err != nil {
		t.Fatalf("docker create failed: %v", err)
	}
	if err := d.Start(ctx); err != nil {
		t.Fatalf("docker start failed: %v", err)
	}

	if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo hello > /tmp/foo/test1.txt"); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	echoOutput, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "echo world > /tmp/foo/test2.txt")
	if err == nil {
		t.Fatalf("docker exec size check unexpectedly succeeded (output: %v)", echoOutput)
	}
	wantErr := "No space left on device"
	if !strings.Contains(echoOutput, wantErr) {
		t.Errorf("unexpected echo error:Expected: %v, Got: %v", wantErr, echoOutput)
	}
}

// NOTE(b/236028361): Regression test. Check we can handle a working directory
// without execute permissions. See comment in
// pkg/sentry/kernel/kernel.go:CreateProcess() for more context.
func TestNonSearchableWorkingDirectory(t *testing.T) {
	dir, err := os.MkdirTemp(testutil.TmpDir(), "tmp-mount")
	if err != nil {
		t.Fatalf("MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)

	// The container will run as a non-root user. Make dir not searchable by
	// others by removing execute bit for others.
	if err := os.Chmod(dir, 0766); err != nil {
		t.Fatalf("Chmod() failed: %v", err)
	}
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	targetMount := "/foo"
	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: targetMount,
			},
		},
		WorkDir: targetMount,
		User:    "nobody",
	}

	echoPhrase := "All izz well"
	got, err := d.Run(ctx, opts, "sh", "-c", "echo "+echoPhrase+" && (ls || true)")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if !strings.Contains(got, echoPhrase) {
		t.Errorf("echo output not found, want: %q, got: %q", echoPhrase, got)
	}
	if wantErrorMsg := "Permission denied"; !strings.Contains(got, wantErrorMsg) {
		t.Errorf("ls error message not found, want: %q, got: %q", wantErrorMsg, got)
	}
}

// NOTE(gvisor.dev/issue/11910): Regression test. Make sure that working
// directory can be set to a symlinked path.
func TestSymlinkWorkingDirectory(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "symlink-workdir")
	if err != nil {
		t.Fatalf("MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)

	// Create the actual target directory
	targetDir := filepath.Join(dir, "actual-dir")
	if err := os.Mkdir(targetDir, 0755); err != nil {
		t.Fatalf("Mkdir() failed: %v", err)
	}

	// Create a symlink pointing to the target directory
	symlinkPath := filepath.Join(dir, "symlink-to-dir")
	if err := os.Symlink("actual-dir", symlinkPath); err != nil {
		t.Fatalf("Symlink() failed: %v", err)
	}

	// Mount the temp directory and set working directory to the symlink
	opts := dockerutil.RunOpts{
		Image:   "basic/alpine",
		WorkDir: "/test/symlink-to-dir",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/test",
			},
		},
	}

	// Test that the container can start with symlinked working directory
	// and that pwd returns the symlinked path
	got, err := d.Run(ctx, opts, "sh", "-c", "pwd")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	want := "/test/symlink-to-dir\n"
	if got != want {
		t.Errorf("working directory mismatch, want: %q, got: %q", want, got)
	}

	// Additional test: verify we can actually use the working directory
	// by creating a file in it
	_, err = d.Run(ctx, opts, "sh", "-c", "echo 'test content' > testfile && cat testfile")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Verify the file was created in the actual target directory
	createdFile := filepath.Join(targetDir, "testfile")
	if _, err := os.Stat(createdFile); err != nil {
		t.Errorf("file was not created in target directory: %v", err)
	}
}

func TestCharDevice(t *testing.T) {
	if testutil.IsRunningWithOverlay() {
		t.Skip("files are not available outside the sandbox with overlay.")
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "tmp-mount")
	if err != nil {
		t.Fatalf("MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)

	opts := dockerutil.RunOpts{
		Image: "basic/alpine",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/dev/zero",
				Target: "/test/zero",
			},
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/out",
			},
		},
	}

	const size = 1024 * 1024

	// `docker logs` encodes the string, making it hard to compare. Write the
	// result to a file that is available to the test.
	cmd := fmt.Sprintf("head -c %d /test/zero > /out/result", size)
	if _, err := d.Run(ctx, opts, "sh", "-c", cmd); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "result"))
	if err != nil {
		t.Fatal(err)
	}
	if want := [size]byte{}; !bytes.Equal(want[:], got) {
		t.Errorf("Wrong bytes, want: [all zeros], got: %v", got)
	}
}

func TestBlockHostUds(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	dir, err := os.MkdirTemp(testutil.TmpDir(), "tmp-mount")
	if err != nil {
		t.Fatalf("MkdirTemp() failed: %v", err)
	}
	defer os.RemoveAll(dir)

	dirFD, err := unix.Open(dir, unix.O_PATH, 0)
	if err != nil {
		t.Fatalf("failed to open %s: %v", dir, err)
	}
	defer unix.Close(dirFD)
	// Use /proc/self/fd to generate path to avoid EINVAL on large path.
	l, err := net.Listen("unix", filepath.Join("/proc/self/fd", strconv.Itoa(dirFD), "test.sock"))
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	defer l.Close()

	opts := dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		WorkDir: "/root",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: dir,
				Target: "/dir",
			},
		},
	}
	if err := d.Spawn(ctx, opts, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	// Application should be able to walk/stat the UDS ...
	if got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "stat", "/dir/test.sock"); err != nil {
		t.Fatalf("stat(2)-ing the UDS failed: output = %q, err = %v", got, err)
	}
	// ... but not connect to it.
	const want = "connect: Connection refused"
	if got, err := d.Exec(ctx, dockerutil.ExecOpts{}, "./host_connect", "/dir/test.sock"); err == nil || !strings.Contains(got, want) {
		t.Errorf("err should be non-nil and output should contain %q, but got err = %v and output = %q", want, err, got)
	}
}

func readLogs(logs string, position int) (int, error) {
	if len(logs) == 0 {
		return 0, fmt.Errorf("error no content was read")
	}

	nums := strings.Split(logs, "\n")
	if position >= len(nums) {
		return 0, fmt.Errorf("position %v is not within the length of content %v", position, nums)
	}
	if position == -1 {
		// Expectation of newline at the end of last position.
		position = len(nums) - 2
	}
	num, err := strconv.Atoi(nums[position])
	if err != nil {
		return 0, fmt.Errorf("error getting number from file: %v", err)
	}

	return num, nil
}

func checkLogs(logs string, oldPos int) error {
	if len(logs) == 0 {
		return fmt.Errorf("error no content was read")
	}

	nums := strings.Split(logs, "\n")
	// Expectation of newline at the end of last position.
	if oldPos >= len(nums)-2 {
		return fmt.Errorf("oldPos %v is not within the length of content %v", oldPos, nums)
	}
	for i := oldPos + 1; i < len(nums)-1; i++ {
		num, err := strconv.Atoi(nums[i])
		if err != nil {
			return fmt.Errorf("error getting number from file: %v", err)
		}
		if num != oldPos+1 {
			return fmt.Errorf("error in save/resume, numbers not in order, previous: %d, next: %d", oldPos, num)
		}
		oldPos++
	}
	return nil
}

func TestUnshareUsernsWithoutSetfcap(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:   "basic/integrationtest",
		CapDrop: []string{"setfcap"},
	}, "unshare", "-Ur", "ls"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if _, err := d.WaitForOutput(ctx, "Operation not permitted", 5*time.Second); err != nil {
		t.Errorf("WaitForOutput failed: %v", err)
	}
}

// Checkpoint the container and continue running.
func TestCheckpointResume(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sh", "-c", "i=0; while true; do echo \"$i\"; i=\"$(expr \"$i\" + 1)\"; sleep .01; done"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	time.Sleep(2 * time.Second)

	// Get the logs before checkpointing.
	logs, err := d.Logs(ctx)
	if err != nil {
		t.Fatalf("docker logs failed: %v", err)
	}

	// Get the last position of the logs printed.
	pos, err := readLogs(logs, -1)
	if err != nil {
		t.Fatalf("readLogs failed: %v", err)
	}

	// Create a snapshot and continue running.
	if err := d.CheckpointResume(ctx, "test"); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}

	var newLogs string
	// Wait for the container to resume running and print new logs.
	if err := testutil.Poll(func() error {
		// Get the logs after checkpointing to check if the container resumed.
		newLogs, err = d.Logs(ctx)
		if err != nil {
			t.Fatalf("docker logs failed: %v", err)
		}
		return nil
	}, defaultWait); err != nil {
		t.Fatalf("container read logs failed after resume: %v", err)
	}

	if err := checkLogs(newLogs, pos); err != nil {
		t.Fatalf("checkLogs failed: %v", err)
	}
	if err := d.Kill(ctx); err != nil {
		t.Fatalf("docker kill failed: %v", err)
	}
}

func connectWithTCPServer(t *testing.T, serverIP string, startPort int, numConn int) {
	const timeout = 1 * time.Minute
	var conn net.Conn
	var err error

	for i := range numConn {
		ip := serverIP + ":" + strconv.Itoa(startPort+i)
		for {
			conn, err = net.DialTimeout("tcp", ip, timeout)
			// Retry to connect to the server if there are any errors.
			// Connect can fail sometimes when the server is not ready
			// and is not in listening state when the request was sent.
			if err != nil {
				t.Logf("Error connecting to server %s: %v, retrying...", ip, err)
				continue
			}
			break
		}
		conn.Close()
	}
}

func connectAndReadWrite(t *testing.T, serverIP string, port int) {
	newserverIP := serverIP + ":" + strconv.Itoa(port)
	newConn, err := net.DialTimeout("tcp", newserverIP, 1*time.Minute)
	if err != nil {
		t.Fatalf("Error connecting to server: %v", err)
	}
	defer newConn.Close()

	readBuf := make([]byte, 32)
	if _, err := newConn.Read(readBuf); err != nil {
		t.Fatalf("Read failed: %v", err)
	}

	if _, err := newConn.Write([]byte("Hello!")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
}

func testCheckpointRestoreListeningConnection(ctx context.Context, t *testing.T, d *dockerutil.Container, fName string, numConn int) {
	defer d.CleanUp(ctx)

	opts := dockerutil.RunOpts{
		Image: "basic/integrationtest",
	}
	// Start the tcp server.
	if err := d.Spawn(ctx, opts, fName); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	const port = 9000
	connectWithTCPServer(t, ip.String(), port, numConn)

	// Create a snapshot.
	const checkpointFile = "networktest"
	if err := d.Checkpoint(ctx, checkpointFile); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if err := d.WaitTimeout(ctx, defaultWait); err != nil {
		t.Fatalf("wait failed: %v", err)
	}
	d.RestoreInTest(ctx, t, checkpointFile)

	var newIP net.IP
	newIP, err = d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}
	if numConn > 1 {
		connectWithTCPServer(t, newIP.String(), port, numConn)
		if err := d.Kill(ctx); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
		return
	}

	connectAndReadWrite(t, newIP.String(), port)
	if err := d.Wait(ctx); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
}

// Test to check restore of a TCP listening connection without netstack S/R.
func TestRestoreListenConn(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	testCheckpointRestoreListeningConnection(ctx, t, d, "./tcp_server" /* fName */, 1 /* numConn */)
}

// Test to check restore of a TCP listening connection with netstack S/R.
func TestRestoreListenConnWithNetstackSR(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	if !testutil.IsRunningWithSaveRestoreNetstack() {
		t.Skip("Netstack save restore is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-save-restore-netstack")
	testCheckpointRestoreListeningConnection(ctx, t, d, "./tcp_server" /* fName */, 1 /* numConn */)
}

// Test to check restore of multiple TCP listening connections with netstack S/R.
func TestRestoreMultipleListenConnWithNetstackSR(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}
	if !testutil.IsRunningWithSaveRestoreNetstack() {
		t.Skip("Netstack save restore is not supported.")
	}
	dockerutil.EnsureDockerExperimentalEnabled()

	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-save-restore-netstack")
	testCheckpointRestoreListeningConnection(ctx, t, d, "./tcp_stress_server" /* fName */, 100 /* numConn */)
}
