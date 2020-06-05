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
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

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
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Start the container.
	if err := d.Create(dockerutil.RunOpts{
		Image: "basic/nginx",
		Ports: []int{80},
	}); err != nil {
		t.Fatalf("docker create failed: %v", err)
	}
	if err := d.Start(); err != nil {
		t.Fatalf("docker start failed: %v", err)
	}

	// Test that container is working.
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatalf("docker.FindPort(80) failed: %v", err)
	}
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Errorf("http request failed: %v", err)
	}

	if err := d.Stop(); err != nil {
		t.Fatalf("docker stop failed: %v", err)
	}
	if err := d.Remove(); err != nil {
		t.Fatalf("docker rm failed: %v", err)
	}
}

func TestPauseResume(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Checkpoint is not supported.")
	}

	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Start the container.
	if err := d.Spawn(dockerutil.RunOpts{
		Image: "basic/python",
		Ports: []int{8080}, // See Dockerfile.
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check that container is working.
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}

	if err := d.Pause(); err != nil {
		t.Fatalf("docker pause failed: %v", err)
	}

	// Check if container is paused.
	switch _, err := client.Get(fmt.Sprintf("http://localhost:%d", port)); v := err.(type) {
	case nil:
		t.Errorf("http req expected to fail but it succeeded")
	case net.Error:
		if !v.Timeout() {
			t.Errorf("http req got error %v, wanted timeout", v)
		}
	default:
		t.Errorf("http req got unexpected error %v", v)
	}

	if err := d.Unpause(); err != nil {
		t.Fatalf("docker unpause failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}
}

func TestCheckpointRestore(t *testing.T) {
	if !testutil.IsCheckpointSupported() {
		t.Skip("Pause/resume is not supported.")
	}

	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Start the container.
	if err := d.Spawn(dockerutil.RunOpts{
		Image: "basic/python",
		Ports: []int{8080}, // See Dockerfile.
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Create a snapshot.
	if err := d.Checkpoint("test"); err != nil {
		t.Fatalf("docker checkpoint failed: %v", err)
	}
	if _, err := d.Wait(30 * time.Second); err != nil {
		t.Fatalf("wait failed: %v", err)
	}

	// TODO(b/143498576): Remove Poll after github.com/moby/moby/issues/38963 is fixed.
	if err := testutil.Poll(func() error { return d.Restore("test") }, 15*time.Second); err != nil {
		t.Fatalf("docker restore failed: %v", err)
	}

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatalf("docker.FindPort(8080) failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Check if container is working again.
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}
}

// Create client and server that talk to each other using the local IP.
func TestConnectToSelf(t *testing.T) {
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Creates server that replies "server" and exists. Sleeps at the end because
	// 'docker exec' gets killed if the init process exists before it can finish.
	if err := d.Spawn(dockerutil.RunOpts{
		Image: "basic/ubuntu",
	}, "/bin/sh", "-c", "echo server | nc -l -p 8080 && sleep 1"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Finds IP address for host.
	ip, err := d.Exec(dockerutil.RunOpts{}, "/bin/sh", "-c", "cat /etc/hosts | grep ${HOSTNAME} | awk '{print $1}'")
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	ip = strings.TrimRight(ip, "\n")

	// Runs client that sends "client" to the server and exits.
	reply, err := d.Exec(dockerutil.RunOpts{}, "/bin/sh", "-c", fmt.Sprintf("echo client | nc %s 8080", ip))
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// Ensure both client and server got the message from each other.
	if want := "server\n"; reply != want {
		t.Errorf("Error on server, want: %q, got: %q", want, reply)
	}
	if _, err := d.WaitForOutput("^client\n$", 1*time.Second); err != nil {
		t.Fatalf("docker.WaitForOutput(client) timeout: %v", err)
	}
}

func TestMemLimit(t *testing.T) {
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// N.B. Because the size of the memory file may grow in large chunks,
	// there is a minimum threshold of 1GB for the MemTotal figure.
	allocMemory := 1024 * 1024
	out, err := d.Run(dockerutil.RunOpts{
		Image:  "basic/alpine",
		Memory: allocMemory, // In kB.
	}, "sh", "-c", "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'")
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
	if want := uint64(allocMemory); got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

func TestNumCPU(t *testing.T) {
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Read how many cores are in the container.
	out, err := d.Run(dockerutil.RunOpts{
		Image: "basic/alpine",
		Extra: []string{"--cpuset-cpus=0"},
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
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	// Start the container with an attached PTY.
	if _, err := d.Run(dockerutil.RunOpts{
		Image: "basic/alpine",
		Pty: func(_ *exec.Cmd, ptmx *os.File) {
			// Call "sleep 100" in the shell.
			if _, err := ptmx.Write([]byte("sleep 100\n")); err != nil {
				t.Fatalf("error writing to pty: %v", err)
			}

			// Give shell a few seconds to start executing the sleep.
			time.Sleep(2 * time.Second)

			// Send a ^C to the pty, which should kill sleep, but
			// not the shell.  \x03 is ASCII "end of text", which
			// is the same as ^C.
			if _, err := ptmx.Write([]byte{'\x03'}); err != nil {
				t.Fatalf("error writing to pty: %v", err)
			}

			// The shell should still be alive at this point. Sleep
			// should have exited with code 2+128=130. We'll exit
			// with 10 plus that number, so that we can be sure
			// that the shell did not get signalled.
			if _, err := ptmx.Write([]byte("exit $(expr $? + 10)\n")); err != nil {
				t.Fatalf("error writing to pty: %v", err)
			}
		},
	}, "sh"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Wait for the container to exit.
	got, err := d.Wait(5 * time.Second)
	if err != nil {
		t.Fatalf("error getting exit code: %v", err)
	}
	// Container should exit with code 10+130=140.
	if want := syscall.WaitStatus(140); got != want {
		t.Errorf("container exited with code %d want %d", got, want)
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
				d := dockerutil.MakeDocker(t)
				defer d.CleanUp()

				opts := dockerutil.RunOpts{
					Image:    "basic/alpine",
					WorkDir:  tc.workingDir,
					ReadOnly: readonly,
				}
				got, err := d.Run(opts, "sh", "-c", "echo ${PWD}")
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
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	opts := dockerutil.RunOpts{Image: "tmpfile"}
	got, err := d.Run(opts, "cat", "/tmp/foo/file.txt")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	if want := "123\n"; want != got {
		t.Errorf("invalid file content, want: %q, got: %q", want, got)
	}
}

// TestHostOverlayfsCopyUp tests that the --overlayfs-stale-read option causes
// runsc to hide the incoherence of FDs opened before and after overlayfs
// copy-up on the host.
func TestHostOverlayfsCopyUp(t *testing.T) {
	d := dockerutil.MakeDocker(t)
	defer d.CleanUp()

	if _, err := d.Run(dockerutil.RunOpts{
		Image:   "hostoverlaytest",
		WorkDir: "/root",
	}, "./test"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
