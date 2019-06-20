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
// Setup instruction in runsc/test/README.md.
package integration

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/test/testutil"
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
	if err := testutil.Pull("nginx"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("lifecycle-test")
	if err := d.Create("-p", "80", "nginx"); err != nil {
		t.Fatal("docker create failed:", err)
	}
	if err := d.Start(); err != nil {
		d.CleanUp()
		t.Fatal("docker start failed:", err)
	}

	// Test that container is working
	port, err := d.FindPort(80)
	if err != nil {
		t.Fatal("docker.FindPort(80) failed: ", err)
	}
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatal("WaitForHTTP() timeout:", err)
	}
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}

	if err := d.Stop(); err != nil {
		d.CleanUp()
		t.Fatal("docker stop failed:", err)
	}
	if err := d.Remove(); err != nil {
		t.Fatal("docker rm failed:", err)
	}
}

func TestPauseResume(t *testing.T) {
	if !testutil.IsPauseResumeSupported() {
		t.Log("Pause/resume is not supported, skipping test.")
		return
	}

	if err := testutil.Pull("google/python-hello"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("pause-resume-test")
	if err := d.Run("-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatal("docker.FindPort(8080) failed:", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatal("WaitForHTTP() timeout:", err)
	}

	// Check that container is working.
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}

	if err := d.Pause(); err != nil {
		t.Fatal("docker pause failed:", err)
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
		t.Fatal("docker unpause failed:", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatal("WaitForHTTP() timeout:", err)
	}

	// Check if container is working again.
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}
}

func TestCheckpointRestore(t *testing.T) {
	if !testutil.IsPauseResumeSupported() {
		t.Log("Pause/resume is not supported, skipping test.")
		return
	}
	if err := testutil.Pull("google/python-hello"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("save-restore-test")
	if err := d.Run("-p", "8080", "google/python-hello"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer d.CleanUp()

	if err := d.Checkpoint("test"); err != nil {
		t.Fatal("docker checkpoint failed:", err)
	}

	if _, err := d.Wait(30 * time.Second); err != nil {
		t.Fatal(err)
	}

	if err := d.Restore("test"); err != nil {
		t.Fatal("docker restore failed:", err)
	}

	// Find where port 8080 is mapped to.
	port, err := d.FindPort(8080)
	if err != nil {
		t.Fatal("docker.FindPort(8080) failed:", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(port, 30*time.Second); err != nil {
		t.Fatal("WaitForHTTP() timeout:", err)
	}

	// Check if container is working again.
	client := http.Client{Timeout: time.Duration(2 * time.Second)}
	if err := httpRequestSucceeds(client, "localhost", port); err != nil {
		t.Error("http request failed:", err)
	}
}

// Create client and server that talk to each other using the local IP.
func TestConnectToSelf(t *testing.T) {
	d := testutil.MakeDocker("connect-to-self-test")

	// Creates server that replies "server" and exists. Sleeps at the end because
	// 'docker exec' gets killed if the init process exists before it can finish.
	if err := d.Run("ubuntu:trusty", "/bin/sh", "-c", "echo server | nc -l -p 8080 && sleep 1"); err != nil {
		t.Fatal("docker run failed:", err)
	}
	defer d.CleanUp()

	// Finds IP address for host.
	ip, err := d.Exec("/bin/sh", "-c", "cat /etc/hosts | grep ${HOSTNAME} | awk '{print $1}'")
	if err != nil {
		t.Fatal("docker exec failed:", err)
	}
	ip = strings.TrimRight(ip, "\n")

	// Runs client that sends "client" to the server and exits.
	reply, err := d.Exec("/bin/sh", "-c", fmt.Sprintf("echo client | nc %s 8080", ip))
	if err != nil {
		t.Fatal("docker exec failed:", err)
	}

	// Ensure both client and server got the message from each other.
	if want := "server\n"; reply != want {
		t.Errorf("Error on server, want: %q, got: %q", want, reply)
	}
	if _, err := d.WaitForOutput("^client\n$", 1*time.Second); err != nil {
		t.Fatal("docker.WaitForOutput(client) timeout:", err)
	}
}

func TestMemLimit(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("cgroup-test")
	cmd := "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'"
	out, err := d.RunFg("--memory=500MB", "alpine", "sh", "-c", cmd)
	if err != nil {
		t.Fatal("docker run failed:", err)
	}
	defer d.CleanUp()

	// Remove warning message that swap isn't present.
	if strings.HasPrefix(out, "WARNING") {
		lines := strings.Split(out, "\n")
		if len(lines) != 3 {
			t.Fatalf("invalid output: %s", out)
		}
		out = lines[1]
	}

	got, err := strconv.ParseUint(strings.TrimSpace(out), 10, 64)
	if err != nil {
		t.Fatalf("failed to parse %q: %v", out, err)
	}
	if want := uint64(500 * 1024); got != want {
		t.Errorf("MemTotal got: %d, want: %d", got, want)
	}
}

func TestNumCPU(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("cgroup-test")
	cmd := "cat /proc/cpuinfo | grep 'processor.*:' | wc -l"
	out, err := d.RunFg("--cpuset-cpus=0", "alpine", "sh", "-c", cmd)
	if err != nil {
		t.Fatal("docker run failed:", err)
	}
	defer d.CleanUp()

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
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatalf("docker pull failed: %v", err)
	}
	d := testutil.MakeDocker("job-control-test")

	// Start the container with an attached PTY.
	_, ptmx, err := d.RunWithPty("alpine", "sh")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	defer ptmx.Close()
	defer d.CleanUp()

	// Call "sleep 100" in the shell.
	if _, err := ptmx.Write([]byte("sleep 100\n")); err != nil {
		t.Fatalf("error writing to pty: %v", err)
	}

	// Give shell a few seconds to start executing the sleep.
	time.Sleep(2 * time.Second)

	// Send a ^C to the pty, which should kill sleep, but not the shell.
	// \x03 is ASCII "end of text", which is the same as ^C.
	if _, err := ptmx.Write([]byte{'\x03'}); err != nil {
		t.Fatalf("error writing to pty: %v", err)
	}

	// The shell should still be alive at this point. Sleep should have
	// exited with code 2+128=130. We'll exit with 10 plus that number, so
	// that we can be sure that the shell did not get signalled.
	if _, err := ptmx.Write([]byte("exit $(expr $? + 10)\n")); err != nil {
		t.Fatalf("error writing to pty: %v", err)
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

// TestTmpFile checks that files inside '/tmp' are not overridden. In addition,
// it checks that working dir is created if it doesn't exit.
func TestTmpFile(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("tmp-file-test")
	if err := d.Run("-w=/tmp/foo/bar", "--read-only", "alpine", "touch", "/tmp/foo/bar/file"); err != nil {
		t.Fatal("docker run failed:", err)
	}
	defer d.CleanUp()
}

func TestMain(m *testing.M) {
	testutil.EnsureSupportedDockerVersion()
	os.Exit(m.Run())
}
