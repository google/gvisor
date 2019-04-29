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

package root

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/runsc/specutils"
	"gvisor.googlesource.com/gvisor/runsc/test/root/testdata"
	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

// Tests for crictl have to be run as root (rather than in a user namespace)
// because crictl creates named network namespaces in /var/run/netns/.

func TestCrictlSanity(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()
	podID, contID, err := crictl.StartPodAndContainer("httpd", testdata.Sandbox, testdata.Httpd)
	if err != nil {
		t.Fatal(err)
	}

	// Look for the httpd page.
	if err = httpGet(crictl, podID, "index.html"); err != nil {
		t.Fatalf("failed to get page: %v", err)
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatal(err)
	}
}

func TestMountPaths(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()
	podID, contID, err := crictl.StartPodAndContainer("httpd", testdata.Sandbox, testdata.HttpdMountPaths)
	if err != nil {
		t.Fatal(err)
	}

	// Look for the directory available at /test.
	if err = httpGet(crictl, podID, "test"); err != nil {
		t.Fatalf("failed to get page: %v", err)
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatal(err)
	}
}

func TestMountOverSymlinks(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()
	podID, contID, err := crictl.StartPodAndContainer("k8s.gcr.io/busybox", testdata.Sandbox, testdata.MountOverSymlink)
	if err != nil {
		t.Fatal(err)
	}

	out, err := crictl.Exec(contID, "readlink", "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if want := "/tmp/resolv.conf"; !strings.Contains(string(out), want) {
		t.Fatalf("/etc/resolv.conf is not pointing to %q: %q", want, string(out))
	}

	etc, err := crictl.Exec(contID, "cat", "/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := crictl.Exec(contID, "cat", "/tmp/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if tmp != etc {
		t.Fatalf("file content doesn't match:\n\t/etc/resolv.conf: %s\n\t/tmp/resolv.conf: %s", string(etc), string(tmp))
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatal(err)
	}
}

// setup sets up before a test. Specifically it:
// * Creates directories and a socket for containerd to utilize.
// * Runs containerd and waits for it to reach a "ready" state for testing.
// * Returns a cleanup function that should be called at the end of the test.
func setup(t *testing.T) (*testutil.Crictl, func(), error) {
	var cleanups []func()
	cleanupFunc := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	cleanup := specutils.MakeCleanup(cleanupFunc)
	defer cleanup.Clean()

	// Create temporary containerd root and state directories, and a socket
	// via which crictl and containerd communicate.
	containerdRoot, err := ioutil.TempDir(testutil.TmpDir(), "containerd-root")
	if err != nil {
		t.Fatalf("failed to create containerd root: %v", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(containerdRoot) })
	containerdState, err := ioutil.TempDir(testutil.TmpDir(), "containerd-state")
	if err != nil {
		t.Fatalf("failed to create containerd state: %v", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(containerdState) })
	sockAddr := filepath.Join(testutil.TmpDir(), "containerd-test.sock")

	// Start containerd.
	config, err := testutil.WriteTmpFile("containerd-config", testdata.ContainerdConfig(getRunsc()))
	if err != nil {
		t.Fatalf("failed to write containerd config")
	}
	cleanups = append(cleanups, func() { os.RemoveAll(config) })
	containerd := exec.Command(getContainerd(),
		"--config", config,
		"--log-level", "debug",
		"--root", containerdRoot,
		"--state", containerdState,
		"--address", sockAddr)
	cleanups = append(cleanups, func() {
		if err := testutil.KillCommand(containerd); err != nil {
			log.Printf("error killing containerd: %v", err)
		}
	})
	containerdStderr, err := containerd.StderrPipe()
	if err != nil {
		t.Fatalf("failed to get containerd stderr: %v", err)
	}
	containerdStdout, err := containerd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to get containerd stdout: %v", err)
	}
	if err := containerd.Start(); err != nil {
		t.Fatalf("failed running containerd: %v", err)
	}

	// Wait for containerd to boot. Then put all containerd output into a
	// buffer to be logged at the end of the test.
	testutil.WaitUntilRead(containerdStderr, "Start streaming server", nil, 10*time.Second)
	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	go func() { io.Copy(stdoutBuf, containerdStdout) }()
	go func() { io.Copy(stderrBuf, containerdStderr) }()
	cleanups = append(cleanups, func() {
		t.Logf("containerd stdout: %s", string(stdoutBuf.Bytes()))
		t.Logf("containerd stderr: %s", string(stderrBuf.Bytes()))
	})

	cleanup.Release()
	return testutil.NewCrictl(20*time.Second, sockAddr), cleanupFunc, nil
}

// httpGet GETs the contents of a file served from a pod on port 80.
func httpGet(crictl *testutil.Crictl, podID, filePath string) error {
	// Get the IP of the httpd server.
	ip, err := crictl.PodIP(podID)
	if err != nil {
		return fmt.Errorf("failed to get IP from pod %q: %v", podID, err)
	}

	// GET the page. We may be waiting for the server to start, so retry
	// with a timeout.
	var resp *http.Response
	cb := func() error {
		r, err := http.Get(fmt.Sprintf("http://%s", path.Join(ip, filePath)))
		resp = r
		return err
	}
	if err := testutil.Poll(cb, 20*time.Second); err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status returned: %d", resp.StatusCode)
	}
	return nil
}

func getContainerd() string {
	// Bazel doesn't pass PATH through, assume the location of containerd
	// unless specified by environment variable.
	c := os.Getenv("CONTAINERD_PATH")
	if c == "" {
		return "/usr/local/bin/containerd"
	}
	return c
}

func getRunsc() string {
	// Bazel doesn't pass PATH through, assume the location of runsc unless
	// specified by environment variable.
	c := os.Getenv("RUNSC_EXEC")
	if c == "" {
		return "/tmp/runsc-test/runsc"
	}
	return c
}
