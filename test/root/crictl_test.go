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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/test/criutil"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Tests for crictl have to be run as root (rather than in a user namespace)
// because crictl creates named network namespaces in /var/run/netns/.

// Sandbox returns a JSON config for a simple sandbox. Sandbox names must be
// unique so different names should be used when running tests on the same
// containerd instance.
func Sandbox(name string) string {
	// Sandbox is a default JSON config for a sandbox.
	s := map[string]interface{}{
		"metadata": map[string]string{
			"name":      name,
			"namespace": "default",
			"uid":       testutil.RandomID(""),
		},
		"linux":         map[string]string{},
		"log_directory": "/tmp",
	}

	v, err := json.Marshal(s)
	if err != nil {
		// This shouldn't happen.
		panic(err)
	}
	return string(v)
}

// SimpleSpec returns a JSON config for a simple container that runs the
// specified command in the specified image.
func SimpleSpec(name, image string, cmd []string, extra map[string]interface{}) string {
	s := map[string]interface{}{
		"metadata": map[string]string{
			"name": name,
		},
		"image": map[string]string{
			"image": testutil.ImageByName(image),
		},
		// Log files are not deleted after root tests are run. Log to random
		// paths to ensure logs are fresh.
		"log_path": fmt.Sprintf("%s.log", testutil.RandomID(name)),
		"stdin":    false,
		"tty":      false,
	}
	if len(cmd) > 0 { // Omit if empty.
		s["command"] = cmd
	}
	for k, v := range extra {
		s[k] = v // Extra settings.
	}
	v, err := json.Marshal(s)
	if err != nil {
		// This shouldn't happen.
		panic(err)
	}
	return string(v)
}

// Httpd is a JSON config for an httpd container.
var Httpd = SimpleSpec("httpd", "basic/httpd", nil, nil)

// TestCrictlSanity refers to b/112433158.
func TestCrictlSanity(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/httpd", Sandbox("default"), Httpd)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Look for the httpd page.
	if err = httpGet(crictl, podID, "index.html"); err != nil {
		t.Fatalf("failed to get page: %v", err)
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// HttpdMountPaths is a JSON config for an httpd container with additional
// mounts.
var HttpdMountPaths = SimpleSpec("httpd", "basic/httpd", nil, map[string]interface{}{
	"mounts": []map[string]interface{}{
		{
			"container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/volumes/kubernetes.io~secret/default-token-2rpfx",
			"readonly":       true,
		},
		{
			"container_path": "/etc/hosts",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/etc-hosts",
			"readonly":       false,
		},
		{
			"container_path": "/dev/termination-log",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/containers/httpd/d1709580",
			"readonly":       false,
		},
		{
			"container_path": "/usr/local/apache2/htdocs/test",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064",
			"readonly":       true,
		},
	},
	"linux": map[string]interface{}{},
})

// TestMountPaths refers to b/117635704.
func TestMountPaths(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/httpd", Sandbox("default"), HttpdMountPaths)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	// Look for the directory available at /test.
	if err = httpGet(crictl, podID, "test"); err != nil {
		t.Fatalf("failed to get page: %v", err)
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// TestMountPaths refers to b/118728671.
func TestMountOverSymlinks(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	spec := SimpleSpec("busybox", "basic/resolv", []string{"sleep", "1000"}, nil)
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/resolv", Sandbox("default"), spec)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	out, err := crictl.Exec(contID, "readlink", "/etc/resolv.conf")
	if err != nil {
		t.Fatalf("readlink failed: %v, out: %s", err, out)
	}
	if want := "/tmp/resolv.conf"; !strings.Contains(string(out), want) {
		t.Fatalf("/etc/resolv.conf is not pointing to %q: %q", want, string(out))
	}

	etc, err := crictl.Exec(contID, "cat", "/etc/resolv.conf")
	if err != nil {
		t.Fatalf("cat failed: %v, out: %s", err, etc)
	}
	tmp, err := crictl.Exec(contID, "cat", "/tmp/resolv.conf")
	if err != nil {
		t.Fatalf("cat failed: %v, out: %s", err, out)
	}
	if tmp != etc {
		t.Fatalf("file content doesn't match:\n\t/etc/resolv.conf: %s\n\t/tmp/resolv.conf: %s", string(etc), string(tmp))
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// TestHomeDir tests that the HOME environment variable is set for
// Pod containers.
func TestHomeDir(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	// Note that container ID returned here is a sub-container. All Pod
	// containers are sub-containers. The root container of the sandbox is the
	// pause container.
	t.Run("sub-container", func(t *testing.T) {
		contSpec := SimpleSpec("subcontainer", "basic/busybox", []string{"sh", "-c", "echo $HOME"}, nil)
		podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", Sandbox("subcont-sandbox"), contSpec)
		if err != nil {
			t.Fatalf("start failed: %v", err)
		}

		out, err := crictl.Logs(contID)
		if err != nil {
			t.Fatalf("failed retrieving container logs: %v, out: %s", err, out)
		}
		if got, want := strings.TrimSpace(string(out)), "/root"; got != want {
			t.Fatalf("Home directory invalid. Got %q, Want : %q", got, want)
		}

		// Stop everything; note that the pod may have already stopped.
		crictl.StopPodAndContainer(podID, contID)
	})

	// Tests that HOME is set for the exec process.
	t.Run("exec", func(t *testing.T) {
		contSpec := SimpleSpec("exec", "basic/busybox", []string{"sleep", "1000"}, nil)
		podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", Sandbox("exec-sandbox"), contSpec)
		if err != nil {
			t.Fatalf("start failed: %v", err)
		}

		out, err := crictl.Exec(contID, "sh", "-c", "echo $HOME")
		if err != nil {
			t.Fatalf("failed retrieving container logs: %v, out: %s", err, out)
		}
		if got, want := strings.TrimSpace(string(out)), "/root"; got != want {
			t.Fatalf("Home directory invalid. Got %q, Want : %q", got, want)
		}

		// Stop everything.
		if err := crictl.StopPodAndContainer(podID, contID); err != nil {
			t.Fatalf("stop failed: %v", err)
		}
	})
}

const containerdRuntime = "runsc"

// Template is the containerd configuration file that configures containerd with
// the gVisor shim, Note that the v2 shim binary name must be
// containerd-shim-<runtime>-v1.
const template = `
disabled_plugins = ["restart"]
[plugins.cri]
  disable_tcp_service = true
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.` + containerdRuntime + `]
  runtime_type = "io.containerd.` + containerdRuntime + `.v1"
[plugins.cri.containerd.runtimes.` + containerdRuntime + `.options]
  TypeUrl = "io.containerd.` + containerdRuntime + `.v1.options"
`

// setup sets up before a test. Specifically it:
// * Creates directories and a socket for containerd to utilize.
// * Runs containerd and waits for it to reach a "ready" state for testing.
// * Returns a cleanup function that should be called at the end of the test.
func setup(t *testing.T) (*criutil.Crictl, func(), error) {
	// Create temporary containerd root and state directories, and a socket
	// via which crictl and containerd communicate.
	containerdRoot, err := ioutil.TempDir(testutil.TmpDir(), "containerd-root")
	if err != nil {
		t.Fatalf("failed to create containerd root: %v", err)
	}
	cu := cleanup.Make(func() { os.RemoveAll(containerdRoot) })
	defer cu.Clean()
	t.Logf("Using containerd root: %s", containerdRoot)

	containerdState, err := ioutil.TempDir(testutil.TmpDir(), "containerd-state")
	if err != nil {
		t.Fatalf("failed to create containerd state: %v", err)
	}
	cu.Add(func() { os.RemoveAll(containerdState) })
	t.Logf("Using containerd state: %s", containerdState)

	sockDir, err := ioutil.TempDir(testutil.TmpDir(), "containerd-sock")
	if err != nil {
		t.Fatalf("failed to create containerd socket directory: %v", err)
	}
	cu.Add(func() { os.RemoveAll(sockDir) })
	sockAddr := path.Join(sockDir, "test.sock")
	t.Logf("Using containerd socket: %s", sockAddr)

	// Extract the containerd version.
	versionCmd := exec.Command(getContainerd(), "-v")
	out, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error extracting containerd version: %v (%s)", err, string(out))
	}
	r := regexp.MustCompile(" v([0-9]+)\\.([0-9]+)\\.([0-9+])")
	vs := r.FindStringSubmatch(string(out))
	if len(vs) != 4 {
		t.Fatalf("error unexpected version string: %s", string(out))
	}
	major, err := strconv.ParseUint(vs[1], 10, 64)
	if err != nil {
		t.Fatalf("error parsing containerd major version: %v (%s)", err, string(out))
	}
	minor, err := strconv.ParseUint(vs[2], 10, 64)
	if err != nil {
		t.Fatalf("error parsing containerd minor version: %v (%s)", err, string(out))
	}
	t.Logf("Using containerd version: %d.%d", major, minor)

	// Check if containerd supports shim v2.
	if major < 1 || (major == 1 && minor <= 1) {
		t.Skipf("skipping incompatible containerd (want at least 1.2, got %d.%d)", major, minor)
	}

	// We rewrite a configuration. This is based on the current docker
	// configuration for the runtime under test.
	runtime, err := dockerutil.RuntimePath()
	if err != nil {
		t.Fatalf("error discovering runtime path: %v", err)
	}
	t.Logf("Using runtime: %v", runtime)

	// Construct a PATH that includes the runtime directory. This is
	// because the shims will be installed there, and containerd may infer
	// the binary name and search the PATH.
	runtimeDir := path.Dir(runtime)
	modifiedPath := os.Getenv("PATH")
	if modifiedPath != "" {
		modifiedPath = ":" + modifiedPath // We prepend below.
	}
	modifiedPath = path.Dir(getContainerd()) + modifiedPath
	modifiedPath = runtimeDir + ":" + modifiedPath
	t.Logf("Using PATH: %v", modifiedPath)

	// Generate the configuration for the test.
	t.Logf("Using config: %s", template)
	configFile, configCleanup, err := testutil.WriteTmpFile("containerd-config", template)
	if err != nil {
		t.Fatalf("failed to write containerd config")
	}
	cu.Add(configCleanup)

	// Start containerd.
	args := []string{
		getContainerd(),
		"--config", configFile,
		"--log-level", "debug",
		"--root", containerdRoot,
		"--state", containerdState,
		"--address", sockAddr,
	}
	t.Logf("Using args: %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "PATH="+modifiedPath)

	// Include output in logs.
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	cu.Add(func() { stderrPipe.Close() })
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	cu.Add(func() { stdoutPipe.Close() })
	var (
		wg     sync.WaitGroup
		stderr bytes.Buffer
		stdout bytes.Buffer
	)
	startupR, startupW := io.Pipe()
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(io.MultiWriter(startupW, &stderr), stderrPipe)
	}()
	go func() {
		defer wg.Done()
		io.Copy(io.MultiWriter(startupW, &stdout), stdoutPipe)
	}()
	cu.Add(func() {
		wg.Wait()
		t.Logf("containerd stdout: %s", stdout.String())
		t.Logf("containerd stderr: %s", stderr.String())
	})

	// Start the process.
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed running containerd: %v", err)
	}

	// Wait for containerd to boot.
	if err := testutil.WaitUntilRead(startupR, "Start streaming server", 10*time.Second); err != nil {
		t.Fatalf("failed to start containerd: %v", err)
	}

	// Discard all subsequent data.
	go io.Copy(ioutil.Discard, startupR)

	// Create the crictl interface.
	cc := criutil.NewCrictl(t, sockAddr)
	cu.Add(cc.CleanUp)

	// Kill must be the last cleanup (as it will be executed first).
	cu.Add(func() {
		// Best effort: ignore errors.
		testutil.KillCommand(cmd)
	})

	return cc, cu.Release(), nil
}

// httpGet GETs the contents of a file served from a pod on port 80.
func httpGet(crictl *criutil.Crictl, podID, filePath string) error {
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
	// Use the local path if it exists, otherwise, use the system one.
	if _, err := os.Stat("/usr/local/bin/containerd"); err == nil {
		return "/usr/local/bin/containerd"
	}
	return "/usr/bin/containerd"
}
