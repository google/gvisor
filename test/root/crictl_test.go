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
	s := map[string]any{
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
func SimpleSpec(name, image string, cmd []string, extra map[string]any) string {
	s := map[string]any{
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
	crictl, cleanup, err := setup(t, false /* enableGrouping */)
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

	// Since shim grouping is disabled, there will be one shim process for the
	// container and another one for the sandbox.
	count, err := countShimProcesses(t, contID)
	if err != nil {
		t.Fatalf("failed to count shim processes for containerID %s: %v", contID, err)
	}
	if count != 1 {
		t.Errorf("got %d shim processes for containerID %s, want 1", count, contID)
	}

	count, err = countShimProcesses(t, podID)
	if err != nil {
		t.Fatalf("failed to count shim processes for podID %s: %v", podID, err)
	}
	if count != 1 {
		t.Errorf("got %d shim processes for podID %s, want 1", count, podID)
	}

	// Stop everything.
	if err := crictl.StopPodAndContainer(podID, contID); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// HttpdMountPaths is a JSON config for an httpd container with additional
// mounts.
var HttpdMountPaths = SimpleSpec("httpd", "basic/httpd", nil, map[string]any{
	"mounts": []map[string]any{
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
	"linux": map[string]any{},
})

// TestMountPaths refers to b/117635704.
func TestMountPaths(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
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
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	spec := SimpleSpec("busybox", "basic/symlink-resolv", []string{"sleep", "1000"}, nil)
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/symlink-resolv", Sandbox("default"), spec)
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
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
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

// containerdConfig is the containerd (1.5+) configuration file that
// configures the gVisor shim.
//
// Note that the v2 shim binary name must be containerd-shim-<runtime>-v1.
const containerdConfig = `
version=2
disabled_plugins = ["io.containerd.internal.v1.restart"]
[plugins."io.containerd.grpc.v1.cri"]
  disable_tcp_service = true
[plugins."io.containerd.runtime.v1.linux"]
  shim_debug = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.` + containerdRuntime + `]
  runtime_type = "io.containerd.` + containerdRuntime + `.v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.` + containerdRuntime + `.options]
  TypeUrl = "io.containerd.` + containerdRuntime + `.v1.options"
`

// setup sets up before a test. Specifically it:
//   - Creates the /etc/containerd/runsc/config.toml file.
//   - Creates directories and a socket for containerd to utilize.
//   - Runs containerd and waits for it to reach a "ready" state for testing.
//   - Returns a cleanup function that should be called at the end of the test.
func setup(t *testing.T, enableGrouping bool) (*criutil.Crictl, func(), error) {
	runscConfigPath := "/etc/containerd/runsc/config.toml"
	runscConfigDir := path.Dir(runscConfigPath)
	if err := os.MkdirAll(runscConfigDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create runsc config directory %q: %v", runscConfigDir, err)
	}
	cu := cleanup.Make(func() { os.RemoveAll(runscConfigDir) })
	defer cu.Clean()

	runscConfig := `
log_path = "/tmp/shim-logs/"
log_level = "debug"
grouping = ` + strconv.FormatBool(enableGrouping) + `
[runsc_config]
    debug = "true"
    debug-log = "/tmp/runsc-logs/"
    strace = "true"
    file-access = "shared"
`
	if err := os.WriteFile(runscConfigPath, []byte(runscConfig), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write runsc config file %q: %v", runscConfigPath, err)
	}
	t.Logf("Wrote runsc config:\n%s", runscConfig)

	// Create temporary containerd root and state directories, and a socket
	// via which crictl and containerd communicate.
	containerdRoot, err := os.MkdirTemp(testutil.TmpDir(), "containerd-root")
	if err != nil {
		t.Fatalf("failed to create containerd root: %v", err)
	}
	cu.Add(func() { os.RemoveAll(containerdRoot) }) // Cleanup the directory
	t.Logf("Using containerd root: %s", containerdRoot)

	containerdState, err := os.MkdirTemp(testutil.TmpDir(), "containerd-state")
	if err != nil {
		t.Fatalf("failed to create containerd state: %v", err)
	}
	cu.Add(func() { os.RemoveAll(containerdState) })
	t.Logf("Using containerd state: %s", containerdState)

	sockDir, err := os.MkdirTemp(testutil.TmpDir(), "containerd-sock")
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
	r := regexp.MustCompile(` v([0-9]+)\.([0-9]+)\.([0-9+])`)
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
	modifiedPath, ok := os.LookupEnv("PATH")
	if ok {
		modifiedPath = ":" + modifiedPath // We prepend below.
	}
	modifiedPath = path.Dir(getContainerd()) + modifiedPath
	modifiedPath = runtimeDir + ":" + modifiedPath
	t.Logf("Using PATH: %v", modifiedPath)

	// Generate the configuration for the test.
	config := getContainerdConfig(major, minor)
	t.Logf("Using config: %s", config)
	configFile, configCleanup, err := testutil.WriteTmpFile("containerd-config", config)
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
	go io.Copy(io.Discard, startupR)

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

// getShimPIDs finds running containerd-shim-runsc-v1 processes whose
// cwd contains the given ID, and returns their PIDs.
// If id is empty, it finds all shim processes.
func getShimPIDs(id string) ([]string, error) {
	const shimPath = "/usr/local/bin/containerd-shim-runsc-v1"
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %v", err)
	}
	defer procDir.Close()
	names, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %v", err)
	}

	var pids []string
	for _, name := range names {
		if _, err := strconv.Atoi(name); err != nil {
			continue
		}

		cmdlineBytes, err := os.ReadFile(path.Join("/proc", name, "cmdline"))
		if err != nil {
			continue
		}
		if len(cmdlineBytes) == 0 {
			continue
		}
		cmdline := bytes.Split(cmdlineBytes, []byte{0})
		if !(len(cmdline) > 0 && string(cmdline[0]) == shimPath) {
			continue
		}

		if id != "" {
			cwd, err := os.Readlink(path.Join("/proc", name, "cwd"))
			if err != nil {
				continue
			}
			if !strings.Contains(cwd, id) {
				continue
			}
		}
		pids = append(pids, name)
	}
	return pids, nil
}

// getPidsRSS returns the total RSS memory in KB for the given PIDs.
func getPidsRSS(t *testing.T, pids []string) int64 {
	var rssKB int64
	for _, pid := range pids {
		statusBytes, err := os.ReadFile(path.Join("/proc", pid, "status"))
		if err != nil {
			// Cannot read status, skip memory calculation for this process.
			t.Logf("failed to read /proc/%s/status for shim process: %v", pid, err)
			continue
		}
		for _, line := range strings.Split(string(statusBytes), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					rss, err := strconv.ParseInt(parts[1], 10, 64)
					if err == nil {
						rssKB += rss
					}
				}
				break
			}
		}
	}
	return rssKB
}

// countShimProcesses counts running containerd-shim-runsc-v1 processes whose
// cwd contains the given ID. This is done by iterating through /proc/<pid>/cwd
// and checking /proc/<pid>/cmdline for the shim path. When shim grouping is:
// - Enabled: Only the pod ID should have an associated shim process. The
// container IDs should not have an associated shim process.
// - Disabled: The pod ID and container IDs should have different shim processes.
func countShimProcesses(t *testing.T, id string) (int, error) {
	pids, err := getShimPIDs(id)
	if err != nil {
		return 0, err
	}
	return len(pids), nil
}

// TestCrictlOneShim tests that only one shim is created for multiple containers in a pod.
func TestCrictlOneShim(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	if err := crictl.Import("basic/httpd"); err != nil {
		t.Fatalf("failed to import image: %v", err)
	}

	sbSpec := Sandbox("one-shim")
	sbSpecFile, specCleanup, err := testutil.WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		t.Fatalf("failed to write sandbox spec: %v", err)
	}
	defer specCleanup()

	podID, err := crictl.RunPod(containerdRuntime, sbSpecFile)
	if err != nil {
		t.Fatalf("failed to run pod: %v", err)
	}
	t.Logf("podID: %v", podID)

	contSpec1 := SimpleSpec("httpd1", "basic/httpd", nil, nil)
	contSpecFile1, specCleanup1, err := testutil.WriteTmpFile("contSpec1", contSpec1)
	if err != nil {
		t.Fatalf("failed to write container spec 1: %v", err)
	}
	defer specCleanup1()

	contID1, err := crictl.Create(podID, contSpecFile1, sbSpecFile)
	t.Logf("container id 1: %v", contID1)
	if err != nil {
		t.Fatalf("failed to create container 1: %v", err)
	}
	if _, err := crictl.Start(contID1); err != nil {
		t.Fatalf("failed to start container 1: %v", err)
	}

	contSpec2 := SimpleSpec("httpd2", "basic/httpd", nil, nil)
	contSpecFile2, specCleanup2, err := testutil.WriteTmpFile("contSpec2", contSpec2)
	if err != nil {
		t.Fatalf("failed to write container spec 2: %v", err)
	}
	defer specCleanup2()

	contID2, err := crictl.Create(podID, contSpecFile2, sbSpecFile)
	t.Logf("container id 2: %v", contID2)
	if err != nil {
		t.Fatalf("failed to create container 2: %v", err)
	}
	if _, err := crictl.Start(contID2); err != nil {
		t.Fatalf("failed to start container 2: %v", err)
	}

	// Check number of shim processes for container ID.
	count, err := countShimProcesses(t, contID1)
	if err != nil {
		t.Fatalf("failed to count shim processes for containerID %s: %v", contID1, err)
	}
	if count != 0 {
		t.Errorf("got %d shim processes for containerID %s, want 0", count, contID1)
	}

	count, err = countShimProcesses(t, contID2)
	if err != nil {
		t.Fatalf("failed to count shim processes for containerID %s: %v", contID2, err)
	}
	if count != 0 {
		t.Errorf("got %d shim processes for containerID %s, want 0", count, contID2)
	}

	// Check number of shim processes for pod ID.
	count, err = countShimProcesses(t, podID)
	if err != nil {
		t.Fatalf("failed to count shim processes for podID %s: %v", podID, err)
	}
	if count != 1 {
		t.Errorf("got %d shim processes for podID %s, want 1", count, podID)
	}

	// Stop everything.
	if err := crictl.StopContainer(contID1); err != nil {
		t.Errorf("failed to stop container 1: %v", err)
	}
	if err := crictl.StopContainer(contID2); err != nil {
		t.Errorf("failed to stop container 2: %v", err)
	}
	if err := crictl.StopPod(podID); err != nil {
		t.Errorf("failed to stop pod: %v", err)
	}
	if err := crictl.RmPod(podID); err != nil {
		t.Errorf("failed to remove pod: %v", err)
	}
}

// TestExecWithGrouping tests that exec works correctly with shim grouping.
func TestExecWithGrouping(t *testing.T) {
	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	if err := crictl.Import("basic/busybox"); err != nil {
		t.Fatalf("failed to import image: %v", err)
	}

	sbSpec := Sandbox("exec")
	sbSpecFile, specCleanup, err := testutil.WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		t.Fatalf("failed to write sandbox spec: %v", err)
	}
	defer specCleanup()

	podID, err := crictl.RunPod(containerdRuntime, sbSpecFile)
	if err != nil {
		t.Fatalf("failed to run pod: %v", err)
	}
	t.Logf("podID: %v", podID)

	contSpec1 := SimpleSpec("cont1", "basic/busybox", []string{"sleep", "1000"}, nil)
	contSpecFile1, specCleanup1, err := testutil.WriteTmpFile("contSpec1", contSpec1)
	if err != nil {
		t.Fatalf("failed to write container spec 1: %v", err)
	}
	defer specCleanup1()

	contID1, err := crictl.Create(podID, contSpecFile1, sbSpecFile)
	t.Logf("container id 1: %v", contID1)
	if err != nil {
		t.Fatalf("failed to create container 1: %v", err)
	}
	if _, err := crictl.Start(contID1); err != nil {
		t.Fatalf("failed to start container 1: %v", err)
	}

	contSpec2 := SimpleSpec("cont2", "basic/busybox", []string{"sleep", "1000"}, nil)
	contSpecFile2, specCleanup2, err := testutil.WriteTmpFile("contSpec2", contSpec2)
	if err != nil {
		t.Fatalf("failed to write container spec 2: %v", err)
	}
	defer specCleanup2()

	contID2, err := crictl.Create(podID, contSpecFile2, sbSpecFile)
	t.Logf("container id 2: %v", contID2)
	if err != nil {
		t.Fatalf("failed to create container 2: %v", err)
	}
	if _, err := crictl.Start(contID2); err != nil {
		t.Fatalf("failed to start container 2: %v", err)
	}

	// Check number of shim processes for pod ID.
	count, err := countShimProcesses(t, podID)
	if err != nil {
		t.Fatalf("failed to count shim processes for podID %s: %v", podID, err)
	}
	if count != 1 {
		t.Errorf("got %d shim processes for podID %s, want 1", count, podID)
	}

	if _, err := crictl.Exec(contID1, "sh", "-c", "setsid sleep 5 & echo $!"); err != nil {
		t.Fatalf("failed to start background process in container 1: %v", err)
	}

	// Check number of shim processes for pod ID after exec.
	count, err = countShimProcesses(t, podID)
	if err != nil {
		t.Fatalf("failed to count shim processes for podID %s: %v", podID, err)
	}
	if count != 1 {
		t.Errorf("got %d shim processes for podID %s after exec, want 1", count, podID)
	}

	// Check that both containers are still running by exec'ing 'true'.
	if _, err := crictl.Exec(contID1, "true"); err != nil {
		t.Errorf("container 1 not running after killing exec'd process: %v", err)
	}
	if _, err := crictl.Exec(contID2, "true"); err != nil {
		t.Errorf("container 2 not running after killing exec'd process: %v", err)
	}

	// Stop everything.
	if err := crictl.StopContainer(contID1); err != nil {
		t.Errorf("failed to stop container 1: %v", err)
	}
	if err := crictl.StopContainer(contID2); err != nil {
		t.Errorf("failed to stop container 2: %v", err)
	}
	if err := crictl.StopPod(podID); err != nil {
		t.Errorf("failed to stop pod: %v", err)
	}
	if err := crictl.RmPod(podID); err != nil {
		t.Errorf("failed to remove pod: %v", err)
	}
}

// runPodStartup is a helper for TestShimGroupingPerformance.
func runPodStartup(t *testing.T, enableGrouping bool, numPods, numContsPerPod int) (time.Duration, int64) {
	crictl, cleanup, err := setup(t, enableGrouping)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	if err := crictl.Import("basic/busybox"); err != nil {
		t.Fatalf("failed to import image: %v", err)
	}

	var sbSpecFiles []string
	var sbSpecCleanups []func()
	for i := 0; i < numPods; i++ {
		sbSpec := Sandbox(fmt.Sprintf("pod-%d", i))
		sbSpecFile, specCleanup, err := testutil.WriteTmpFile(fmt.Sprintf("sbSpec-%d", i), sbSpec)
		if err != nil {
			t.Fatalf("failed to write sandbox spec: %v", err)
		}
		sbSpecFiles = append(sbSpecFiles, sbSpecFile)
		sbSpecCleanups = append(sbSpecCleanups, specCleanup)
	}
	defer func() {
		for _, cleanup := range sbSpecCleanups {
			cleanup()
		}
	}()

	var contSpecFiles []string
	var contSpecCleanups []func()
	for j := 0; j < numContsPerPod; j++ {
		contSpec := SimpleSpec(fmt.Sprintf("cont-%d", j), "basic/busybox", []string{"sleep", "1000"}, nil)
		contSpecFile, contSpecCleanup, err := testutil.WriteTmpFile(fmt.Sprintf("contSpec-%d", j), contSpec)
		if err != nil {
			t.Fatalf("failed to write container spec: %v", err)
		}
		contSpecFiles = append(contSpecFiles, contSpecFile)
		contSpecCleanups = append(contSpecCleanups, contSpecCleanup)
	}
	defer func() {
		for _, cleanup := range contSpecCleanups {
			cleanup()
		}
	}()

	start := time.Now()
	for i := 0; i < numPods; i++ {
		podID, err := crictl.RunPod(containerdRuntime, sbSpecFiles[i])
		if err != nil {
			t.Fatalf("failed to run pod: %v", err)
		}

		for j := 0; j < numContsPerPod; j++ {
			contID, err := crictl.Create(podID, contSpecFiles[j], sbSpecFiles[i])
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}
			if _, err := crictl.Start(contID); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}
		}
	}
	duration := time.Since(start)

	pids, err := getShimPIDs("")
	if err != nil {
		t.Fatalf("failed to get shim pids: %v", err)
	}
	rss := getPidsRSS(t, pids)
	t.Logf("Grouping=%t: %d shim processes using %d KB RSS", enableGrouping, len(pids), rss)

	return duration, rss
}

// TestShimGroupingPerformance measures startup time difference with and
// without shim grouping.
func TestShimGroupingPerformance(t *testing.T) {
	const numPods = 10
	const numContsPerPod = 5
	var durationWithGrouping, durationWithoutGrouping time.Duration
	var memWithGrouping, memWithoutGrouping int64
	t.Run("WithGrouping", func(t *testing.T) {
		durationWithGrouping, memWithGrouping = runPodStartup(t, true, numPods, numContsPerPod)
	})
	t.Run("WithoutGrouping", func(t *testing.T) {
		durationWithoutGrouping, memWithoutGrouping = runPodStartup(t, false, numPods, numContsPerPod)
	})
	t.Logf("Pod startup with %d pods, %d containers each:", numPods, numContsPerPod)
	t.Logf("  Grouping enabled: %v, memory: %d KB", durationWithGrouping, memWithGrouping)
	t.Logf("  Grouping disabled: %v, memory: %d KB", durationWithoutGrouping, memWithoutGrouping)
	if durationWithoutGrouping > 0 {
		improvement := 100 * (durationWithoutGrouping - durationWithGrouping).Seconds() / durationWithoutGrouping.Seconds()
		t.Logf("  Performance improvement: %.2f%% (%v)", improvement, durationWithoutGrouping-durationWithGrouping)
	}
	if memWithoutGrouping > 0 {
		memSaved := 100 * float64(memWithoutGrouping-memWithGrouping) / float64(memWithoutGrouping)
		t.Logf("  Memory saved: %.2f%% (%d KB)", memSaved, memWithoutGrouping-memWithGrouping)
	}
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

func getContainerdConfig(major, minor uint64) string {
	return containerdConfig
}
