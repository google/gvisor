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
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestCrictlSanity(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enableGrouping bool
	}{
		{
			name:           "enableGrouping",
			enableGrouping: true,
		},
		{
			name:           "disableGrouping",
			enableGrouping: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setup(t, tc.enableGrouping)
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
		})
	}
}

func TestMountPaths(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enableGrouping bool
	}{
		{
			name:           "enableGrouping",
			enableGrouping: true,
		},
		{
			name:           "disableGrouping",
			enableGrouping: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setup(t, tc.enableGrouping)
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
		})
	}
}

func TestMountOverSymlinks(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enableGrouping bool
	}{
		{
			name:           "enableGrouping",
			enableGrouping: true,
		},
		{
			name:           "disableGrouping",
			enableGrouping: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setup(t, tc.enableGrouping)
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
		})
	}
}

// TestHomeDir tests that the HOME environment variable is set for
// Pod containers.
func TestHomeDir(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enableGrouping bool
	}{
		{
			name:           "enableGrouping",
			enableGrouping: true,
		},
		{
			name:           "disableGrouping",
			enableGrouping: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Setup containerd and crictl.
			crictl, cleanup, err := setup(t, tc.enableGrouping)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()

			// Note that container ID returned here is a sub-container. All Pod
			// containers are sub-containers. The root container of the sandbox is the
			// pause container.
			t.Run("sub-container", func(t *testing.T) {
				contSpec := SimpleSpec("subcontainer", "basic/busybox", []string{"sh", "-c", "echo $HOME"}, nil)
				podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", Sandbox("default"), contSpec)
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
				podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", Sandbox("default"), contSpec)
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
		})
	}
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
