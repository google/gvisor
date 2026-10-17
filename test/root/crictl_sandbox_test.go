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

package root

// Tests for the containerd sandbox API: runtime handlers configured with
// sandboxer = "shim". There is no pause container; the shim boots the sandbox
// with `runsc create --no-root-container`.
//
// The shim reports bootstrap version 2, and below version 3 containerd starts a
// shim per container rather than using the sandbox's shim
// (supportSandboxAPIVersion in core/runtime/v2/shim_manager.go). So shim
// grouping still matters here, and the tests run with it on and off.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"gvisor.dev/gvisor/pkg/test/criutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// groupingModes are the shim grouping settings the tests run under.
var groupingModes = []struct {
	name           string
	enableGrouping bool
}{
	{name: "enableGrouping", enableGrouping: true},
	{name: "disableGrouping", enableGrouping: false},
}

// getSandboxConfig returns a containerd config that sends runsc pods through
// the sandbox API. It uses "sandbox_mode" for containerd 1.7 and "sandboxer"
// for 2.0+.
//
// It has no runsc options section, which a sandboxer = "shim" handler cannot
// have (see runsc.resolveOptions). The shim reads
// /etc/containerd/runsc/config.toml instead, which setup() writes.
func getSandboxConfig(major, minor uint64) string {
	sandboxerField := "sandboxer = \"shim\""
	if major == 1 && minor == 7 {
		sandboxerField = "sandbox_mode = \"shim\""
	}

	return `
version=2
disabled_plugins = ["io.containerd.internal.v1.restart"]
[plugins."io.containerd.grpc.v1.cri"]
  disable_tcp_service = true
[plugins."io.containerd.runtime.v1.linux"]
  shim_debug = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
  ` + sandboxerField + `
`
}

// setupSandboxController brings up containerd with runsc pods going through
// the sandbox API.
func setupSandboxController(t *testing.T, enableGrouping bool) (*criutil.Crictl, func(), error) {
	t.Helper()

	return setupWith(t, setupOpts{
		enableGrouping: enableGrouping,
		containerdConfig: func(major, minor uint64) string {
			if major < 1 || (major == 1 && minor < 7) {
				t.Skipf("skipping test because containerd version %d.%d does not support sandboxer config (requires >= 1.7)", major, minor)
			}
			return getSandboxConfig(major, minor)
		},
		// ENABLE_CRI_SANDBOXES=1 enables the sandbox API on containerd 1.7.
		extraEnv: []string{"ENABLE_CRI_SANDBOXES=1"},
	})
}

// TestSandboxController runs a pod through the sandbox API.
func TestSandboxController(t *testing.T) {
	for _, tc := range groupingModes {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setupSandboxController(t, tc.enableGrouping)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()

			spec := SimpleSpec("busybox", "basic/busybox", []string{"sleep", "1000"}, nil)
			sbSpec := Sandbox(testutil.RandomID("sandbox-controller"))
			podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, spec)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			if got, err := crictl.Exec(contID, "echo", "hello"); err != nil {
				t.Errorf("exec failed: %v", err)
			} else if want := "hello"; !strings.Contains(got, want) {
				t.Errorf("exec output = %q, want it to contain %q", got, want)
			}

			if err := crictl.StopPodAndContainers(podID, []string{contID}); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

// TestSandboxControllerOutlivesContainers checks that a sandbox with no
// containers left can still start a new one.
func TestSandboxControllerOutlivesContainers(t *testing.T) {
	for _, tc := range groupingModes {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setupSandboxController(t, tc.enableGrouping)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()

			spec := SimpleSpec("first", "basic/busybox", []string{"sleep", "1000"}, nil)
			sbSpec := Sandbox(testutil.RandomID("sandbox-outlives"))
			podID, firstID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, spec)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			if err := crictl.StopContainer(firstID); err != nil {
				t.Fatalf("failed to stop container: %v", err)
			}

			secondSpec := SimpleSpec("second", "basic/busybox", []string{"sleep", "1000"}, nil)
			secondID, err := crictl.StartContainer(podID, "basic/busybox", sbSpec, secondSpec)
			if err != nil {
				t.Fatalf("failed to start a second container in the pod: %v", err)
			}
			if got, err := crictl.Exec(secondID, "echo", "still here"); err != nil {
				t.Errorf("exec failed: %v", err)
			} else if want := "still here"; !strings.Contains(got, want) {
				t.Errorf("exec output = %q, want it to contain %q", got, want)
			}

			if err := crictl.StopPodAndContainers(podID, []string{secondID}); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

// TestSandboxControllerShimGrouping checks how many shims a sandbox API pod
// gets, and that they exit on teardown.
func TestSandboxControllerShimGrouping(t *testing.T) {
	for _, tc := range groupingModes {
		t.Run(tc.name, func(t *testing.T) {
			crictl, cleanup, err := setupSandboxController(t, tc.enableGrouping)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()

			sbSpec := Sandbox(testutil.RandomID("sandbox-grouping"))
			firstSpec := SimpleSpec("first", "basic/busybox", []string{"sleep", "1000"}, nil)
			podID, firstID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, firstSpec)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			secondSpec := SimpleSpec("second", "basic/busybox", []string{"sleep", "1000"}, nil)
			secondID, err := crictl.StartContainer(podID, "basic/busybox", sbSpec, secondSpec)
			if err != nil {
				t.Fatalf("failed to start second container: %v", err)
			}

			// The sandbox always has its own shim.
			if count, err := countShimProcesses(t, podID); err != nil {
				t.Fatalf("failed to count shim processes for podID %s: %v", podID, err)
			} else if count != 1 {
				t.Errorf("got %d shim processes for podID %s, want 1", count, podID)
			}

			// Containers reuse it only with grouping.
			wantPerContainer := 1
			if tc.enableGrouping {
				wantPerContainer = 0
			}
			for _, contID := range []string{firstID, secondID} {
				count, err := countShimProcesses(t, contID)
				if err != nil {
					t.Fatalf("failed to count shim processes for containerID %s: %v", contID, err)
				}
				if count != wantPerContainer {
					t.Errorf("got %d shim processes for containerID %s, want %d", count, contID, wantPerContainer)
				}
			}

			if err := crictl.StopPodAndContainers(podID, []string{firstID, secondID}); err != nil {
				t.Fatalf("stop failed: %v", err)
			}

			// containerd does not wait for the shim to exit after
			// ShutdownSandbox, so poll.
			if err := testutil.Poll(func() error {
				count, err := countShimProcesses(t, podID)
				if err != nil {
					return &backoff.PermanentError{Err: err}
				}
				if count != 0 {
					return fmt.Errorf("got %d shim processes for podID %s after teardown, want 0", count, podID)
				}
				return nil
			}, 10*time.Second); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestSandboxControllerNetworking checks that the sandbox joins the pod
// network namespace, which the shim takes from CreateSandboxRequest.NetnsPath.
func TestSandboxControllerNetworking(t *testing.T) {
	crictl, cleanup, err := setupSandboxController(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	sbSpec := Sandbox(testutil.RandomID("sandbox-net"))
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/httpd", sbSpec, Httpd)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if err := httpGet(crictl, podID, "index.html"); err != nil {
		t.Fatalf("failed to get page: %v", err)
	}

	if err := crictl.StopPodAndContainers(podID, []string{contID}); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// TestSandboxControllerSharedNetns checks that all containers in a pod share
// its network namespace.
func TestSandboxControllerSharedNetns(t *testing.T) {
	crictl, cleanup, err := setupSandboxController(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	sbSpec := Sandbox(testutil.RandomID("sandbox-netns"))
	firstSpec := SimpleSpec("first", "basic/busybox", []string{"sleep", "1000"}, nil)
	podID, firstID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, firstSpec)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	secondSpec := SimpleSpec("second", "basic/busybox", []string{"sleep", "1000"}, nil)
	secondID, err := crictl.StartContainer(podID, "basic/busybox", sbSpec, secondSpec)
	if err != nil {
		t.Fatalf("failed to start second container: %v", err)
	}

	podIP, err := crictl.PodIP(podID)
	if err != nil {
		t.Fatalf("failed to get pod IP: %v", err)
	}
	for _, contID := range []string{firstID, secondID} {
		out, err := crictl.Exec(contID, "ip", "-4", "-o", "addr", "show")
		if err != nil {
			t.Fatalf("failed to list addresses in container %s: %v (out: %s)", contID, err, out)
		}
		if !strings.Contains(out, podIP) {
			t.Errorf("container %s does not have the pod IP %s; addresses:\n%s", contID, podIP, out)
		}
	}

	if err := crictl.StopPodAndContainers(podID, []string{firstID, secondID}); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

// sandboxStatusOutput is the part of `crictl inspectp` output the tests check.
// "info" is the verbose info SandboxStatus returns. Identity is checked via the
// runtime spec annotations, because containerd may rewrite "info" through its
// own SandboxInfo type, which has no "sandboxID".
type sandboxStatusOutput struct {
	Status struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"status"`
	Info struct {
		Pid         int `json:"pid"`
		RuntimeSpec struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"runtimeSpec"`
	} `json:"info"`
}

// TestSandboxControllerStatus checks what SandboxStatus reports through CRI
// PodSandboxStatus.
func TestSandboxControllerStatus(t *testing.T) {
	crictl, cleanup, err := setupSandboxController(t, true /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	spec := SimpleSpec("busybox", "basic/busybox", []string{"sleep", "1000"}, nil)
	sbSpec := Sandbox(testutil.RandomID("sandbox-status"))
	podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", sbSpec, spec)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	out, err := crictl.InspectPod(podID)
	if err != nil {
		t.Fatalf("inspectp failed: %v", err)
	}
	var status sandboxStatusOutput
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("failed to parse inspectp output: %v\n%s", err, out)
	}
	if got, want := status.Status.State, "SANDBOX_READY"; got != want {
		t.Errorf("sandbox state = %q, want %q", got, want)
	}
	if got := status.Status.ID; got != podID {
		t.Errorf("sandbox id = %q, want %q", got, podID)
	}

	if got := status.Info.Pid; got <= 0 {
		t.Errorf("verbose info pid = %d, want a live pid\n%s", got, out)
	}
	if got := status.Info.RuntimeSpec.Annotations["io.kubernetes.cri.sandbox-id"]; got != podID {
		t.Errorf("verbose info runtimeSpec sandbox-id annotation = %q, want %q\n%s", got, podID, out)
	}

	// Stop without removing, so the pod can still be inspected.
	if err := crictl.StopContainer(contID); err != nil {
		t.Fatalf("failed to stop container: %v", err)
	}
	if err := crictl.StopPod(podID); err != nil {
		t.Fatalf("failed to stop pod: %v", err)
	}

	out, err = crictl.InspectPod(podID)
	if err != nil {
		t.Fatalf("inspectp after stop failed: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("failed to parse inspectp output: %v\n%s", err, out)
	}
	if got, want := status.Status.State, "SANDBOX_NOTREADY"; got != want {
		t.Errorf("sandbox state after stop = %q, want %q", got, want)
	}

	if err := crictl.RmPod(podID); err != nil {
		t.Fatalf("failed to remove pod: %v", err)
	}
}
