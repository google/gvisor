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

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
)

// getSandboxConfig returns a containerd configuration for testing the sandbox
// controller. It uses "sandbox_mode" for containerd 1.7 and "sandboxer" for
// containerd 2.0+.
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
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
`
}

func TestSandboxControllerUnimplemented(t *testing.T) {
	// Override containerd config to use the dedicated sandbox config.
	oldConfigFunc := getContainerdConfig
	defer func() { getContainerdConfig = oldConfigFunc }()

	// Keep track of original extraEnv to restore it after the test.
	oldExtraEnv := extraEnv
	defer func() { extraEnv = oldExtraEnv }()

	getContainerdConfig = func(major, minor uint64) string {
		if major < 1 || (major == 1 && minor < 7) {
			t.Skipf("skipping test because containerd version %d.%d does not support sandboxer config (requires >= 1.7)", major, minor)
			return oldConfigFunc(major, minor)
		}

		// Inject ENABLE_CRI_SANDBOXES=1 into containerd's environment.
		// This is required for containerd 1.7 to enable the experimental Sandbox API,
		// but not needed for containerd 2.0+.
		if major == 1 && minor == 7 {
			extraEnv = append(extraEnv, "ENABLE_CRI_SANDBOXES=1")
		}

		return getSandboxConfig(major, minor)
	}

	// Setup containerd and crictl.
	crictl, cleanup, err := setup(t, false /* enableGrouping */)
	if err != nil {
		t.Fatalf("failed to setup crictl: %v", err)
	}
	defer cleanup()

	// Run a helper pod. It should fail because CreateSandbox is unimplemented.
	sbSpec := Sandbox("sandbox-test")
	sbSpecFile, specCleanup, err := testutil.WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		t.Fatalf("failed to write sandbox spec: %v", err)
	}
	defer specCleanup()

	_, err = crictl.RunPod(containerdRuntime, sbSpecFile)
	if err == nil {
		t.Fatalf("expected RunPod to fail, but it succeeded")
	}

	// We expect the error to contain "Unimplemented" or "not implemented".
	// The exact error message depends on how containerd wraps it, but since we
	// return errdefs.ErrNotImplemented, it should map to gRPC code Unimplemented.
	// crictl output usually contains "Unimplemented".
	errStr := err.Error()
	t.Logf("RunPod failed as expected with error: %s", errStr)

	if !strings.Contains(errStr, "Unimplemented") && !strings.Contains(errStr, "not implemented") {
		t.Errorf("expected error to indicate 'Unimplemented' or 'not implemented', got: %s", errStr)
	}
}
