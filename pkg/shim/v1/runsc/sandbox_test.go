// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runsc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	api "github.com/containerd/containerd/api/runtime/sandbox/v1"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	"github.com/containerd/containerd/v2/pkg/stdio"
	"github.com/containerd/errdefs"
	errgrpc "github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
)

func TestCgroupsPath(t *testing.T) {
	for _, tc := range []struct {
		parent string
		want   string
	}{
		{
			parent: "/kubepods/besteffort/pod123",
			want:   "/kubepods/besteffort/pod123/sb",
		},
		{
			parent: "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod123.slice",
			want:   "kubepods-besteffort-pod123.slice:cri-containerd:sb",
		},
	} {
		if got := cgroupsPath(tc.parent, "sb"); got != tc.want {
			t.Errorf("cgroupsPath(%q) = %q, want %q", tc.parent, got, tc.want)
		}
	}
}

func TestSandboxSpec(t *testing.T) {
	config := &podSandboxConfig{
		name:         "name",
		namespace:    "ns",
		uid:          "uid",
		hostname:     "host",
		logDirectory: "/logs",
		annotations: map[string]string{
			"dev.gvisor.flag.debug": "true",
			"other":                 "x",
		},
		cgroupParent: "/kubepods/pod123",
		sysctls:      map[string]string{"net.ipv4.ip_forward": "1"},
		resources: &podResources{
			cpuPeriod:   100000,
			cpuQuota:    50000,
			cpuShares:   512,
			memoryLimit: 1 << 30,
		},
	}
	passed := map[string]string{"dev.gvisor.flag.strace": "true"}

	got := sandboxSpec("sb", "/var/run/netns/cni-1", passed, config)

	want := &specs.Spec{
		Version:  specs.Version,
		Hostname: "host",
		Annotations: map[string]string{
			"dev.gvisor.flag.strace":                  "true",
			"io.kubernetes.cri.container-type":        "sandbox",
			"io.kubernetes.cri.sandbox-id":            "sb",
			"io.kubernetes.cri.sandbox-name":          "name",
			"io.kubernetes.cri.sandbox-namespace":     "ns",
			"io.kubernetes.cri.sandbox-uid":           "uid",
			"io.kubernetes.cri.sandbox-log-directory": "/logs",
			"io.kubernetes.cri.sandbox-cpu-period":    "100000",
			"io.kubernetes.cri.sandbox-cpu-quota":     "50000",
			"io.kubernetes.cri.sandbox-cpu-shares":    "512",
			"io.kubernetes.cri.sandbox-mem":           "1073741824",
		},
		Linux: &specs.Linux{
			CgroupsPath: "/kubepods/pod123/sb",
			Sysctl:      map[string]string{"net.ipv4.ip_forward": "1"},
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.NetworkNamespace, Path: "/var/run/netns/cni-1"},
			},
		},
	}
	// Pod annotations are not copied; Process and Root stay nil.
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("sandboxSpec mismatch (-want +got):\n%s", diff)
	}
}

func TestSandboxSpecHostNetwork(t *testing.T) {
	got := sandboxSpec("sb", "", nil, &podSandboxConfig{hostNetwork: true})
	if len(got.Linux.Namespaces) != 0 {
		t.Errorf("sandboxSpec namespaces = %+v, want none", got.Linux.Namespaces)
	}
	if got.Linux.CgroupsPath != "" {
		t.Errorf("sandboxSpec cgroups path = %q, want none", got.Linux.CgroupsPath)
	}
}

// newTestSandbox returns a service serving a started sandbox whose runsc
// commands all succeed without doing anything.
func newTestSandbox(id string) (*runscService, *proc.Init) {
	init := proc.New(id, &runsccmd.Runsc{Command: "/bin/true"}, stdio.Stdio{})
	init.Platform = nopPlatform{}
	s := &runscService{containers: map[string]*Container{}}
	s.mu.Lock()
	s.sandbox = &sandboxState{
		id:        id,
		container: &Container{ID: id, task: init},
		started:   true,
	}
	s.mu.Unlock()
	return s, init
}

func TestWaitSandbox(t *testing.T) {
	const id = "sb"
	s, _ := newTestSandbox(id)

	if _, err := s.WaitSandbox(context.Background(), &api.WaitSandboxRequest{SandboxID: "other"}); !errdefs.IsNotFound(errgrpc.ToNative(err)) {
		t.Errorf("WaitSandbox(other) = %v, want NotFound", err)
	}

	// Before the sandbox exits, WaitSandbox returns when its caller gives up.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := s.WaitSandbox(ctx, &api.WaitSandboxRequest{SandboxID: id}); !errors.Is(errgrpc.ToNative(err), context.DeadlineExceeded) {
		t.Errorf("WaitSandbox before exit = %v, want DeadlineExceeded", err)
	}

	// The exit reaches the sandbox through the shim's exit handling.
	s.checkProcesses(context.Background(), proc.Exit{Timestamp: time.Now(), ID: id, Status: 3})
	resp, err := s.WaitSandbox(context.Background(), &api.WaitSandboxRequest{SandboxID: id})
	if err != nil {
		t.Fatalf("WaitSandbox after exit: %v", err)
	}
	if resp.ExitStatus != 3 {
		t.Errorf("WaitSandbox exit status = %d, want 3", resp.ExitStatus)
	}
}

func TestStopSandboxDeadline(t *testing.T) {
	s, init := newTestSandbox("sb")

	// The delete succeeds, but the exit is never reported, so StopSandbox
	// returns when its caller's deadline passes rather than after TimeoutSecs.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := s.StopSandbox(ctx, &api.StopSandboxRequest{SandboxID: "sb", TimeoutSecs: 60}); !errors.Is(errgrpc.ToNative(err), context.DeadlineExceeded) {
		t.Errorf("StopSandbox = %v, want DeadlineExceeded", err)
	}
	select {
	case <-init.Exited():
		t.Errorf("StopSandbox recorded an exit after its caller gave up")
	default:
	}
}

func TestShutdownSandboxWaitsForBundleRemoval(t *testing.T) {
	s, init := newTestSandbox("sb")
	bundle := t.TempDir()
	s.mu.Lock()
	s.sandbox.bundle = bundle
	s.mu.Unlock()
	_, sd := shutdown.WithShutdown(context.Background())
	s.shutdown = sd

	if _, err := s.ShutdownSandbox(context.Background(), &api.ShutdownSandboxRequest{SandboxID: "sb"}); err != nil {
		t.Fatalf("ShutdownSandbox: %v", err)
	}
	// The sandbox is gone, so a pending WaitSandbox must return.
	select {
	case <-init.Exited():
	default:
		t.Errorf("ShutdownSandbox did not record the sandbox exit")
	}
	select {
	case <-sd.Done():
		t.Fatalf("shim shut down before containerd deleted the bundle")
	case <-time.After(3 * removalPollInterval):
	}

	// containerd deletes the bundle once it has the reply.
	if err := os.RemoveAll(bundle); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sd.Done():
	case <-time.After(10 * time.Second):
		t.Fatalf("shim did not shut down after the bundle was deleted")
	}
}

func TestShutdownSandboxUnknown(t *testing.T) {
	s := &runscService{containers: map[string]*Container{}}
	_, sd := shutdown.WithShutdown(context.Background())
	s.shutdown = sd

	if _, err := s.ShutdownSandbox(context.Background(), &api.ShutdownSandboxRequest{SandboxID: "sb"}); err != nil {
		t.Fatalf("ShutdownSandbox: %v", err)
	}
	select {
	case <-sd.Done():
	case <-time.After(10 * time.Second):
		t.Fatalf("shim did not shut down")
	}
}

func TestCreateSandboxRejectsSpec(t *testing.T) {
	bundle := t.TempDir()
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &runscService{containers: map[string]*Container{}}
	_, err := s.CreateSandbox(context.Background(), &api.CreateSandboxRequest{SandboxID: "sb", BundlePath: bundle})
	if !errdefs.IsNotImplemented(errgrpc.ToNative(err)) {
		t.Errorf("CreateSandbox with a spec = %v, want NotImplemented", err)
	}
}
