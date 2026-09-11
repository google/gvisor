// Copyright 2021 The gVisor Authors.
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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/containerd/console"
	apievents "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	coreevents "github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/stdio"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/shim/v1/proc"
	"gvisor.dev/gvisor/pkg/shim/v1/runsccmd"
	"gvisor.dev/gvisor/pkg/shim/v1/utils"
)

// errorPublisher is a publisher that always returns an error.
type errorPublisher struct{}

func (p *errorPublisher) Publish(_ context.Context, _ string, _ coreevents.Event) error {
	return fmt.Errorf("dial unix: missing address")
}

func (p *errorPublisher) Close() error { return nil }

// TestForwardDoesNotPanicOnPublishError verifies that the event forward
// function logs errors instead of panicking when the publisher fails and no
// event sink is configured (empty TTRPC_ADDRESS). This is how the shim runs
// under CRI-O, where publish errors are expected and non-fatal.
func TestForwardDoesNotPanicOnPublishError(t *testing.T) {
	// Empty TTRPC_ADDRESS means no event sink is configured (as under CRI-O).
	t.Setenv("TTRPC_ADDRESS", "")

	s := &runscService{
		events: make(chan any, 2),
	}
	s.events <- &apievents.TaskCreate{ContainerID: "test"}
	s.events <- &apievents.TaskExit{ContainerID: "test"}
	close(s.events)

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forward(context.Background(), &errorPublisher{})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not complete within timeout")
	}
}

// TestForwardPanicsOnPublishErrorUnderContainerd verifies that, when a
// containerd event sink is configured (TTRPC_ADDRESS set), a publish failure
// remains fatal (panics) as it did before CRI-O support was added. This keeps
// the non-fatal behavior scoped to the CRI-O case only.
func TestForwardPanicsOnPublishErrorUnderContainerd(t *testing.T) {
	t.Setenv("TTRPC_ADDRESS", "/run/containerd/containerd.sock.ttrpc")

	s := &runscService{
		events: make(chan any, 1),
	}
	s.events <- &apievents.TaskCreate{ContainerID: "test"}
	close(s.events)

	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		s.forward(context.Background(), &errorPublisher{})
	}()

	select {
	case r := <-panicked:
		if r == nil {
			t.Fatal("forward did not panic on publish error under containerd")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forward did not complete within timeout")
	}
}

// fakeOOMPoller reports a fixed OOM verdict per container id.
type fakeOOMPoller struct {
	oom map[string]bool
}

func (f *fakeOOMPoller) add(string, any) error { return nil }
func (f *fakeOOMPoller) run(context.Context)   {}
func (f *fakeOOMPoller) isOOM(id string) bool  { return f.oom[id] }
func (f *fakeOOMPoller) Close() error          { return nil }

// nopPlatform is a no-op console platform for proc.Init.
type nopPlatform struct{}

func (nopPlatform) CopyConsole(_ context.Context, cons console.Console, _, _, _, _ string, _ *sync.WaitGroup) (console.Console, error) {
	return cons, nil
}
func (nopPlatform) ShutdownConsole(context.Context, console.Console) error { return nil }
func (nopPlatform) Close() error                                           { return nil }

// TestCheckProcessesOOMExitStatus verifies the exit status published on init
// process exit when the container was OOM-killed. When the memcg kill lands on
// the sentry, `runsc wait` cannot recover the real signal status and reports
// the synthetic proc.InternalErrorCode; since the cgroup confirms an OOM kill,
// the shim must publish 128+SIGKILL (137) instead so tooling keyed on the
// standard OOM exit code works. A real exit status must never be overridden.
func TestCheckProcessesOOMExitStatus(t *testing.T) {
	const sigkillStatus = 137 // 128 + SIGKILL
	for _, tc := range []struct {
		name        string
		oom         bool
		exitStatus  int
		wantStatus  int
		wantTaskOOM bool
	}{
		{
			// Sentry OOM-killed: wait failed (128) and cgroup confirms OOM.
			name:        "oom-internal-error-becomes-137",
			oom:         true,
			exitStatus:  proc.InternalErrorCode,
			wantStatus:  sigkillStatus,
			wantTaskOOM: true,
		},
		{
			// OOM confirmed but runsc reported a real status: keep it.
			name:        "oom-real-status-preserved",
			oom:         true,
			exitStatus:  2,
			wantStatus:  2,
			wantTaskOOM: true,
		},
		{
			// Wait failure without OOM: generic status stays 128.
			name:        "no-oom-internal-error-preserved",
			oom:         false,
			exitStatus:  proc.InternalErrorCode,
			wantStatus:  proc.InternalErrorCode,
			wantTaskOOM: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const cid = "test-container"
			init := proc.New(cid, &runsccmd.Runsc{Command: "/nonexistent/runsc"}, stdio.Stdio{})
			init.Platform = nopPlatform{}
			c := &Container{
				ID:   cid,
				task: init,
			}
			s := &runscService{
				events:     make(chan any, 4),
				containers: map[string]*Container{cid: c},
				oomPoller:  &fakeOOMPoller{oom: map[string]bool{cid: tc.oom}},
			}

			s.checkProcesses(context.Background(), proc.Exit{
				Timestamp: time.Now(),
				ID:        cid,
				Status:    tc.exitStatus,
			})

			if got := init.ExitStatus(); got != tc.wantStatus {
				t.Errorf("init.ExitStatus() = %d, want %d", got, tc.wantStatus)
			}

			var got []any
			for len(s.events) > 0 {
				got = append(got, <-s.events)
			}
			want := 1
			if tc.wantTaskOOM {
				want = 2
			}
			if len(got) != want {
				t.Fatalf("got %d events (%v), want %d", len(got), got, want)
			}
			idx := 0
			if tc.wantTaskOOM {
				oomEv, ok := got[idx].(*apievents.TaskOOM)
				if !ok {
					t.Fatalf("event %d = %T, want *TaskOOM (must precede TaskExit)", idx, got[idx])
				}
				if oomEv.ContainerID != cid {
					t.Errorf("TaskOOM.ContainerID = %q, want %q", oomEv.ContainerID, cid)
				}
				idx++
			}
			exitEv, ok := got[idx].(*apievents.TaskExit)
			if !ok {
				t.Fatalf("event %d = %T, want *TaskExit", idx, got[idx])
			}
			if exitEv.ExitStatus != uint32(tc.wantStatus) {
				t.Errorf("TaskExit.ExitStatus = %d, want %d", exitEv.ExitStatus, tc.wantStatus)
			}
		})
	}
}

func TestContainerUpdateNilResources(t *testing.T) {
	c := &Container{}
	err := c.Update(t.Context(), &task.UpdateTaskRequest{ID: "x", Resources: nil})
	if !errors.Is(err, errdefs.ErrInvalidArgument) {
		t.Fatalf("Update(nil Resources): %v, want ErrInvalidArgument", err)
	}
}

func TestCgroupPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple",
			path: "foo/pod123/container",
			want: "foo/pod123",
		},
		{
			name: "absolute",
			path: "/foo/pod123/container",
			want: "/foo/pod123",
		},
		{
			name: "no-container",
			path: "foo/pod123",
			want: "",
		},
		{
			name: "no-container-absolute",
			path: "/foo/pod123",
			want: "",
		},
		{
			name: "double-pod",
			path: "/foo/podium/pod123/container",
			want: "/foo/podium/pod123",
		},
		{
			name: "start-pod",
			path: "pod123/container",
			want: "pod123",
		},
		{
			name: "start-pod-absolute",
			path: "/pod123/container",
			want: "/pod123",
		},
		{
			name: "slashes",
			path: "///foo/////pod123//////container",
			want: "/foo/pod123",
		},
		{
			name: "no-pod",
			path: "/foo/nopod123/container",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: tc.path,
				},
			}
			updated := setPodCgroup(&spec)
			if got := spec.Annotations[cgroupParentAnnotation]; got != tc.want {
				t.Errorf("setPodCgroup(%q), want: %q, got: %q", tc.path, tc.want, got)
			}
			if shouldUpdate := len(tc.want) > 0; shouldUpdate != updated {
				t.Errorf("setPodCgroup(%q)=%v, want: %v", tc.path, updated, shouldUpdate)
			}
		})
	}
}

// Test cases that cgroup path should not be updated.
func TestCgroupNoUpdate(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *specs.Spec
	}{
		{
			name: "empty",
			spec: &specs.Spec{},
		},
		{
			name: "subcontainer",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: "foo/pod123/container",
				},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation: utils.ContainerTypeContainer,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if updated := setPodCgroup(tc.spec); updated {
				t.Errorf("setPodCgroup(%+v), got: %v, want: false", tc.spec.Linux, updated)
			}
		})
	}
}

// TestApplyPodResourcesFromAnnotations exercises the translation of the CRI
// io.kubernetes.cri.sandbox-* annotations into spec.Linux.Resources.
// See google/gvisor#13777.
func TestApplyPodResourcesFromAnnotations(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	u64 := func(v uint64) *uint64 { return &v }

	for _, tc := range []struct {
		name        string
		spec        *specs.Spec
		wantUpdated bool
		wantQuota   *int64
		wantPeriod  *uint64
		wantShares  *uint64
		wantMemLim  *int64
		// wantNoLinux asserts spec.Linux stays nil (used for the non-sandbox case).
		wantNoLinux bool
		// wantNoResources asserts spec.Linux.Resources stays nil.
		wantNoResources bool
	}{
		{
			name: "nil-spec",
			spec: nil,
		},
		{
			name: "no-annotations",
			spec: &specs.Spec{},
		},
		{
			name: "container-untouched",
			spec: &specs.Spec{
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation:    utils.ContainerTypeContainer,
					utils.SandboxCPUQuotaAnnotation:  "85800",
					utils.SandboxCPUPeriodAnnotation: "100000",
					utils.SandboxMemoryAnnotation:    "2304770048",
				},
			},
			wantNoLinux: true,
		},
		{
			name: "sandbox-no-relevant-annotations",
			spec: &specs.Spec{
				Annotations: map[string]string{"foo": "bar"},
			},
		},
		{
			name: "sandbox-full-limits-overwrite-pause-shares",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{Shares: u64(2)}, // pause container's default shares
					},
				},
				Annotations: map[string]string{
					utils.SandboxCPUQuotaAnnotation:  "85800",
					utils.SandboxCPUPeriodAnnotation: "100000",
					utils.SandboxCPUSharesAnnotation: "684",
					utils.SandboxMemoryAnnotation:    "2304770048",
				},
			},
			wantUpdated: true,
			wantQuota:   i64(85800),
			wantPeriod:  u64(100000),
			// Shares=2 is containerd's pause-container default, not pod-level shares.
			wantShares: u64(684),
			wantMemLim: i64(2304770048),
		},
		{
			name: "sandbox-memory-only",
			spec: &specs.Spec{
				Annotations: map[string]string{
					utils.SandboxMemoryAnnotation: "1073741824",
				},
			},
			wantUpdated: true,
			wantMemLim:  i64(1073741824),
		},
		{
			name: "sandbox-unparsable-cpu-quota-skipped",
			spec: &specs.Spec{
				Annotations: map[string]string{
					utils.SandboxCPUQuotaAnnotation: "not-an-int",
					utils.SandboxMemoryAnnotation:   "1073741824",
				},
			},
			// mem still applied, so still updated
			wantUpdated: true,
			wantQuota:   nil,
			wantMemLim:  i64(1073741824),
		},
		{
			name: "sandbox-zero-annotations-skipped",
			spec: &specs.Spec{
				Annotations: map[string]string{
					utils.SandboxCPUQuotaAnnotation:  "0",
					utils.SandboxCPUPeriodAnnotation: "0",
					utils.SandboxCPUSharesAnnotation: "0",
					utils.SandboxMemoryAnnotation:    "0",
				},
			},
			wantNoResources: true,
		},
		{
			name: "sandbox-negative-quota-and-memory-skipped",
			spec: &specs.Spec{
				Annotations: map[string]string{
					utils.SandboxCPUQuotaAnnotation:  "-1",
					utils.SandboxCPUPeriodAnnotation: "100000",
					utils.SandboxMemoryAnnotation:    "-1",
				},
			},
			wantUpdated: true,
			wantPeriod:  u64(100000),
		},
		{
			name: "sandbox-preexisting-non-default-shares-preserved",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{Shares: u64(1024)},
					},
				},
				Annotations: map[string]string{
					utils.SandboxCPUSharesAnnotation: "684",
				},
			},
			wantUpdated: false,
			wantShares:  u64(1024),
		},
		{
			name: "containerd-sandbox-spec-fixture",
			// Mirrors a real fixture captured from eks-verdent-ag: a gVisor
			// sandbox pod with requests/limits cpu=2,memory=4Gi had pod-level
			// annotations shares=2048/quota=200000/period=100000/memory=4294967296,
			// while linux.resources.cpu.shares still carried the pause default 2.
			spec: &specs.Spec{
				Linux: &specs.Linux{
					CgroupsPath: "kubepods-podfixture.slice:cri-containerd:sandbox",
					Resources: &specs.LinuxResources{
						Memory: &specs.LinuxMemory{Limit: i64(4294967296)},
						CPU: &specs.LinuxCPU{
							Shares: u64(2),
							Quota:  i64(200000),
							Period: u64(100000),
						},
					},
				},
				Annotations: map[string]string{
					utils.ContainerTypeAnnotation:    "sandbox",
					utils.SandboxCPUPeriodAnnotation: "100000",
					utils.SandboxCPUQuotaAnnotation:  "200000",
					utils.SandboxCPUSharesAnnotation: "2048",
					utils.SandboxMemoryAnnotation:    "4294967296",
				},
			},
			wantUpdated: true,
			wantQuota:   i64(200000),
			wantPeriod:  u64(100000),
			wantShares:  u64(2048),
			wantMemLim:  i64(4294967296),
		},
		{
			name: "sandbox-preexisting-quota-preserved",
			spec: &specs.Spec{
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{Quota: i64(50000)},
					},
				},
				Annotations: map[string]string{
					utils.SandboxCPUQuotaAnnotation: "85800",
				},
			},
			wantUpdated: false,
			// Preexisting quota must be preserved.
			wantQuota: i64(50000),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			updated := applyPodResourcesFromAnnotations(tc.spec)
			if updated != tc.wantUpdated {
				t.Errorf("applyPodResourcesFromAnnotations updated = %v, want %v",
					updated, tc.wantUpdated)
			}
			if tc.spec == nil {
				return
			}
			if tc.wantNoLinux {
				if tc.spec.Linux != nil {
					t.Errorf("expected Linux to remain nil for non-sandbox container")
				}
				return
			}
			if tc.wantNoResources {
				if tc.spec.Linux != nil && tc.spec.Linux.Resources != nil {
					t.Errorf("expected Linux.Resources to remain nil, got %+v", tc.spec.Linux.Resources)
				}
				return
			}
			// Extract actual values, tolerating nil chains.
			var gotQuota *int64
			var gotPeriod, gotShares *uint64
			var gotMemLim *int64
			if tc.spec.Linux != nil && tc.spec.Linux.Resources != nil {
				if c := tc.spec.Linux.Resources.CPU; c != nil {
					gotQuota, gotPeriod, gotShares = c.Quota, c.Period, c.Shares
				}
				if m := tc.spec.Linux.Resources.Memory; m != nil {
					gotMemLim = m.Limit
				}
			}
			eqI := func(t *testing.T, name string, got, want *int64) {
				t.Helper()
				switch {
				case got == nil && want == nil:
				case got == nil || want == nil:
					t.Errorf("%s got=%v want=%v", name, got, want)
				case *got != *want:
					t.Errorf("%s got=%d want=%d", name, *got, *want)
				}
			}
			eqU := func(t *testing.T, name string, got, want *uint64) {
				t.Helper()
				switch {
				case got == nil && want == nil:
				case got == nil || want == nil:
					t.Errorf("%s got=%v want=%v", name, got, want)
				case *got != *want:
					t.Errorf("%s got=%d want=%d", name, *got, *want)
				}
			}
			eqI(t, "cpu.quota", gotQuota, tc.wantQuota)
			eqU(t, "cpu.period", gotPeriod, tc.wantPeriod)
			eqU(t, "cpu.shares", gotShares, tc.wantShares)
			eqI(t, "mem.limit", gotMemLim, tc.wantMemLim)
		})
	}
}
