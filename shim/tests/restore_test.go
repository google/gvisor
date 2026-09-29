// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shim_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	tasktype "github.com/containerd/containerd/api/types/task"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	pb "gvisor.dev/gvisor/pkg/shim/v1/taskserver/task_server_go_proto"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/shim/shimutils"
)

// TestRestoreSandbox verifies the checkpoint/restore round trip over the task
// service: a create carrying a checkpoint path followed by a start brings the
// container back where it left off, rather than starting a fresh one.
//
// Restore is driven one container at a time, root container first. The root
// call restores the whole sandbox from the image; the rest reattach each
// container's gofer and stdio to processes that are already back.
func TestRestoreSandbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		// subcontainers is the number of application containers to run in the
		// sandbox alongside its root container.
		subcontainers int
		// named annotates every spec with a container name, the key runsc
		// matches a container to the image by. Without it runsc falls back to
		// creation order, so both paths are worth covering.
		named bool
	}{
		{
			name: "root container only",
		},
		{
			name:          "with subcontainer",
			subcontainers: 1,
		},
		{
			name:          "with named subcontainer",
			subcontainers: 1,
			named:         true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Keep the runsc state directory out of the working directory. The
			// container spec bind-mounts the working directory into the
			// sandbox, and runsc's own mounts underneath it break that bind.
			rootTmp, err := os.MkdirTemp("/tmp", "runsc-root-")
			if err != nil {
				t.Fatalf("failed to create temp root: %v", err)
			}
			t.Cleanup(func() {
				os.RemoveAll(rootTmp)
			})

			containerd := shimutils.NewMockContainerd(t, map[string]any{
				"root": rootTmp,
			}, map[string]any{
				"ignore-cgroups": "true",
			})

			// Markers go under testutil.TmpDir, which the spec already mounts
			// read-write. Everything else the container sees is the read-only
			// host root, and gVisor shadows /tmp with its own tmpfs.
			markerDir, err := os.MkdirTemp(testutil.TmpDir(), "markers-")
			if err != nil {
				t.Fatalf("failed to create marker dir: %v", err)
			}
			t.Cleanup(func() {
				os.RemoveAll(markerDir)
			})

			sandboxMarker := markerPath(markerDir, "sandbox")
			sandboxSpec := shimutils.NewSandboxSpec()
			sandboxSpec.Process.Args = markerArgs(sandboxMarker)
			runAsMappedRoot(sandboxSpec)
			if tc.named {
				nameContainer(sandboxSpec, "sandbox")
			}
			sandbox, client := setupSandboxWithSpec(t, containerd, sandboxSpec)

			opts, err := containerd.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options: %v", err)
			}

			// Containers in restore order: the root container, then the
			// application containers that joined it.
			containers := []*shimutils.Container{sandbox}
			markers := []string{sandboxMarker}
			for i := 0; i < tc.subcontainers; i++ {
				marker := markerPath(markerDir, fmt.Sprintf("container-%d", i))
				spec := shimutils.NewContainerSpec(sandbox.ID(), markerArgs(marker))
				runAsMappedRoot(spec)
				if tc.named {
					nameContainer(spec, fmt.Sprintf("container-%d", i))
				}
				container, err := shimutils.NewContainer(spec, containerd)
				if err != nil {
					t.Fatalf("failed to create container %d: %v", i, err)
				}
				if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
					t.Fatalf("failed to create container %d: %v", i, err)
				}
				if err := startAndWaitForContainer(t.Context(), client, container.ID(), containerd); err != nil {
					t.Fatalf("failed to start container %d: %v", i, err)
				}
				containers = append(containers, container)
				markers = append(markers, marker)
			}

			// Let every container get past its marker before checkpointing, so
			// that a marker written twice can only mean a restart.
			for _, marker := range markers {
				if err := waitForMarker(t.Context(), marker); err != nil {
					t.Fatalf("container did not start: %v", err)
				}
			}

			// Checkpoint takes the whole sandbox, not just the container it is
			// addressed to, and tears it down on the way out.
			imagePath, err := os.MkdirTemp(containerd.WorkingDir(), "checkpoint-")
			if err != nil {
				t.Fatalf("failed to create checkpoint dir: %v", err)
			}
			// Checkpoint has no containerd equivalent, so it arrives on
			// gVisor's own service — on the same socket as everything else.
			gvisorClient := containerd.GetTTRPCClient(t)
			checkpointReq := &pb.CheckpointRequest{
				Id:        sandbox.ID(),
				ImagePath: imagePath,
			}
			if err := gvisorClient.Call(t.Context(), "gvisor.task.TaskService", "Checkpoint", checkpointReq, &pb.CheckpointResponse{}); err != nil {
				t.Fatalf("failed to checkpoint sandbox: %v", err)
			}

			// Restore onto a fresh shim and a fresh runsc state directory,
			// neither holding a record of the checkpointed containers, which
			// leaves their IDs free to reuse. runsc itself matches a container
			// to the image by the name annotation on its spec, falling back to
			// creation order for a spec that carries no name.
			restoredRootTmp, err := os.MkdirTemp("/tmp", "runsc-restore-root-")
			if err != nil {
				t.Fatalf("failed to create temp root for restore: %v", err)
			}
			t.Cleanup(func() {
				os.RemoveAll(restoredRootTmp)
			})
			restored := shimutils.NewMockContainerdWithSuffix(t, "restore", map[string]any{
				"root": restoredRootTmp,
			}, map[string]any{
				"ignore-cgroups": "true",
			})
			if err := restored.StartShim(t, sandbox); err != nil {
				t.Fatalf("failed to start shim for restore: %v", err)
			}
			restoredClient := restored.GetClient(t)
			restoredOpts, err := restored.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options for restore: %v", err)
			}

			// The checkpoint on the create request is what makes the following
			// start restore the container instead of starting it.
			for i, container := range containers {
				createReq := &task.CreateTaskRequest{
					ID:         container.ID(),
					Bundle:     container.Bundle(),
					Options:    restoredOpts,
					Checkpoint: imagePath,
				}
				if _, err := restoredClient.Create(t.Context(), createReq); err != nil {
					t.Fatalf("failed to create %s from checkpoint: %v", container.ID(), err)
				}
				if err := startAndWaitForContainer(t.Context(), restoredClient, container.ID(), restored); err != nil {
					t.Fatalf("failed to restore %s: %v", container.ID(), err)
				}
				stateResp, err := restoredClient.State(t.Context(), &task.StateRequest{ID: container.ID()})
				if err != nil {
					t.Fatalf("failed to get state of restored %s: %v", container.ID(), err)
				}
				if stateResp.Status != tasktype.Status_RUNNING {
					t.Fatalf("restored %s has status %v, want %v", container.ID(), stateResp.Status, tasktype.Status_RUNNING)
				}
				if err := checkMarker(markers[i]); err != nil {
					t.Errorf("container %s was restarted, not restored: %v", container.ID(), err)
				}
			}

			if err := killAndWaitForContainer(t.Context(), restoredClient, sandbox.ID(), restored); err != nil {
				t.Fatalf("failed to kill and wait for restored sandbox: %v", err)
			}
		})
	}
}

// TestRestoreSubcontainerBeforeRoot verifies that restoring a subcontainer
// before the root container fails with an error naming the sandbox state.
func TestRestoreSubcontainerBeforeRoot(t *testing.T) {
	rootTmp, err := os.MkdirTemp("/tmp", "runsc-root-")
	if err != nil {
		t.Fatalf("failed to create temp root: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(rootTmp)
	})

	containerd := shimutils.NewMockContainerd(t, map[string]any{
		"root": rootTmp,
	}, map[string]any{
		"ignore-cgroups": "true",
	})
	sandbox, client := setupSandboxWithSpec(t, containerd, shimutils.NewSandboxSpec())
	opts, err := containerd.GetRuntimeOptions()
	if err != nil {
		t.Fatalf("failed to get runtime options: %v", err)
	}

	sub, err := shimutils.NewContainer(shimutils.NewContainerSpec(sandbox.ID(), []string{"sleep", "100000"}), containerd)
	if err != nil {
		t.Fatalf("failed to create subcontainer: %v", err)
	}
	if err := createAndWaitForContainer(t.Context(), client, sub, opts); err != nil {
		t.Fatalf("failed to create subcontainer: %v", err)
	}
	if err := startAndWaitForContainer(t.Context(), client, sub.ID(), containerd); err != nil {
		t.Fatalf("failed to start subcontainer: %v", err)
	}

	imagePath, err := os.MkdirTemp(containerd.WorkingDir(), "checkpoint-")
	if err != nil {
		t.Fatalf("failed to create checkpoint dir: %v", err)
	}
	checkpointReq := &pb.CheckpointRequest{
		Id:        sandbox.ID(),
		ImagePath: imagePath,
	}
	if err := containerd.GetTTRPCClient(t).Call(t.Context(), "gvisor.task.TaskService", "Checkpoint", checkpointReq, &pb.CheckpointResponse{}); err != nil {
		t.Fatalf("failed to checkpoint sandbox: %v", err)
	}

	restoredRootTmp, err := os.MkdirTemp("/tmp", "runsc-restore-root-")
	if err != nil {
		t.Fatalf("failed to create temp root for restore: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(restoredRootTmp)
	})
	restored := shimutils.NewMockContainerdWithSuffix(t, "restore", map[string]any{
		"root": restoredRootTmp,
	}, map[string]any{
		"ignore-cgroups": "true",
	})
	if err := restored.StartShim(t, sandbox); err != nil {
		t.Fatalf("failed to start shim for restore: %v", err)
	}
	restoredClient := restored.GetClient(t)
	restoredOpts, err := restored.GetRuntimeOptions()
	if err != nil {
		t.Fatalf("failed to get runtime options for restore: %v", err)
	}

	for _, container := range []*shimutils.Container{sandbox, sub} {
		createReq := &task.CreateTaskRequest{
			ID:         container.ID(),
			Bundle:     container.Bundle(),
			Options:    restoredOpts,
			Checkpoint: imagePath,
		}
		if _, err := restoredClient.Create(t.Context(), createReq); err != nil {
			t.Fatalf("failed to create %s from checkpoint: %v", container.ID(), err)
		}
	}

	if _, err := restoredClient.Start(t.Context(), &task.StartRequest{ID: sub.ID()}); err == nil {
		t.Errorf("restoring subcontainer %s before the root container succeeded, want an error", sub.ID())
	} else if want := "sandbox is not being restored"; !strings.Contains(err.Error(), want) {
		t.Errorf("restoring subcontainer %s before the root container: got error %v, want it to contain %q", sub.ID(), err, want)
	}

	// The create left a sandbox running, with nothing restored into it.
	if _, err := restoredClient.Kill(t.Context(), &task.KillRequest{ID: sandbox.ID(), Signal: 9, All: true}); err != nil {
		t.Logf("failed to kill sandbox %s: %v", sandbox.ID(), err)
	}
}

// runAsMappedRoot runs the container as the only user the spec maps into its
// user namespace, so that it can write files the test can read back.
func runAsMappedRoot(spec *specs.Spec) {
	spec.Process.User = specs.User{}
}

// nameContainer annotates a spec with the container name containerd would set,
// which is how runsc pairs a container with its state in the checkpoint image.
func nameContainer(spec *specs.Spec, name string) {
	spec.Annotations[specutils.ContainerdContainerNameAnnotation] = name
}

// markerPath returns the marker path for a container, visible at the same path
// inside the sandbox and out.
func markerPath(dir, name string) string {
	return filepath.Join(dir, "marker-"+name)
}

// markerArgs returns the process args for a container that appends to the
// marker file once and then sleeps. The marker tells a restore from a fresh
// start: a restored process comes back inside the sleep, so it never appends a
// second time.
func markerArgs(marker string) []string {
	return []string{"sh", "-c", fmt.Sprintf("echo started >>%q; exec sleep 10000", marker)}
}

// waitForMarker waits for a container to write its marker.
func waitForMarker(ctx context.Context, marker string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	for {
		if _, err := os.Stat(marker); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for marker %q", marker)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// checkMarker verifies that the marker file was written exactly once.
func checkMarker(marker string) error {
	b, err := os.ReadFile(marker)
	if err != nil {
		return err
	}
	if lines := strings.Count(string(b), "\n"); lines != 1 {
		return fmt.Errorf("marker %q was written %d times, want 1", marker, lines)
	}
	return nil
}
