// Copyright 2026 The containerd Authors.
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

// Package shim_test is a test package for the shim. It is intended to be used in conjunction with
// the containerd testing framework.
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
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/shim/shimutils"
)

type testCase struct {
	name      string
	shimArgs  map[string]any
	runscArgs map[string]any
}

func TestCreateKillWaitSandbox(t *testing.T) {
	for _, tc := range []testCase{
		{
			name: "default",
		},
		{
			name: "grouping",
			shimArgs: map[string]any{
				"grouping": true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containerd := shimutils.NewMockContainerd(t, tc.shimArgs, nil)
			spec := shimutils.NewSandboxSpec()

			sandbox, err := shimutils.NewContainer(spec, containerd)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}
			if err := containerd.StartShim(t, sandbox); err != nil {
				t.Fatalf("failed to start shim: %v", err)
			}

			client := containerd.GetClient(t)

			opts, err := containerd.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, sandbox, opts); err != nil {
				t.Fatalf("failed to create and wait for container: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), sandbox); err != nil {
				t.Fatalf("failed to start and wait for container: %v", err)
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID()); err != nil {
				t.Fatalf("failed to kill and wait for container: %v", err)
			}
		})
	}
}

func TestCreateSandboxWithContainer(t *testing.T) {
	for _, tc := range []testCase{
		{
			name: "default",
		},
		{
			name: "grouping",
			shimArgs: map[string]any{
				"grouping": true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containerd := shimutils.NewMockContainerd(t, tc.shimArgs, nil)
			sandboxSpec := shimutils.NewSandboxSpec()

			sandbox, err := shimutils.NewContainer(sandboxSpec, containerd)
			if err != nil {
				t.Fatalf("failed to create sandbox: %v", err)
			}

			if err := containerd.StartShim(t, sandbox); err != nil {
				t.Fatalf("failed to start shim: %v", err)
			}

			client := containerd.GetClient(t)

			opts, err := containerd.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, sandbox, opts); err != nil {
				t.Fatalf("failed to create and wait for sandbox: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), sandbox); err != nil {
				t.Fatalf("failed to start and wait for sandbox: %v", err)
			}

			containerSpec := shimutils.NewContainerSpec(sandbox.ID(), []string{"sleep", "10000"})
			container, err := shimutils.NewContainer(containerSpec, containerd)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
				t.Fatalf("failed to create and wait for container: %v", err)
			}

			startReq := &task.StartRequest{
				ID: container.ID(),
			}
			if _, err := client.Start(t.Context(), startReq); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}

			statusReq := &task.StateRequest{
				ID: container.ID(),
			}
			statusResp, err := client.State(t.Context(), statusReq)
			if err != nil {
				t.Fatalf("failed to get state: %v", err)
			}
			if statusResp.Status != tasktype.Status_RUNNING {
				t.Fatalf("got status %v want %v", statusResp.Status, tasktype.Status_RUNNING)
			}

			t.Logf("Container ID: %s", container.ID())

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID()); err != nil {
				t.Fatalf("failed to kill and wait for sandbox: %v", err)
			}
		})
	}
}

func TestCheckpointRestoreSandboxWithContainer(t *testing.T) {
	containerd := shimutils.NewMockContainerd(t, nil, nil)
	sandboxSpec := shimutils.NewSandboxSpec()
	containerSpec := shimutils.NewContainerSpec("", []string{"sleep", "10000"})

	sandbox, err := shimutils.NewContainer(sandboxSpec, containerd)
	if err != nil {
		t.Fatalf("failed to create sandbox: %v", err)
	}
	containerSpec.Annotations[specutils.ContainerdSandboxIDAnnotation] = sandbox.ID()
	container, err := shimutils.NewContainer(containerSpec, containerd)
	if err != nil {
		t.Fatalf("failed to create container: %v", err)
	}

	if err := containerd.StartShim(t, sandbox); err != nil {
		t.Fatalf("failed to start shim: %v", err)
	}
	client := containerd.GetClient(t)
	opts, err := containerd.GetRuntimeOptions()
	if err != nil {
		t.Fatalf("failed to get runtime options: %v", err)
	}

	if err := createAndWaitForContainer(t.Context(), client, sandbox, opts); err != nil {
		t.Fatalf("failed to create and wait for sandbox: %v", err)
	}
	if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), sandbox); err != nil {
		t.Fatalf("failed to start and wait for sandbox: %v", err)
	}
	if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
		t.Fatalf("failed to create and wait for container: %v", err)
	}
	if err := startAndWaitForContainer(t.Context(), client, container.ID(), container); err != nil {
		t.Fatalf("failed to start and wait for container: %v", err)
	}

	checkpointDir := filepath.Join(containerd.WorkingDir(), "checkpoint")
	if err := os.MkdirAll(checkpointDir, 0o777); err != nil {
		t.Fatalf("failed to create checkpoint dir: %v", err)
	}
	if _, err := client.Checkpoint(t.Context(), &task.CheckpointTaskRequest{
		ID:   sandbox.ID(),
		Path: checkpointDir,
	}); err != nil {
		t.Fatalf("failed to checkpoint sandbox: %v", err)
	}
	if _, err := os.Stat(filepath.Join(checkpointDir, "checkpoint.img")); err != nil {
		t.Fatalf("checkpoint did not create checkpoint.img: %v", err)
	}

	restoreContainerd := shimutils.NewMockContainerd(t, nil, nil)
	restoreSandboxSpec := cloneSpecWithCheckpoint(sandboxSpec, checkpointDir, "")
	restoreSandbox, err := shimutils.NewContainer(restoreSandboxSpec, restoreContainerd)
	if err != nil {
		t.Fatalf("failed to create restore sandbox: %v", err)
	}
	restoreContainerSpec := cloneSpecWithCheckpoint(containerSpec, checkpointDir, restoreSandbox.ID())
	restoreContainer, err := shimutils.NewContainer(restoreContainerSpec, restoreContainerd)
	if err != nil {
		t.Fatalf("failed to create restore container: %v", err)
	}

	if err := restoreContainerd.StartShim(t, restoreSandbox); err != nil {
		t.Fatalf("failed to start restore shim: %v", err)
	}
	restoreClient := restoreContainerd.GetClient(t)
	restoreOpts, err := restoreContainerd.GetRuntimeOptions()
	if err != nil {
		t.Fatalf("failed to get restore runtime options: %v", err)
	}

	if err := createAndWaitForContainer(t.Context(), restoreClient, restoreSandbox, restoreOpts); err != nil {
		t.Fatalf("failed to create and wait for restore sandbox: %v", err)
	}
	if err := startAndWaitForContainer(t.Context(), restoreClient, restoreSandbox.ID(), restoreSandbox); err != nil {
		t.Fatalf("failed to restore sandbox: %v", err)
	}
	if err := createAndWaitForContainer(t.Context(), restoreClient, restoreContainer, restoreOpts); err != nil {
		t.Fatalf("failed to create and wait for restore container: %v", err)
	}
	if err := startAndWaitForContainer(t.Context(), restoreClient, restoreContainer.ID(), restoreContainer); err != nil {
		t.Fatalf("failed to restore container: %v", err)
	}

	for _, id := range []string{restoreSandbox.ID(), restoreContainer.ID()} {
		statusResp, err := restoreClient.State(t.Context(), &task.StateRequest{ID: id})
		if err != nil {
			t.Fatalf("failed to get restored state for %q: %v", id, err)
		}
		if statusResp.Status != tasktype.Status_RUNNING {
			t.Fatalf("restored container %q status = %v, want %v", id, statusResp.Status, tasktype.Status_RUNNING)
		}
	}

	if err := killAndWaitForContainer(t.Context(), client, sandbox.ID()); err != nil {
		t.Fatalf("failed to kill checkpoint source sandbox: %v", err)
	}
	if err := killAndWaitForContainer(t.Context(), restoreClient, restoreSandbox.ID()); err != nil {
		t.Fatalf("failed to kill restored sandbox: %v", err)
	}
}

func cloneSpecWithCheckpoint(spec *specs.Spec, checkpointDir, sandboxID string) *specs.Spec {
	clone := *spec
	clone.Annotations = map[string]string{}
	for k, v := range spec.Annotations {
		clone.Annotations[k] = v
	}
	clone.Annotations["dev.gvisor.checkpoint.host-image-path"] = checkpointDir
	if sandboxID != "" {
		clone.Annotations[specutils.ContainerdSandboxIDAnnotation] = sandboxID
	}
	return &clone
}

func createAndWaitForContainer(ctx context.Context, client task.TaskService, container *shimutils.Container, opts *anypb.Any) error {
	errGroup := errgroup.Group{}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var createResp *task.CreateTaskResponse
	errGroup.Go(func() error {
		createReq := &task.CreateTaskRequest{
			ID:      container.ID(),
			Bundle:  container.Bundle(),
			Options: opts,
		}
		var err error
		createResp, err = client.Create(ctx, createReq)
		if err != nil {
			return fmt.Errorf("failed to create task: %v", err)
		}
		if createResp.Pid == 0 {
			return fmt.Errorf("created task PID is 0")
		}
		return nil
	})

	errGroup.Go(func() error {

		for {
			time.Sleep(100 * time.Millisecond)
			statusReq := &task.StateRequest{
				ID: container.ID(),
			}
			statusResp, err := client.State(ctx, statusReq)

			if err != nil && strings.Contains(err.Error(), "not found") {
				continue
			}

			if err != nil {
				return fmt.Errorf("failed to get state: %v", err)
			}
			if statusResp.Status == tasktype.Status_CREATED {
				return nil
			}
		}
	})

	return errGroup.Wait()
}

func startAndWaitForContainer(ctx context.Context, client task.TaskService, containerID string, container *shimutils.Container) error {
	errGroup := errgroup.Group{}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	errGroup.Go(func() error {
		stateReq := &task.StateRequest{
			ID: containerID,
		}
		for {
			time.Sleep(100 * time.Millisecond)
			stateResp, err := client.State(ctx, stateReq)
			if err != nil {
				return fmt.Errorf("failed to get state: %v", err)
			}
			if stateResp.Status == tasktype.Status_RUNNING {
				return nil
			}
		}
	})

	errGroup.Go(func() error {
		startReq := &task.StartRequest{
			ID: containerID,
		}

		_, err := client.Start(ctx, startReq)
		if err != nil {
			return fmt.Errorf("failed to start task: %v", err)
		}
		return nil
	})

	return errGroup.Wait()
}

func killAndWaitForContainer(ctx context.Context, client task.TaskService, containerID string) error {
	errGroup := errgroup.Group{}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	errGroup.Go(func() error {
		waitReq := &task.WaitRequest{
			ID: containerID,
		}
		_, err := client.Wait(ctx, waitReq)
		if err != nil {
			if strings.Contains(err.Error(), "ttrpc: closed") {
				return nil
			}
			return fmt.Errorf("failed to wait for task: %v", err)
		}
		return nil
	})

	errGroup.Go(func() error {
		killReq := &task.KillRequest{
			ID:     containerID,
			Signal: 9,
			All:    true,
		}
		_, err := client.Kill(ctx, killReq)
		if err != nil {
			return fmt.Errorf("failed to kill task: %v", err)
		}
		return nil
	})

	return errGroup.Wait()
}
