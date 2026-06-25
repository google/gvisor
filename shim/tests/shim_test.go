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
	"strings"
	"testing"
	"time"

	eventtypes "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/runtime/task/v2"
	tasktype "github.com/containerd/containerd/api/types/task"
	typeurl "github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/anypb"
	"gvisor.dev/gvisor/shim/shimutils"
)

func TestMain(m *testing.M) {
	// Register the Process type with the typeurl package so that it can be used with the containerd
	// testing framework.
	typeurl.Register(&specs.Process{}, "types.containerd.io", "opencontainers/runtime-spec", "1", "Process")

	os.Exit(m.Run())
}

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

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to start and wait for container: %v", err)
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill and wait for container: %v", err)
			}

			// Verify events using the new Events() API.
			evts := containerd.Events()
			var started, exited bool
			for _, e := range evts {
				switch evt := e.(type) {
				case *eventtypes.TaskStart:
					if evt.ContainerID == sandbox.ID() {
						started = true
					}
				case *eventtypes.TaskExit:
					if evt.ContainerID == sandbox.ID() {
						exited = true
					}
				}
			}
			if !started {
				t.Errorf("expected TaskStart event for sandbox %s, but got none in: %v", sandbox.ID(), evts)
			}
			if !exited {
				t.Errorf("expected TaskExit event for sandbox %s, but got none in: %v", sandbox.ID(), evts)
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

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
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

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill and wait for sandbox: %v", err)
			}
		})
	}
}

func createAndWaitForContainer(ctx context.Context, client task.TaskService, container *shimutils.Container, opts *anypb.Any) error {
	errGroup := errgroup.Group{}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
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

func startAndWaitForContainer(ctx context.Context, client task.TaskService, containerID string, containerd *shimutils.MockContainerd) error {
	errGroup := errgroup.Group{}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	errGroup.Go(func() error {
		for {
			select {
			case evt := <-containerd.EventChan:
				if startEvt, ok := evt.(*eventtypes.TaskStart); ok && startEvt.ContainerID == containerID {
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("timed out waiting for TaskStart event for container %s", containerID)
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

func killAndWaitForContainer(ctx context.Context, client task.TaskService, containerID string, containerd *shimutils.MockContainerd) error {
	errGroup := errgroup.Group{}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	errGroup.Go(func() error {
		for {
			select {
			case evt := <-containerd.EventChan:
				if exitEvt, ok := evt.(*eventtypes.TaskExit); ok && exitEvt.ContainerID == containerID {
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("timed out waiting for TaskExit event for container %s", containerID)
			}
		}
	})

	errGroup.Go(func() error {
		killReq := &task.KillRequest{
			ID:     containerID,
			Signal: 9,
			All:    true,
		}
		_, err := client.Kill(ctx, killReq)
		if err != nil {
			if strings.Contains(err.Error(), "ttrpc: closed") {
				return nil
			}
			return fmt.Errorf("failed to kill task: %v", err)
		}
		return nil
	})

	return errGroup.Wait()
}

func TestPauseResumeSandbox(t *testing.T) {
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
				t.Fatalf("failed to create sandbox: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to start sandbox: %v", err)
			}

			pauseReq := &task.PauseRequest{
				ID: sandbox.ID(),
			}
			if _, err := client.Pause(t.Context(), pauseReq); err != nil {
				t.Fatalf("failed to pause sandbox: %v", err)
			}

			select {
			case evt := <-containerd.EventChan:
				pausedEvt, ok := evt.(*eventtypes.TaskPaused)
				if !ok || pausedEvt.ContainerID != sandbox.ID() {
					t.Fatalf("expected TaskPaused event for sandbox %s, got: %#v", sandbox.ID(), evt)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out waiting for TaskPaused event")
			}

			resumeReq := &task.ResumeRequest{
				ID: sandbox.ID(),
			}
			if _, err := client.Resume(t.Context(), resumeReq); err != nil {
				t.Fatalf("failed to resume sandbox: %v", err)
			}

			select {
			case evt := <-containerd.EventChan:
				resumedEvt, ok := evt.(*eventtypes.TaskResumed)
				if !ok || resumedEvt.ContainerID != sandbox.ID() {
					t.Fatalf("expected TaskResumed event for sandbox %s, got: %#v", sandbox.ID(), evt)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out waiting for TaskResumed event")
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}

func TestPidsSandbox(t *testing.T) {
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
				t.Fatalf("failed to create sandbox: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to start sandbox: %v", err)
			}

			pidsReq := &task.PidsRequest{
				ID: sandbox.ID(),
			}
			pidsResp, err := client.Pids(t.Context(), pidsReq)
			if err != nil {
				t.Fatalf("failed to get pids: %v", err)
			}

			if len(pidsResp.Processes) == 0 {
				t.Fatalf("expected at least one pid, got 0")
			}

			t.Logf("Pids in sandbox: %+v", pidsResp.Processes)

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}

func TestDeleteContainer(t *testing.T) {
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
				t.Fatalf("failed to create sandbox: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to start sandbox: %v", err)
			}

			containerSpec := shimutils.NewContainerSpec(sandbox.ID(), []string{"sleep", "10000"})
			container, err := shimutils.NewContainer(containerSpec, containerd)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, container.ID(), containerd); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}

			if err := killAndWaitForContainer(t.Context(), client, container.ID(), containerd); err != nil {
				t.Fatalf("failed to kill container: %v", err)
			}

			deleteReq := &task.DeleteRequest{
				ID: container.ID(),
			}
			deleteResp, err := client.Delete(t.Context(), deleteReq)
			if err != nil {
				if !strings.Contains(err.Error(), "operation not permitted") {
					t.Fatalf("failed to delete task: %v", err)
				}
				t.Logf("Ignoring expected delete error in rootless environment: %v", err)
			} else {
				if deleteResp.ExitedAt.AsTime().IsZero() {
					t.Fatalf("expected non-zero ExitedAt in DeleteResponse")
				}
				statusReq := &task.StateRequest{
					ID: container.ID(),
				}
				_, err = client.State(t.Context(), statusReq)
				if err == nil {
					t.Fatalf("expected error getting state of deleted task, got nil")
				}
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}

func TestExecContainer(t *testing.T) {
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
				t.Fatalf("failed to create sandbox: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to start sandbox: %v", err)
			}

			containerSpec := shimutils.NewContainerSpec(sandbox.ID(), []string{"sleep", "10000"})
			container, err := shimutils.NewContainer(containerSpec, containerd)
			if err != nil {
				t.Fatalf("failed to create containerSpec: %v", err)
			}

			if err := createAndWaitForContainer(t.Context(), client, container, opts); err != nil {
				t.Fatalf("failed to create container: %v", err)
			}

			if err := startAndWaitForContainer(t.Context(), client, container.ID(), containerd); err != nil {
				t.Fatalf("failed to start container: %v", err)
			}

			procSpec := &specs.Process{
				Args: []string{"true"},
				Env: []string{
					"PATH=" + os.Getenv("PATH"),
				},
				Cwd: "/",
			}
			procAny, err := typeurl.MarshalAny(procSpec)
			if err != nil {
				t.Fatalf("failed to marshal process spec: %v", err)
			}
			procAnyProto, err := typeurl.MarshalAnyToProto(procAny)
			if err != nil {
				t.Fatalf("failed to marshal to proto: %v", err)
			}

			execID := "exec-1"
			execReq := &task.ExecProcessRequest{
				ID:     container.ID(),
				ExecID: execID,
				Spec:   procAnyProto,
			}

			if _, err := client.Exec(t.Context(), execReq); err != nil {
				t.Fatalf("failed to exec process: %v", err)
			}

			startReq := &task.StartRequest{
				ID:     container.ID(),
				ExecID: execID,
			}
			if _, err := client.Start(t.Context(), startReq); err != nil {
				t.Fatalf("failed to start exec process: %v", err)
			}

			waitReq := &task.WaitRequest{
				ID:     container.ID(),
				ExecID: execID,
			}
			waitResp, err := client.Wait(t.Context(), waitReq)
			if err != nil {
				t.Fatalf("failed to wait for exec process: %v", err)
			}

			if waitResp.ExitStatus != 0 {
				t.Fatalf("expected exit status 0, got %d", waitResp.ExitStatus)
			}

			if err := killAndWaitForContainer(t.Context(), client, sandbox.ID(), containerd); err != nil {
				t.Fatalf("failed to kill sandbox: %v", err)
			}
		})
	}
}
