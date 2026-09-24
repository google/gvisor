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
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"github.com/containerd/ttrpc"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	pb "gvisor.dev/gvisor/pkg/shim/v1/taskserver/task_server_go_proto"
	"gvisor.dev/gvisor/shim/shimutils"
)

func getGvisorTaskClient(t *testing.T, socketPath string) *ttrpc.Client {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("unix", socketPath, 1*time.Second)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("failed to dial custom socket %s: %v", socketPath, err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	return ttrpc.NewClient(conn)
}

func TestGvisorTaskService(t *testing.T) {
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
			rootTmp, err := os.MkdirTemp("/tmp", "runsc-root-")
			if err != nil {
				t.Fatalf("failed to create temp root: %v", err)
			}
			t.Cleanup(func() {
				os.RemoveAll(rootTmp)
			})

			shimArgs := map[string]any{
				"enable_hibernate_server": true,
				"root":                    rootTmp,
			}
			for k, v := range tc.shimArgs {
				shimArgs[k] = v
			}

			runscArgs := map[string]any{
				"overlay2":       "all:self",
				"ignore-cgroups": "true",
			}
			for k, v := range tc.runscArgs {
				runscArgs[k] = v
			}

			containerd := shimutils.NewMockContainerd(t, shimArgs, runscArgs)

			spec := shimutils.NewSandboxSpec()
			spec.Mounts = append(spec.Mounts, specs.Mount{
				Destination: "/tmp",
				Type:        "tmpfs",
				Source:      "tmpfs",
			})
			sandbox, _ := setupSandboxWithSpec(t, containerd, spec)

			socketPath := filepath.Join(rootTmp, sandbox.ID()+"_sandbox.sock")
			client := getGvisorTaskClient(t, socketPath)
			id := sandbox.ID()

			// 1. Test Version
			t.Run("Version", func(t *testing.T) {
				req := &pb.VersionRequest{}
				resp := &pb.VersionResponse{}
				if err := client.Call(t.Context(), "gvisor.task.TaskService", "Version", req, resp); err != nil {
					t.Fatalf("Version failed: %v", err)
				}
				if resp.GetVersion() == "" {
					t.Errorf("expected non-empty version")
				}
				t.Logf("gVisor version: %s", resp.GetVersion())
			})

			// 2. Test State
			t.Run("State", func(t *testing.T) {
				req := &pb.StateRequest{
					Id: id,
				}
				resp := &pb.StateResponse{}
				if err := client.Call(t.Context(), "gvisor.task.TaskService", "State", req, resp); err != nil {
					t.Fatalf("State failed: %v", err)
				}
				if resp.GetId() != id {
					t.Errorf("expected ID %s, got %s", id, resp.GetId())
				}
				if resp.GetState() != "running" {
					t.Errorf("expected state running, got %s", resp.GetState())
				}
			})

			t.Run("StateWithDebugLog", func(t *testing.T) {
				logDir := t.TempDir() + "/"

				req := &pb.StateRequest{
					Id: id,
					Debug: &pb.Debug{
						DebugLog: logDir,
					},
				}
				resp := &pb.StateResponse{}
				if err := client.Call(t.Context(), "gvisor.task.TaskService", "State", req, resp); err != nil {
					t.Fatalf("State failed: %v", err)
				}

				// Verify that a log file was created in logDir and contains debug logs.
				files, err := os.ReadDir(logDir)
				if err != nil {
					t.Fatalf("failed to read log dir: %v", err)
				}
				if len(files) == 0 {
					t.Fatalf("expected log files in %s, but got none", logDir)
				}
				t.Logf("Found %d log files", len(files))
				for _, f := range files {
					t.Logf("Log file: %s", f.Name())
					logPath := filepath.Join(logDir, f.Name())
					content, err := os.ReadFile(logPath)
					if err != nil {
						t.Errorf("failed to read log file %s: %v", logPath, err)
					} else if len(content) == 0 {
						t.Errorf("expected non-empty log file in %s, but was empty", logPath)
					} else {
						t.Logf("Log file content size: %d bytes", len(content))
					}
				}

				// Verify that a subsequent request without debug options does NOT write to logDir.
				initialFileCount := len(files)
				reqNoDebug := &pb.StateRequest{Id: id}
				respNoDebug := &pb.StateResponse{}
				if err := client.Call(t.Context(), "gvisor.task.TaskService", "State", reqNoDebug, respNoDebug); err != nil {
					t.Fatalf("State without debug failed: %v", err)
				}
				filesAfter, err := os.ReadDir(logDir)
				if err != nil {
					t.Fatalf("failed to read log dir after: %v", err)
				}
				if len(filesAfter) > initialFileCount {
					t.Errorf("expected no new log files after request without debug, but got %d (was %d)", len(filesAfter), initialFileCount)
				}
			})

			// 3. Test Checkpoint
			t.Run("Checkpoint", func(t *testing.T) {
				imgDir, err := os.MkdirTemp(containerd.WorkingDir(), "checkpoint-")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				leaveRunning := true
				req := &pb.CheckpointRequest{
					Id:           id,
					ImagePath:    imgDir,
					LeaveRunning: leaveRunning,
				}
				resp := &pb.CheckpointResponse{}
				err = client.Call(t.Context(), "gvisor.task.TaskService", "Checkpoint", req, resp)
				if err != nil {
					t.Fatalf("Checkpoint failed: %v", err)
				}
			})

			// 3b. Test FSCheckpoint
			t.Run("FSCheckpoint", func(t *testing.T) {
				imgDir, err := os.MkdirTemp(containerd.WorkingDir(), "fscheckpoint-")
				if err != nil {
					t.Fatalf("failed to create temp dir: %v", err)
				}
				leaveRunning := true
				fsCheckpoint := true
				req := &pb.CheckpointRequest{
					Id:           id,
					ImagePath:    imgDir,
					LeaveRunning: leaveRunning,
					FsCheckpoint: fsCheckpoint,
					FsPath:       "all-tmpfs",
				}
				resp := &pb.CheckpointResponse{}
				err = client.Call(t.Context(), "gvisor.task.TaskService", "Checkpoint", req, resp)
				if err != nil {
					t.Fatalf("FSCheckpoint failed: %v", err)
				}
			})

			// 4. Test Wait
			for _, wt := range []struct {
				name          string
				val           pb.WaitRequest_WaitType
				expectTimeout bool
				expectErr     string
			}{
				{"WaitCheckpoint", pb.WaitRequest_CHECKPOINT, true, ""},
				{"WaitRestore", pb.WaitRequest_RESTORE, false, "cannot wait for restore"},
				{"WaitFSCheckpoint", pb.WaitRequest_FSCHECKPOINT, true, ""},
				{"WaitFSRestore", pb.WaitRequest_FSRESTORE, false, "filesystem restore is not enabled"},
			} {
				t.Run(wt.name+"Timeout", func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)
					defer cancel()
					req := &pb.WaitRequest{
						Id:       id,
						WaitType: wt.val,
					}
					resp := &pb.WaitResponse{}
					err := client.Call(ctx, "gvisor.task.TaskService", "Wait", req, resp)
					if wt.expectTimeout {
						if err != nil {
							if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "did not terminate successfully") {
								t.Fatalf("expected deadline exceeded, got: %v", err)
							}
						} else {
							t.Fatalf("expected timeout, but Wait succeeded?")
						}
					} else {
						if err == nil {
							t.Fatalf("expected error, but Wait succeeded?")
						}
						if !strings.Contains(err.Error(), wt.expectErr) {
							t.Fatalf("expected error containing %q, got: %v", wt.expectErr, err)
						}
					}
				})
			}
		})
	}
}

func setupSandboxWithSpec(t *testing.T, containerd *shimutils.MockContainerd, spec *specs.Spec) (*shimutils.Container, task.TaskService) {
	t.Helper()
	sandbox, err := shimutils.NewContainer(spec, containerd)
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

	return sandbox, client
}
