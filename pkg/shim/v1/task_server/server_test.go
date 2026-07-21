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

// Package taskserver contains tests for the task_server package.
package taskserver

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	ttrpc "github.com/containerd/ttrpc"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"gvisor.dev/gvisor/pkg/cleanup"
	pb "gvisor.dev/gvisor/pkg/shim/v1/task_server/task_server_go_proto"
)

const (
	badRequest  = "bad"
	goodRequest = "good"

	versionString = "google-20260528"
)

type mockServer struct {
	GvisorTaskServiceExt
}

func (m *mockServer) Checkpoint(ctx context.Context, req *pb.CheckpointRequest) (*pb.CheckpointResponse, error) {
	if req.GetId() == badRequest {
		return nil, errors.New("checkpoint failed")
	}
	return &pb.CheckpointResponse{}, nil
}

func (m *mockServer) Wait(ctx context.Context, req *pb.WaitRequest) (*pb.WaitResponse, error) {
	if req.GetId() == badRequest {
		return nil, errors.New("wait failed")
	}
	exitStatus := int32(0)
	if req.GetWaitType() == pb.WaitRequest_CHECKPOINT {
		exitStatus = 42
	}
	return &pb.WaitResponse{ExitStatus: exitStatus}, nil
}

func (m *mockServer) State(ctx context.Context, req *pb.StateRequest) (*pb.StateResponse, error) {
	if req.GetId() == badRequest {
		return nil, errors.New("state failed")
	}
	return &pb.StateResponse{
		Id:    req.GetId(),
		State: "running",
		Pid:   1234,
	}, nil
}

func (m *mockServer) Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{Version: versionString}, nil
}

type serverTest struct {
	name        string
	data        string
	want        any
	wantErrDesc string
	check       func(t *testing.T, client *ttrpc.Client, data string) (any, error)
}

func testCheckpoint(t *testing.T, client *ttrpc.Client, data string) (any, error) {
	req := &pb.CheckpointRequest{
		Id: data,
	}
	resp := &pb.CheckpointResponse{}
	if err := client.Call(t.Context(), "gvisor.task.TaskService", "Checkpoint", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func testWait(t *testing.T, client *ttrpc.Client, data string) (any, error) {
	req := &pb.WaitRequest{
		Id:       data,
		WaitType: pb.WaitRequest_CHECKPOINT,
	}
	resp := &pb.WaitResponse{}
	if err := client.Call(t.Context(), "gvisor.task.TaskService", "Wait", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func testState(t *testing.T, client *ttrpc.Client, data string) (any, error) {
	req := &pb.StateRequest{
		Id: data,
	}
	resp := &pb.StateResponse{}
	if err := client.Call(t.Context(), "gvisor.task.TaskService", "State", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func testVersion(t *testing.T, client *ttrpc.Client, data string) (any, error) {
	req := &pb.VersionRequest{}
	resp := &pb.VersionResponse{}
	if err := client.Call(t.Context(), "gvisor.task.TaskService", "Version", req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func TestServer(t *testing.T) {
	for _, tc := range []serverTest{
		{
			name:  "checkpoint success",
			data:  goodRequest,
			want:  &pb.CheckpointResponse{},
			check: testCheckpoint,
		},
		{
			name:        "checkpoint failure",
			data:        badRequest,
			wantErrDesc: "checkpoint failed",
			check:       testCheckpoint,
		},
		{
			name:  "wait success",
			data:  goodRequest,
			want:  &pb.WaitResponse{ExitStatus: 42},
			check: testWait,
		},
		{
			name:        "wait failure",
			data:        badRequest,
			wantErrDesc: "wait failed",
			check:       testWait,
		},
		{
			name: "state success",
			data: goodRequest,
			want: &pb.StateResponse{
				Id:    goodRequest,
				State: "running",
				Pid:   1234,
			},
			check: testState,
		},
		{
			name:        "state failure",
			data:        badRequest,
			wantErrDesc: "state failed",
			check:       testState,
		},
		{
			name:  "version",
			data:  goodRequest,
			want:  &pb.VersionResponse{Version: versionString},
			check: testVersion,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := t.TempDir()
			const containerID = "some-id"
			server, err := NewServer(rootDir, containerID)
			if err != nil {
				t.Fatal(err)
			}

			go server.Serve(t.Context())
			cu := cleanup.Make(func() {
				server.Shutdown(t.Context())
			})
			defer cu.Clean()

			server.RegisterService(&mockServer{})

			conn, err := net.Dial("unix", server.Address())
			if err != nil {
				t.Fatalf("failed to connect to server: %v", err)
			}

			client := ttrpc.NewClient(conn)
			defer client.Close()

			got, err := tc.check(t, client, tc.data)
			t.Logf("got: %v, err: %v", got, err)
			switch {
			case tc.wantErrDesc != "":
				if err == nil {
					t.Errorf("Did not receive expected error with description: %q", tc.wantErrDesc)
				} else if !strings.Contains(err.Error(), tc.wantErrDesc) {
					t.Errorf("Unexpected error: got %v, want error containing %v", err, tc.wantErrDesc)
				}
			default:
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
					t.Errorf("Mismatch message: %s", diff)
				}
			}

			if err := server.Shutdown(t.Context()); err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			cu.Release()

			_, err = os.Stat(server.Address())
			if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Socket file %q still exists", server.Address())
			}
		})
	}
}
