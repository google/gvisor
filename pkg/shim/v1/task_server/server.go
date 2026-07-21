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

// Package taskserver implements a direct interface to the gvisor shim for task operations.
package taskserver

import (
	"context"
	"fmt"
	"net"
	"os"

	ttrpc "github.com/containerd/ttrpc"
	pb "gvisor.dev/gvisor/pkg/shim/v1/task_server/task_server_go_proto"
)

// GvisorTaskServiceExt is an interface for the gvisor task service.
type GvisorTaskServiceExt interface {
	Checkpoint(ctx context.Context, req *pb.CheckpointRequest) (*pb.CheckpointResponse, error)
	Wait(ctx context.Context, req *pb.WaitRequest) (*pb.WaitResponse, error)
	State(ctx context.Context, req *pb.StateRequest) (*pb.StateResponse, error)
	Version(ctx context.Context, req *pb.VersionRequest) (*pb.VersionResponse, error)
}

// GvisorTaskServiceEndpoint is a ttrpc server for third party callers to communicate with the gvisor shim.
// Instead of going through containerd, this server provides a direct interface to task operations
// with running sandboxes.
type GvisorTaskServiceEndpoint struct {
	server  *ttrpc.Server
	address string
	l       net.Listener
}

// NewServer creates a new GvisorTaskServer.
func NewServer(rootDir, id string) (*GvisorTaskServiceEndpoint, error) {
	addr := addrFromID(rootDir, id)
	// If the socket already exists, remove it. This can happen if a previous instance of the server
	// crashed before it was properly shut down.
	if _, err := os.Stat(addr); err == nil {
		os.Remove(addr)
	}

	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}

	server, err := ttrpc.NewServer()
	if err != nil {
		return nil, err
	}
	return &GvisorTaskServiceEndpoint{
		server:  server,
		address: addr,
		l:       l,
	}, nil
}

// Address returns the address of the shim socket.
func (s *GvisorTaskServiceEndpoint) Address() string {
	return s.address
}

// Serve serves the ttrpc server on the given address.
func (s *GvisorTaskServiceEndpoint) Serve(ctx context.Context) error {
	// Note: the TTRPC server takes ownership of the listener and will close it when the server is
	// shut down.
	return s.server.Serve(ctx, s.l)
}

// Shutdown shuts down the ttrpc server.
func (s *GvisorTaskServiceEndpoint) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// RegisterService registers the given services with the ttrpc server.
func (s *GvisorTaskServiceEndpoint) RegisterService(srvc GvisorTaskServiceExt) {
	// Register the custom gVisor TaskService methods
	s.server.RegisterService("gvisor.task.TaskService", &ttrpc.ServiceDesc{
		Methods: map[string]ttrpc.Method{
			"Checkpoint": func(ctx context.Context, unmarshal func(any) error) (any, error) {
				req := &pb.CheckpointRequest{}
				if err := unmarshal(req); err != nil {
					return nil, err
				}
				return srvc.Checkpoint(ctx, req)
			},
			"Wait": func(ctx context.Context, unmarshal func(any) error) (any, error) {
				req := &pb.WaitRequest{}
				if err := unmarshal(req); err != nil {
					return nil, err
				}
				return srvc.Wait(ctx, req)
			},
			"State": func(ctx context.Context, unmarshal func(any) error) (any, error) {
				req := &pb.StateRequest{}
				if err := unmarshal(req); err != nil {
					return nil, err
				}
				return srvc.State(ctx, req)
			},
			"Version": func(ctx context.Context, unmarshal func(any) error) (any, error) {
				req := &pb.VersionRequest{}
				if err := unmarshal(req); err != nil {
					return nil, err
				}
				return srvc.Version(ctx, req)
			},
		},
	})
}

// addrFromID returns the address of the shim socket for the given ID.
func addrFromID(rootDir, id string) string {
	return fmt.Sprintf("%s/%s_sandbox.sock", rootDir, id)
}
