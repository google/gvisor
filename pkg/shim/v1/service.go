// Copyright 2018 The gVisor Authors.
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

// Package v1 implements Containerd Shim v2 interface.
package v1

import (
	"context"
	"os"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	types "github.com/containerd/containerd/v2/pkg/protobuf/types"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/containerd/containerd/v2/pkg/shutdown"
	errgrpc "github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/log"
	"github.com/containerd/ttrpc"

	api "github.com/containerd/containerd/api/runtime/sandbox/v1"
	"github.com/containerd/errdefs"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	rsc "gvisor.dev/gvisor/pkg/shim/v1/runsc"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// shimAddressPath is the relative path to a file that contains the address
	// to the shim UDS. See service.shimAddress.
	shimAddressPath = "address"
)

// NewShimRedirector creates a new shim service that integrates with runsc.
func NewShimRedirector(ctx context.Context, publisher shim.Publisher, sd shutdown.Service) (extension.TaskServiceExt, error) {
	runsc, err := rsc.NewTaskService(ctx, publisher, sd)
	if err != nil {
		sd.Shutdown()
		return nil, err
	}

	runtimeOptions := rsc.GetRuntimeOptions()

	s := &shimRedirector{
		shutdown:       sd,
		main:           runsc,
		runtimeOptions: runtimeOptions,
	}
	if address, _ := shim.ReadAddress(shimAddressPath); len(address) > 0 {
		sd.RegisterCallback(func(context.Context) error {
			shim.RemoveSocket(address)
			return nil
		})
	}

	s.grouping = runtimeOptions.Grouping
	return s, nil
}

// shimRedirector is the implementation of task service extension over gRPC/ttrpc. It
// is a intermediate layer between the containerd API and the runsc task service.
//
// It intercepts some calls to the task service and forwards all calls
// to extension.TaskServiceExt which actually implements the service interface.
type shimRedirector struct {
	mu sync.Mutex

	// shimAddress is the location of the UDS used to communicate to containerd.
	shimAddress string

	// main is the extension.TaskServiceExt that is used for all calls to the
	// container's shim, except for the cases where `ext` is set.
	//
	// Protected by mu.
	main extension.TaskServiceExt

	// ext may intercept calls to the container's shim. During the call to create
	// container, the extension may be created and the shim will start using it
	// for all calls to the container's shim.
	//
	// Protected by mu.
	ext extension.TaskServiceExt

	// grouping indicates if shim grouping is enabled.
	grouping bool

	shutdown       shutdown.Service
	runtimeOptions *rsc.Options
}

var _ extension.TaskServiceExt = (*shimRedirector)(nil)

// Preconditions:
//   - s.mu must be locked
func (s *shimRedirector) getLocked() extension.TaskServiceExt {
	if s.ext == nil {
		return s.main
	}
	return s.ext
}

// get return the extension.TaskServiceExt that should be used for the next
// call to the container's shim.
func (s *shimRedirector) get() extension.TaskServiceExt {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.getLocked()
}

const kubernetesGroupAnnotation = "io.kubernetes.cri.sandbox-id"

type spec struct {
	// Annotations contains arbitrary metadata for the container.
	Annotations map[string]string `json:"annotations,omitempty"`
}

// isDaemon ensures we only create sockets and run Serve() in the main background process,
// ignoring short-lived containerd helpers like delete or state.
func isDaemon() bool {
	for _, arg := range os.Args {
		if arg == "delete" || arg == "state" || arg == "info" || arg == "stats" {
			return false
		}
	}
	return true
}

// initExt initializes the extension that may intercept calls to the container's shim.
func (s *shimRedirector) initExt(ctx context.Context, r *task.CreateTaskRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.grouping {
		// Create shim extension if required.
		if s.ext == nil && extension.NewPodExtension != nil {
			log.L.Debugf("Create shim extension per pod")
			var err error
			s.ext, err = extension.NewPodExtension(ctx, s.main, r)
			if err != nil {
				log.L.Debugf("Creating shim extension per pod failed with error: %v", err)
				return err
			}
		}
	} else {
		if extension.NewExtension != nil {
			log.L.Debugf("Create shim extension per container")
			var err error
			s.ext, err = extension.NewExtension(ctx, s.main, r)
			if err != nil {

				return err
			}
		}
	}
	return nil
}

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *shimRedirector) Create(ctx context.Context, r *task.CreateTaskRequest) (*task.CreateTaskResponse, error) {
	log.L.Debugf("Create, id: %s, bundle: %q", r.ID, r.Bundle)
	if err := s.initExt(ctx, r); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := s.get().Create(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// CreateWithFSRestore creates a container which restores its filesystem from a snapshot.
func (s *shimRedirector) CreateWithFSRestore(ctx context.Context, r *extension.CreateWithFSRestoreRequest) (*task.CreateTaskResponse, error) {
	log.L.Debugf("CreateWithFSRestore, id: %s, bundle: %q", r.Create.ID, r.Create.Bundle)
	if err := s.initExt(ctx, r.Create); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := s.get().CreateWithFSRestore(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Start starts the container.
func (s *shimRedirector) Start(ctx context.Context, r *task.StartRequest) (*task.StartResponse, error) {
	log.L.Debugf("Start, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Start(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Delete deletes container.
func (s *shimRedirector) Delete(ctx context.Context, r *task.DeleteRequest) (*task.DeleteResponse, error) {
	log.L.Debugf("Delete, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Delete(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Exec spawns a process inside the container.
func (s *shimRedirector) Exec(ctx context.Context, r *task.ExecProcessRequest) (*types.Empty, error) {
	log.L.Debugf("Exec, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Exec(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// ResizePty resizes the terminal of a process.
func (s *shimRedirector) ResizePty(ctx context.Context, r *task.ResizePtyRequest) (*types.Empty, error) {
	log.L.Debugf("ResizePty, id: %s, execID: %s, dimension: %dx%d", r.ID, r.ExecID, r.Height, r.Width)
	resp, err := s.get().ResizePty(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// State returns runtime state information for the container.
func (s *shimRedirector) State(ctx context.Context, r *task.StateRequest) (*task.StateResponse, error) {
	log.L.Debugf("State, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().State(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Pause the container.
func (s *shimRedirector) Pause(ctx context.Context, r *task.PauseRequest) (*types.Empty, error) {
	log.L.Debugf("Pause, id: %s", r.ID)
	resp, err := s.get().Pause(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Resume the container.
func (s *shimRedirector) Resume(ctx context.Context, r *task.ResumeRequest) (*types.Empty, error) {
	log.L.Debugf("Resume, id: %s", r.ID)
	resp, err := s.get().Resume(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Kill the container with the provided signal.
func (s *shimRedirector) Kill(ctx context.Context, r *task.KillRequest) (*types.Empty, error) {
	log.L.Debugf("Kill, id: %s, execID: %s, signal: %d, all: %t", r.ID, r.ExecID, r.Signal, r.All)
	resp, err := s.get().Kill(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Pids returns all pids inside the container.
func (s *shimRedirector) Pids(ctx context.Context, r *task.PidsRequest) (*task.PidsResponse, error) {
	log.L.Debugf("Pids, id: %s", r.ID)
	resp, err := s.get().Pids(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// CloseIO closes the I/O context of the container.
func (s *shimRedirector) CloseIO(ctx context.Context, r *task.CloseIORequest) (*types.Empty, error) {
	log.L.Debugf("CloseIO, id: %s, execID: %s, stdin: %t", r.ID, r.ExecID, r.Stdin)
	resp, err := s.get().CloseIO(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Checkpoint checkpoints the container.
func (s *shimRedirector) Checkpoint(ctx context.Context, r *task.CheckpointTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Checkpoint, id: %s", r.ID)
	resp, err := s.get().Checkpoint(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Connect returns shim information such as the shim's pid.
func (s *shimRedirector) Connect(ctx context.Context, r *task.ConnectRequest) (*task.ConnectResponse, error) {
	log.L.Debugf("Connect, id: %s", r.ID)
	resp, err := s.get().Connect(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

func (s *shimRedirector) Shutdown(ctx context.Context, r *task.ShutdownRequest) (*types.Empty, error) {
	log.L.Debugf("Shutdown, id: %s", r.ID)
	resp, err := s.get().Shutdown(ctx, r)
	if err != nil {
		// The Shutdown call should return a nil error even if the shim did not
		// shutdown due to running containers. Returning nil indicates that the
		// request was successfully processed by the shim, regardless of whether the
		// shim was exited. This aligns with standard runc behavior, where the shim
		// stays alive as long as containers are present but acknowledges the shutdown
		// signal without error. The error from runscService's Shutdown call is used
		// as an indicator to identify if there are any active containers in the shim.
		log.L.Debugf("Shutdown, shim did not shutdown due to: %v", err)
		return resp, errgrpc.ToGRPC(nil)
	}
	s.shutdown.Shutdown()
	os.Exit(0)
	panic("Should not get here")
}

func (s *shimRedirector) Stats(ctx context.Context, r *task.StatsRequest) (*task.StatsResponse, error) {
	log.L.Debugf("Stats, id: %s", r.ID)
	resp, err := s.get().Stats(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Update updates a running container.
func (s *shimRedirector) Update(ctx context.Context, r *task.UpdateTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Update, id: %s", r.ID)
	resp, err := s.get().Update(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Wait waits for the container to exit.
func (s *shimRedirector) Wait(ctx context.Context, r *task.WaitRequest) (*task.WaitResponse, error) {
	log.L.Debugf("Wait, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Wait(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

// Restore restores the container.
func (s *shimRedirector) Restore(ctx context.Context, r *extension.RestoreRequest) (*task.StartResponse, error) {
	log.L.Debugf("Restore, id: %s", r.Start.ID)
	resp, err := s.get().Restore(ctx, r)
	return resp, errgrpc.ToGRPC(err)
}

func (s *shimRedirector) RegisterTTRPC(server *ttrpc.Server) error {
	task.RegisterTaskService(server, s)
	api.RegisterTTRPCSandboxService(server, s)
	return nil
}

func (s *shimRedirector) getSandboxService() (api.TTRPCSandboxService, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv, ok := s.getLocked().(api.TTRPCSandboxService); ok {
		return srv, nil
	}
	if srv, ok := s.main.(api.TTRPCSandboxService); ok {
		return srv, nil
	}
	return nil, errdefs.ErrNotImplemented
}

// CreateSandbox implements api.TTRPCSandboxService.CreateSandbox.
func (s *shimRedirector) CreateSandbox(ctx context.Context, req *api.CreateSandboxRequest) (*api.CreateSandboxResponse, error) {
	log.L.Debugf("CreateSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.CreateSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// StartSandbox implements api.TTRPCSandboxService.StartSandbox.
func (s *shimRedirector) StartSandbox(ctx context.Context, req *api.StartSandboxRequest) (*api.StartSandboxResponse, error) {
	log.L.Debugf("StartSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.StartSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// Platform implements api.TTRPCSandboxService.Platform.
func (s *shimRedirector) Platform(ctx context.Context, req *api.PlatformRequest) (*api.PlatformResponse, error) {
	log.L.Debugf("Platform redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.Platform(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// StopSandbox implements api.TTRPCSandboxService.StopSandbox.
func (s *shimRedirector) StopSandbox(ctx context.Context, req *api.StopSandboxRequest) (*api.StopSandboxResponse, error) {
	log.L.Debugf("StopSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.StopSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// WaitSandbox implements api.TTRPCSandboxService.WaitSandbox.
func (s *shimRedirector) WaitSandbox(ctx context.Context, req *api.WaitSandboxRequest) (*api.WaitSandboxResponse, error) {
	log.L.Debugf("WaitSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.WaitSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// SandboxStatus implements api.TTRPCSandboxService.SandboxStatus.
func (s *shimRedirector) SandboxStatus(ctx context.Context, req *api.SandboxStatusRequest) (*api.SandboxStatusResponse, error) {
	log.L.Debugf("SandboxStatus redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.SandboxStatus(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// PingSandbox implements api.TTRPCSandboxService.PingSandbox.
func (s *shimRedirector) PingSandbox(ctx context.Context, req *api.PingRequest) (*api.PingResponse, error) {
	log.L.Debugf("PingSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.PingSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// ShutdownSandbox implements api.TTRPCSandboxService.ShutdownSandbox.
func (s *shimRedirector) ShutdownSandbox(ctx context.Context, req *api.ShutdownSandboxRequest) (*api.ShutdownSandboxResponse, error) {
	log.L.Debugf("ShutdownSandbox redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.ShutdownSandbox(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}

// SandboxMetrics implements api.TTRPCSandboxService.SandboxMetrics.
func (s *shimRedirector) SandboxMetrics(ctx context.Context, req *api.SandboxMetricsRequest) (*api.SandboxMetricsResponse, error) {
	log.L.Debugf("SandboxMetrics redirector, id: %s", req.SandboxID)
	srv, err := s.getSandboxService()
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	resp, err := srv.SandboxMetrics(ctx, req)
	return resp, errgrpc.ToGRPC(err)
}
