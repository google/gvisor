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
	"fmt"
	"os"

	"github.com/containerd/containerd/pkg/shutdown"
	"github.com/containerd/containerd/runtime/v2/shim"
	shimapi "github.com/containerd/containerd/runtime/v2/task"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/gogo/protobuf/types"
	hibernatepb "gvisor.dev/gvisor/pkg/shim/v1/runsc/hibernate_go_proto"

	"gvisor.dev/gvisor/pkg/shim/v1/extension"
	rsc "gvisor.dev/gvisor/pkg/shim/v1/runsc"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// shimAddressPath is the relative path to a file that contains the address
	// to the shim UDS. See service.shimAddress.
	shimAddressPath = "address"
)

type shimTaskManager struct {
	extension.TaskServiceExt
	id      string
	manager shim.Manager
}

// Cleanup implements shim.Shim.Cleanup.
func (stm *shimTaskManager) Cleanup(ctx context.Context) (*shimapi.DeleteResponse, error) {
	ss, err := stm.manager.Stop(ctx, stm.id)
	if err != nil {
		return nil, err
	}
	return &shimapi.DeleteResponse{
		Pid:        uint32(ss.Pid),
		ExitStatus: uint32(ss.ExitStatus),
		ExitedAt:   ss.ExitedAt,
	}, nil
}

// StartShim implements shim.Shim.StartShim.
func (stm *shimTaskManager) StartShim(ctx context.Context, opts shim.StartOpts) (string, error) {
	return stm.manager.Start(ctx, opts.ID, opts)
}

// New returns a new shim service that can be used for
// - serving the task service over grpc/ttrpc
// - shim management
func New(ctx context.Context, id string, publisher shim.Publisher, fn func()) (shim.Shim, error) {
	var shimOpts shim.Opts
	if ctxOpts := ctx.Value(shim.OptsKey{}); ctxOpts != nil {
		shimOpts = ctxOpts.(shim.Opts)
	}
	sd, ok := ctx.(shutdown.Service)
	if !ok {
		ctx, sd = shutdown.WithShutdown(ctx)
		sd.RegisterCallback(func(context.Context) error {
			fn()
			return nil
		})
	}
	ts, err := newShimRedirector(ctx, id, publisher, sd)
	if err != nil {
		return nil, err
	}
	return &shimTaskManager{
		TaskServiceExt: ts,
		id:             id,
		manager:        NewShimManager("runsc", shimOpts.BundlePath),
	}, nil
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

// newShimRedirector creates a new runsc service that delegates to respective runsc task service.
func newShimRedirector(ctx context.Context, id string, publisher shim.Publisher, sd shutdown.Service) (extension.TaskServiceExt, error) {
	runsc, err := rsc.NewTaskService(ctx, id, publisher, sd)
	if err != nil {
		sd.Shutdown()
		return nil, err
	}

	runtimeOptions := getRuntimeOptions()

	var hibernateServerEndpoint *rsc.HibernateServerEndpoint
	if runtimeOptions.EnableHibernateServer && isDaemon() {
		var err error
		hibernateServerEndpoint, err = rsc.NewHibernateServerEndpoint(runtimeOptions.Root, "shim", id)
		if err != nil {
			sd.Shutdown()
			return nil, err
		}
		if hibernateServerEndpoint != nil {
			sd.RegisterCallback(func(context.Context) error {
				return hibernateServerEndpoint.Shutdown(ctx)
			})
		}
	}
	s := &shimRedirector{
		shutdown:                sd,
		main:                    runsc,
		hibernateServerEndpoint: hibernateServerEndpoint,
	}
	if address, _ := shim.ReadAddress(shimAddressPath); len(address) > 0 {
		sd.RegisterCallback(func(context.Context) error {
			shim.RemoveSocket(address)
			return nil
		})
	}

	if address, _ := shim.ReadAddress("hibernate_server"); len(address) > 0 {
		sd.RegisterCallback(func(context.Context) error {
			shim.RemoveSocket(fmt.Sprintf("unix://%s", address))
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

	// hibernateServerOnce ensures that the hibernate service is only started once.
	hibernateServerOnce sync.Once

	// hibernateServerEndpoint is the ttrpc server that listens for hibernate requests.
	hibernateServerEndpoint *rsc.HibernateServerEndpoint

	shutdown shutdown.Service
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

// initExt initializes the extension that may intercept calls to the container's shim.
func (s *shimRedirector) initExt(ctx context.Context, r *shimapi.CreateTaskRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.grouping {
		// Create shim extension if required.
		if s.ext == nil && extension.NewPodExtension != nil {
			log.L.Infof("Create shim extension per pod")
			var err error
			s.ext, err = extension.NewPodExtension(ctx, s.main, r)
			if err != nil {
				log.L.Debugf("Creating shim extension per pod failed with error: %v", err)
				s.mu.Unlock()
				return err
			}
		}
	} else {
		// Check if we need to create an extension to intercept calls to the container's shim.
		if extension.NewExtension != nil {
			log.L.Infof("Create shim extension per container")
			var err error
			s.ext, err = extension.NewExtension(ctx, s.main, r)
			if err != nil {
				s.mu.Unlock()
				return err
			}
		}
	}
	if s.hibernateServerEndpoint != nil {
		s.hibernateServerOnce.Do(func() {
			s.hibernateServerEndpoint.RegisterService(s.getLocked())
			go func() {
				if err := s.hibernateServerEndpoint.Serve(context.Background()); err != nil {
					log.L.Errorf("Failed to start hibernate server: %v", err)
				}
			}()
		})
	} else {
		log.L.Infof("Hibernate server endpoint is nil")
	}
	return nil
}

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *shimRedirector) Create(ctx context.Context, r *shimapi.CreateTaskRequest) (*shimapi.CreateTaskResponse, error) {
	log.L.Debugf("Create, id: %s, bundle: %q", r.ID, r.Bundle)
	if err := s.initExt(ctx, r); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	resp, err := s.get().Create(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// CreateWithFSRestore creates a container which restores its filesystem from a snapshot.
func (s *shimRedirector) CreateWithFSRestore(ctx context.Context, r *extension.CreateWithFSRestoreRequest) (*shimapi.CreateTaskResponse, error) {
	log.L.Debugf("CreateWithFSRestore, id: %s, bundle: %q", r.Create.ID, r.Create.Bundle)
	if err := s.initExt(ctx, r.Create); err != nil {
		return nil, errdefs.ToGRPC(err)
	}
	resp, err := s.get().CreateWithFSRestore(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Start starts the container.
func (s *shimRedirector) Start(ctx context.Context, r *shimapi.StartRequest) (*shimapi.StartResponse, error) {
	log.L.Debugf("Start, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Start(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Delete deletes container.
func (s *shimRedirector) Delete(ctx context.Context, r *shimapi.DeleteRequest) (*shimapi.DeleteResponse, error) {
	log.L.Debugf("Delete, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Delete(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Exec spawns a process inside the container.
func (s *shimRedirector) Exec(ctx context.Context, r *shimapi.ExecProcessRequest) (*types.Empty, error) {
	log.L.Debugf("Exec, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Exec(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// ResizePty resizes the terminal of a process.
func (s *shimRedirector) ResizePty(ctx context.Context, r *shimapi.ResizePtyRequest) (*types.Empty, error) {
	log.L.Debugf("ResizePty, id: %s, execID: %s, dimension: %dx%d", r.ID, r.ExecID, r.Height, r.Width)
	resp, err := s.get().ResizePty(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// State returns runtime state information for the container.
func (s *shimRedirector) State(ctx context.Context, r *shimapi.StateRequest) (*shimapi.StateResponse, error) {
	log.L.Debugf("State, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().State(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Pause the container.
func (s *shimRedirector) Pause(ctx context.Context, r *shimapi.PauseRequest) (*types.Empty, error) {
	log.L.Debugf("Pause, id: %s", r.ID)
	resp, err := s.get().Pause(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Resume the container.
func (s *shimRedirector) Resume(ctx context.Context, r *shimapi.ResumeRequest) (*types.Empty, error) {
	log.L.Debugf("Resume, id: %s", r.ID)
	resp, err := s.get().Resume(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Kill the container with the provided signal.
func (s *shimRedirector) Kill(ctx context.Context, r *shimapi.KillRequest) (*types.Empty, error) {
	log.L.Debugf("Kill, id: %s, execID: %s, signal: %d, all: %t", r.ID, r.ExecID, r.Signal, r.All)
	resp, err := s.get().Kill(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Pids returns all pids inside the container.
func (s *shimRedirector) Pids(ctx context.Context, r *shimapi.PidsRequest) (*shimapi.PidsResponse, error) {
	log.L.Debugf("Pids, id: %s", r.ID)
	resp, err := s.get().Pids(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// CloseIO closes the I/O context of the container.
func (s *shimRedirector) CloseIO(ctx context.Context, r *shimapi.CloseIORequest) (*types.Empty, error) {
	log.L.Debugf("CloseIO, id: %s, execID: %s, stdin: %t", r.ID, r.ExecID, r.Stdin)
	resp, err := s.get().CloseIO(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Checkpoint checkpoints the container.
func (s *shimRedirector) Checkpoint(ctx context.Context, r *shimapi.CheckpointTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Checkpoint, id: %s", r.ID)
	resp, err := s.get().Checkpoint(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Connect returns shim information such as the shim's pid.
func (s *shimRedirector) Connect(ctx context.Context, r *shimapi.ConnectRequest) (*shimapi.ConnectResponse, error) {
	log.L.Debugf("Connect, id: %s", r.ID)
	resp, err := s.get().Connect(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

func (s *shimRedirector) Shutdown(ctx context.Context, r *shimapi.ShutdownRequest) (*types.Empty, error) {
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
		return resp, errdefs.ToGRPC(nil)
	}
	s.shutdown.Shutdown()
	os.Exit(0)
	panic("Should not get here")
}

func (s *shimRedirector) Stats(ctx context.Context, r *shimapi.StatsRequest) (*shimapi.StatsResponse, error) {
	log.L.Debugf("Stats, id: %s", r.ID)
	resp, err := s.get().Stats(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Update updates a running container.
func (s *shimRedirector) Update(ctx context.Context, r *shimapi.UpdateTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Update, id: %s", r.ID)
	resp, err := s.get().Update(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Wait waits for the container to exit.
func (s *shimRedirector) Wait(ctx context.Context, r *shimapi.WaitRequest) (*shimapi.WaitResponse, error) {
	log.L.Debugf("Wait, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Wait(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Restore restores the container.
func (s *shimRedirector) Restore(ctx context.Context, r *extension.RestoreRequest) (*shimapi.StartResponse, error) {
	log.L.Debugf("Restore, id: %s", r.Start.ID)
	resp, err := s.get().Restore(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

func (s *shimRedirector) Hide(ctx context.Context, r *hibernatepb.HideRequest, resp *hibernatepb.HideResponse) error {
	log.L.Debugf("Hide, id: %s", r.GetContainerId())
	err := s.get().Hide(ctx, r, resp)
	return errdefs.ToGRPC(err)
}

func (s *shimRedirector) Unhide(ctx context.Context, r *hibernatepb.UnhideRequest, resp *hibernatepb.UnhideResponse) error {
	log.L.Debugf("Unhide, id: %s", r.GetContainerId())
	err := s.get().Unhide(ctx, r, resp)
	return errdefs.ToGRPC(err)
}
