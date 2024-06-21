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

// Package shim implements Containerd Shim v2 interface.
package shim

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/runtime/v2/shim"
	taskapi "github.com/containerd/containerd/runtime/v2/task"
	"github.com/gogo/protobuf/types"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"

	"gvisor.dev/gvisor/pkg/shim/extension"
	"gvisor.dev/gvisor/pkg/shim/runsc"
	"gvisor.dev/gvisor/pkg/sync"
)

const (
	// shimAddressPath is the relative path to a file that contains the address
	// to the shim UDS. See service.shimAddress.
	shimAddressPath = "address"
)

// New returns a new shim service that can be used via gRPC.
func New(ctx context.Context, id string, publisher shim.Publisher, cancel func()) (shim.Shim, error) {
	var opts shim.Opts
	if ctxOpts := ctx.Value(shim.OptsKey{}); ctxOpts != nil {
		opts = ctxOpts.(shim.Opts)
	}

	runsc, err := runsc.New(ctx, id, publisher)
	if err != nil {
		cancel()
		return nil, err
	}
	s := &service{
		genericOptions: opts,
		cancel:         cancel,
		main:           runsc,
	}

	if address, err := shim.ReadAddress(shimAddressPath); err == nil {
		s.shimAddress = address
	}

	return s, nil
}

// service is the shim implementation of a remote shim over gRPC. It runs in 2
// different modes:
//  1. Service: process runs for the life time of the container and receives
//     calls described in shimapi.TaskService interface.
//  2. Tool: process is short lived and runs only to perform the requested
//     operations and then exits. It implements the direct functions in
//     shim.Shim interface.
//
// It forwards all calls to extension.TaskServiceExt which actually implements the
// service interface. This struct receives the RPC calls, forwards them to the
// appropriate service implementation, and convert errors to gRPC errors.
type service struct {
	mu sync.Mutex

	// genericOptions are options that come from the shim interface and are common
	// to all shims.
	genericOptions shim.Opts

	// cancel is a function that needs to be called before the shim stops. The
	// function is provided by the caller to New().
	cancel func()

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
}

var _ shim.Shim = (*service)(nil)

// get return the extension.TaskServiceExt that should be used for the next
// call to the container's shim.
func (s *service) get() extension.TaskServiceExt {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ext == nil {
		return s.main
	}
	return s.ext
}

func (s *service) newCommand(ctx context.Context, containerdBinary, containerdAddress string) (*exec.Cmd, error) {
	ns, err := namespaces.NamespaceRequired(ctx)
	if err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	args := []string{
		"-namespace", ns,
		"-address", containerdAddress,
		"-publish-binary", containerdBinary,
	}
	if s.genericOptions.Debug {
		args = append(args, "-debug")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setpgid: true,
	}
	return cmd, nil
}

func (s *service) StartShim(ctx context.Context, id, containerdBinary, containerdAddress, containerdTTRPCAddress string) (string, error) {
	log.L.Debugf("StartShim, id: %s, binary: %q, address: %q", id, containerdBinary, containerdAddress)

	cmd, err := s.newCommand(ctx, containerdBinary, containerdAddress)
	if err != nil {
		return "", err
	}
	address, err := shim.SocketAddress(ctx, containerdAddress, id)
	if err != nil {
		return "", err
	}
	socket, err := shim.NewSocket(address)
	if err != nil {
		// The only time where this would happen is if there is a bug and the socket
		// was not cleaned up in the cleanup method of the shim or we are using the
		// grouping functionality where the new process should be run with the same
		// shim as an existing container.
		if !shim.SocketEaddrinuse(err) {
			return "", fmt.Errorf("create new shim socket: %w", err)
		}
		if shim.CanConnect(address) {
			if err := shim.WriteAddress(shimAddressPath, address); err != nil {
				return "", fmt.Errorf("write existing socket for shim: %w", err)
			}
			return address, nil
		}
		if err := shim.RemoveSocket(address); err != nil {
			return "", fmt.Errorf("remove pre-existing socket: %w", err)
		}
		if socket, err = shim.NewSocket(address); err != nil {
			return "", fmt.Errorf("try create new shim socket 2x: %w", err)
		}
	}
	cu := cleanup.Make(func() {
		socket.Close()
		_ = shim.RemoveSocket(address)
	})
	defer cu.Clean()

	f, err := socket.File()
	if err != nil {
		return "", err
	}

	cmd.ExtraFiles = append(cmd.ExtraFiles, f)

	log.L.Debugf("Executing: %q %s", cmd.Path, cmd.Args)
	if err := cmd.Start(); err != nil {
		f.Close()
		return "", err
	}
	cu.Add(func() { cmd.Process.Kill() })

	// make sure to wait after start
	go cmd.Wait()
	if err := shim.WritePidFile("shim.pid", cmd.Process.Pid); err != nil {
		return "", err
	}
	if err := shim.WriteAddress(shimAddressPath, address); err != nil {
		return "", err
	}
	if err := shim.SetScore(cmd.Process.Pid); err != nil {
		return "", fmt.Errorf("failed to set OOM Score on shim: %w", err)
	}
	cu.Release()
	return address, nil
}

// Cleanup is called from another process to stop the container and undo all
// operations done in Create().
func (s *service) Cleanup(ctx context.Context) (*taskapi.DeleteResponse, error) {
	log.L.Debugf("Cleanup")
	resp, err := s.get().Cleanup(ctx)
	return resp, errdefs.ToGRPC(err)
}

// Create creates a new initial process and container with the underlying OCI
// runtime.
func (s *service) Create(ctx context.Context, r *taskapi.CreateTaskRequest) (*taskapi.CreateTaskResponse, error) {
	log.L.Debugf("Create, id: %s, bundle: %q", r.ID, r.Bundle)

	// Check if we need to create an extension to intercept calls to the container's shim.
	if extension.NewExtension != nil {
		s.mu.Lock()
		var err error
		s.ext, err = extension.NewExtension(ctx, s.main, r)
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		if s.ext == nil {
			log.L.Debugf("No extension created for container")
		} else {
			log.L.Infof("Extension created for container")
		}
		s.mu.Unlock()
	}

	resp, err := s.get().Create(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Start starts the container.
func (s *service) Start(ctx context.Context, r *taskapi.StartRequest) (*taskapi.StartResponse, error) {
	log.L.Debugf("Start, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Start(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Delete deletes container.
func (s *service) Delete(ctx context.Context, r *taskapi.DeleteRequest) (*taskapi.DeleteResponse, error) {
	log.L.Debugf("Delete, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Delete(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Exec spawns a process inside the container.
func (s *service) Exec(ctx context.Context, r *taskapi.ExecProcessRequest) (*types.Empty, error) {
	log.L.Debugf("Exec, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Exec(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// ResizePty resizes the terminal of a process.
func (s *service) ResizePty(ctx context.Context, r *taskapi.ResizePtyRequest) (*types.Empty, error) {
	log.L.Debugf("ResizePty, id: %s, execID: %s, dimension: %dx%d", r.ID, r.ExecID, r.Height, r.Width)
	resp, err := s.get().ResizePty(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// State returns runtime state information for the container.
func (s *service) State(ctx context.Context, r *taskapi.StateRequest) (*taskapi.StateResponse, error) {
	log.L.Debugf("State, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().State(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Pause the container.
func (s *service) Pause(ctx context.Context, r *taskapi.PauseRequest) (*types.Empty, error) {
	log.L.Debugf("Pause, id: %s", r.ID)
	resp, err := s.get().Pause(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Resume the container.
func (s *service) Resume(ctx context.Context, r *taskapi.ResumeRequest) (*types.Empty, error) {
	log.L.Debugf("Resume, id: %s", r.ID)
	resp, err := s.get().Resume(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Kill the container with the provided signal.
func (s *service) Kill(ctx context.Context, r *taskapi.KillRequest) (*types.Empty, error) {
	log.L.Debugf("Kill, id: %s, execID: %s, signal: %d, all: %t", r.ID, r.ExecID, r.Signal, r.All)
	resp, err := s.get().Kill(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Pids returns all pids inside the container.
func (s *service) Pids(ctx context.Context, r *taskapi.PidsRequest) (*taskapi.PidsResponse, error) {
	log.L.Debugf("Pids, id: %s", r.ID)
	resp, err := s.get().Pids(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// CloseIO closes the I/O context of the container.
func (s *service) CloseIO(ctx context.Context, r *taskapi.CloseIORequest) (*types.Empty, error) {
	log.L.Debugf("CloseIO, id: %s, execID: %s, stdin: %t", r.ID, r.ExecID, r.Stdin)
	resp, err := s.get().CloseIO(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Checkpoint checkpoints the container.
func (s *service) Checkpoint(ctx context.Context, r *taskapi.CheckpointTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Checkpoint, id: %s", r.ID)
	resp, err := s.get().Checkpoint(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Connect returns shim information such as the shim's pid.
func (s *service) Connect(ctx context.Context, r *taskapi.ConnectRequest) (*taskapi.ConnectResponse, error) {
	log.L.Debugf("Connect, id: %s", r.ID)
	resp, err := s.get().Connect(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

func (s *service) Shutdown(ctx context.Context, r *taskapi.ShutdownRequest) (*types.Empty, error) {
	log.L.Debugf("Shutdown, id: %s", r.ID)
	resp, err := s.get().Shutdown(ctx, r)
	if err != nil {
		return resp, errdefs.ToGRPC(err)
	}

	s.cancel()
	if len(s.shimAddress) != 0 {
		_ = shim.RemoveSocket(s.shimAddress)
	}
	os.Exit(0)
	panic("Should not get here")
}

func (s *service) Stats(ctx context.Context, r *taskapi.StatsRequest) (*taskapi.StatsResponse, error) {
	log.L.Debugf("Stats, id: %s", r.ID)
	resp, err := s.get().Stats(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Update updates a running container.
func (s *service) Update(ctx context.Context, r *taskapi.UpdateTaskRequest) (*types.Empty, error) {
	log.L.Debugf("Update, id: %s", r.ID)
	resp, err := s.get().Update(ctx, r)
	return resp, errdefs.ToGRPC(err)
}

// Wait waits for the container to exit.
func (s *service) Wait(ctx context.Context, r *taskapi.WaitRequest) (*taskapi.WaitResponse, error) {
	log.L.Debugf("Wait, id: %s, execID: %s", r.ID, r.ExecID)
	resp, err := s.get().Wait(ctx, r)
	return resp, errdefs.ToGRPC(err)
}
