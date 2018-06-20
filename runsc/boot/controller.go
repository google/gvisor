// Copyright 2018 Google Inc.
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

package boot

import (
	"errors"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
	"gvisor.googlesource.com/gvisor/pkg/sentry/watchdog"
)

const (
	// ContainerCheckpoint checkpoints a container.
	ContainerCheckpoint = "containerManager.Checkpoint"

	// ContainerEvent is the URPC endpoint for getting stats about the
	// container used by "runsc events".
	ContainerEvent = "containerManager.Event"

	// ContainerExecute is the URPC endpoint for executing a command in a
	// container..
	ContainerExecute = "containerManager.Execute"

	// ContainerPause pauses the container.
	ContainerPause = "containerManager.Pause"

	// ContainerProcesses is the URPC endpoint for getting the list of
	// processes running in a container.
	ContainerProcesses = "containerManager.Processes"

	// ContainerResume unpauses the paused container.
	ContainerResume = "containerManager.Resume"

	// ContainerSignal is used to send a signal to a container.
	ContainerSignal = "containerManager.Signal"

	// ContainerStart is the URPC endpoint for running a non-root container
	// within a sandbox.
	ContainerStart = "containerManager.Start"

	// ContainerWait is used to wait on the init process of the container
	// and return its ExitStatus.
	ContainerWait = "containerManager.Wait"

	// NetworkCreateLinksAndRoutes is the URPC endpoint for creating links
	// and routes in a network stack.
	NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"

	// RootContainerStart is the URPC endpoint for starting a new sandbox
	// with root container.
	RootContainerStart = "containerManager.StartRoot"
)

// ControlSocketAddr generates an abstract unix socket name for the given id.
func ControlSocketAddr(id string) string {
	return fmt.Sprintf("\x00runsc-sandbox.%s", id)
}

// controller holds the control server, and is used for communication into the
// sandbox.
type controller struct {
	// srv is the contorl server.
	srv *server.Server

	// manager holds the containerManager methods.
	manager *containerManager
}

// newController creates a new controller and starts it listening.
func newController(fd int, k *kernel.Kernel, w *watchdog.Watchdog) (*controller, error) {
	srv, err := server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	manager := &containerManager{
		startChan:       make(chan struct{}),
		startResultChan: make(chan error),
		k:               k,
		watchdog:        w,
	}
	srv.Register(manager)

	if eps, ok := k.NetworkStack().(*epsocket.Stack); ok {
		net := &Network{
			Stack: eps.Stack,
		}
		srv.Register(net)
	}

	if err := srv.StartServing(); err != nil {
		return nil, err
	}

	return &controller{
		srv:     srv,
		manager: manager,
	}, nil
}

// containerManager manages sandboes containers.
type containerManager struct {
	// startChan is used to signal when the root container process should
	// be started.
	startChan chan struct{}

	// startResultChan is used to signal when the root container  has
	// started. Any errors encountered during startup will be sent to the
	// channel. A nil value indicates success.
	startResultChan chan error

	// k is the emulated linux kernel on which the sandboxed
	// containers run.
	k *kernel.Kernel

	// watchdog is the kernel watchdog.
	watchdog *watchdog.Watchdog

	// l is the loader that creates containers and sandboxes.
	l *Loader
}

// StartRoot will start the root container process.
func (cm *containerManager) StartRoot(_, _ *struct{}) error {
	log.Debugf("containerManager.StartRoot")
	// Tell the root container to start and wait for the result.
	cm.startChan <- struct{}{}
	return <-cm.startResultChan
}

// Processes retrieves information about processes running in the sandbox.
func (cm *containerManager) Processes(_, out *[]*control.Process) error {
	log.Debugf("containerManager.Processes")
	return control.Processes(cm.k, out)
}

// StartArgs contains arguments to the Start method.
type StartArgs struct {
	// Spec is the spec of the container to start.
	Spec *specs.Spec

	// TODO: Separate sandbox and container configs.
	// Config is the runsc-specific configuration for the sandbox.
	Conf *Config
}

// Start runs a created container within a sandbox.
func (cm *containerManager) Start(args *StartArgs, _ *struct{}) error {
	log.Debugf("containerManager.Start")

	// Validate arguments.
	if args == nil {
		return errors.New("start missing arguments")
	}
	if args.Spec == nil {
		return errors.New("start arguments missing spec")
	}
	if args.Conf == nil {
		return errors.New("start arguments missing config")
	}

	cm.l.startContainer(args, cm.k)
	return nil
}

// Execute runs a command on a created or running sandbox.
func (cm *containerManager) Execute(e *control.ExecArgs, waitStatus *uint32) error {
	log.Debugf("containerManager.Execute")
	proc := control.Proc{Kernel: cm.k}
	if err := proc.Exec(e, waitStatus); err != nil {
		return fmt.Errorf("error executing: %+v: %v", e, err)
	}
	return nil
}

// Checkpoint pauses a sandbox and saves its state.
func (cm *containerManager) Checkpoint(o *control.SaveOpts, _ *struct{}) error {
	log.Debugf("containerManager.Checkpoint")
	state := control.State{
		Kernel:   cm.k,
		Watchdog: cm.watchdog,
	}
	return state.Save(o, nil)
}

// Pause suspends a container.
func (cm *containerManager) Pause(_, _ *struct{}) error {
	cm.k.Pause()
	return nil
}

// Resume unpauses a container.
func (cm *containerManager) Resume(_, _ *struct{}) error {
	cm.k.Unpause()
	return nil
}

// Wait waits for the init process in the given container.
func (cm *containerManager) Wait(cid *string, waitStatus *uint32) error {
	log.Debugf("containerManager.Wait")
	// TODO: Use the cid and wait on the init process in that
	// container. Currently we just wait on PID 1 in the sandbox.
	tg := cm.k.TaskSet().Root.ThreadGroupWithID(1)
	if tg == nil {
		return fmt.Errorf("cannot wait: no thread group with id 1")
	}
	tg.WaitExited()
	*waitStatus = tg.ExitStatus().Status()
	return nil
}

// SignalArgs are arguments to the Signal method.
type SignalArgs struct {
	// CID is the container id.
	CID string

	// Signo is the signal to send to the process.
	Signo int32
}

// Signal sends a signal to the init process of the container.
func (cm *containerManager) Signal(args *SignalArgs, _ *struct{}) error {
	log.Debugf("containerManager.Signal")
	// TODO: Use the cid and send the signal to the init
	// process in theat container. Currently we just signal PID 1 in the
	// sandbox.
	si := arch.SignalInfo{Signo: args.Signo}
	t := cm.k.TaskSet().Root.TaskWithID(1)
	if t == nil {
		return fmt.Errorf("cannot signal: no task with id 1")
	}
	return t.SendSignal(&si)
}
