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
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
)

const (
	// ContainerEvent is the URPC endpoint for getting stats about the
	// container used by "runsc events".
	ContainerEvent = "containerManager.Event"

	// ContainerExecute is the URPC endpoint for executing a command in a
	// container..
	ContainerExecute = "containerManager.Execute"

	// ContainerProcesses is the URPC endpoint for getting the list of
	// processes running in a container.
	ContainerProcesses = "containerManager.Processes"

	// ContainerSignal is used to send a signal to a container.
	ContainerSignal = "containerManager.Signal"

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
func newController(fd int, k *kernel.Kernel) (*controller, error) {
	srv, err := server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	manager := &containerManager{
		startChan:       make(chan struct{}),
		startResultChan: make(chan error),
		k:               k,
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
}

// StartRoot will start the root container process.
func (cm *containerManager) StartRoot(_, _ *struct{}) error {
	// Tell the root container to start and wait for the result.
	cm.startChan <- struct{}{}
	return <-cm.startResultChan
}

// Processes retrieves information about processes running in the sandbox.
func (cm *containerManager) Processes(_, out *[]*control.Process) error {
	return control.Processes(cm.k, out)
}

// Execute runs a command on a created or running sandbox.
func (cm *containerManager) Execute(e *control.ExecArgs, waitStatus *uint32) error {
	proc := control.Proc{Kernel: cm.k}
	if err := proc.Exec(e, waitStatus); err != nil {
		return fmt.Errorf("error executing: %+v: %v", e, err)
	}
	return nil
}

// Wait waits for the init process in the given container.
func (cm *containerManager) Wait(cid *string, waitStatus *uint32) error {
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
