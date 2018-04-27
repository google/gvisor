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
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/epsocket"
)

const (
	// ApplicationStart is the URPC endpoint for starting a sandboxed app.
	ApplicationStart = "application.Start"

	// ApplicationProcesses is the URPC endpoint for getting the list of
	// processes running in a sandbox.
	ApplicationProcesses = "application.Processes"

	// ApplicationExecute is the URPC endpoint for executing a command in a
	// sandbox.
	ApplicationExecute = "application.Execute"

	// ApplicationEvent is the URPC endpoint for getting stats about the
	// container used by "runsc events".
	ApplicationEvent = "application.Event"

	// NetworkCreateLinksAndRoutes is the URPC endpoint for creating links
	// and routes in a network stack.
	NetworkCreateLinksAndRoutes = "Network.CreateLinksAndRoutes"
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

	// app holds the application methods.
	app *application
}

// newController creates a new controller and starts it listening.
func newController(fd int, k *kernel.Kernel) (*controller, error) {
	srv, err := server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	app := &application{
		startChan:       make(chan struct{}),
		startResultChan: make(chan error, 1),
		k:               k,
	}
	srv.Register(app)

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
		srv: srv,
		app: app,
	}, nil
}

// application contains methods that control the sandboxed application.
type application struct {
	// startChan is used to signal when the application process should be
	// started.
	startChan chan struct{}

	// startResultChan is used to signal when the application has started. Any
	// errors encountered during startup will be sent to the channel. A nil value
	// indicates success.
	startResultChan chan error

	// k is the emulated linux kernel on which the sandboxed
	// application runs.
	k *kernel.Kernel
}

// Start will start the application process.
func (a *application) Start(_, _ *struct{}) error {
	// Tell the application to start and wait for the result.
	a.startChan <- struct{}{}
	return <-a.startResultChan
}

// Processes retrieves information about processes running in the sandbox.
func (a *application) Processes(_, out *[]*control.Process) error {
	return control.Processes(a.k, out)
}

// Execute runs a command on a created or running sandbox.
func (a *application) Execute(e *control.ExecArgs, waitStatus *uint32) error {
	proc := control.Proc{Kernel: a.k}
	if err := proc.Exec(e, waitStatus); err != nil {
		return fmt.Errorf("error executing: %+v: %v", e, err)
	}
	return nil
}
