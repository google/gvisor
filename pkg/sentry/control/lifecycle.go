// Copyright 2021 The gVisor Authors.
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

package control

import (
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs/user"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/urpc"
)

// Lifecycle provides functions related to starting and stopping tasks.
type Lifecycle struct {
	// Kernel is the kernel where the tasks belong to.
	Kernel *kernel.Kernel

	// ShutdownCh is the channel used to signal the sentry to shutdown
	// the sentry/sandbox.
	ShutdownCh chan struct{}

	// mu protects the fields below.
	mu sync.RWMutex

	// MountNamespacesMap is a map of container id/names and the mount
	// namespaces.
	MountNamespacesMap map[string]*vfs.MountNamespace

	// containerMap is a map of the container id and the container.
	containerMap map[string]*Container
}

// containerState is the state of the container.
type containerState int

const (
	// stateCreated is the state when the container was created. It is the
	// initial state.
	stateCreated containerState = iota

	// stateRunning is the state when the container/application is running.
	stateRunning

	// stateStopped is the state when the container has exited.
	stateStopped
)

// Container contains the set of parameters to represent a container.
type Container struct {
	// containerID.
	containerID string

	// tg is the init(PID 1) threadgroup of the container.
	tg *kernel.ThreadGroup

	// state is the current state of the container.
	state containerState
}

// StartContainerArgs is the set of arguments to start a container.
type StartContainerArgs struct {
	// Filename is the filename to load.
	//
	// If this is provided as "", then the file will be guessed via Argv[0].
	Filename string `json:"filename"`

	// Argv is a list of arguments.
	Argv []string `json:"argv"`

	// Envv is a list of environment variables.
	Envv []string `json:"envv"`

	// WorkingDirectory defines the working directory for the new process.
	WorkingDirectory string `json:"wd"`

	// KUID is the UID to run with in the root user namespace. Defaults to
	// root if not set explicitly.
	KUID auth.KUID `json:"KUID"`

	// KGID is the GID to run with in the root user namespace. Defaults to
	// the root group if not set explicitly.
	KGID auth.KGID `json:"KGID"`

	// ExtraKGIDs is the list of additional groups to which the user belongs.
	ExtraKGIDs []auth.KGID `json:"extraKGID"`

	// Capabilities is the list of capabilities to give to the process.
	Capabilities *auth.TaskCapabilities `json:"capabilities"`

	// FilePayload determines the files to give to the new process.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string `json:"containerID"`

	// Limits is the limit set for the process being executed.
	Limits *limits.LimitSet `json:"limits"`
}

// String prints the StartContainerArgs.argv as a string.
func (args StartContainerArgs) String() string {
	if len(args.Argv) == 0 {
		return args.Filename
	}
	a := make([]string, len(args.Argv))
	copy(a, args.Argv)
	if args.Filename != "" {
		a[0] = args.Filename
	}
	return strings.Join(a, " ")
}

func (l *Lifecycle) updateContainerState(containerID string, newState containerState) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.containerMap[containerID]
	if !ok {
		return fmt.Errorf("container %v not started", containerID)
	}

	switch newState {
	case stateCreated:
		// Impossible.
		panic(fmt.Sprintf("invalid state transition: %v => %v", c.state, newState))

	case stateRunning:
		if c.state != stateCreated {
			// Impossible.
			panic(fmt.Sprintf("invalid state transition: %v => %v", c.state, newState))
		}

	case stateStopped:
		// Valid state transition.

	default:
		// Invalid new state.
		panic(fmt.Sprintf("invalid new state: %v", newState))
	}

	c.state = newState
	return nil
}

// StartContainer will start a new container in the sandbox.
func (l *Lifecycle) StartContainer(args *StartContainerArgs, _ *uint32) error {
	// Import file descriptors.
	fdTable := l.Kernel.NewFDTable()

	creds := auth.NewUserCredentials(
		args.KUID,
		args.KGID,
		args.ExtraKGIDs,
		args.Capabilities,
		l.Kernel.RootUserNamespace())

	limitSet := args.Limits
	if limitSet == nil {
		limitSet = limits.NewLimitSet()
	}

	// Create a new pid namespace for the container. Each container must run
	// in its own pid namespace.
	pidNs := l.Kernel.RootPIDNamespace().NewChild(l.Kernel.RootUserNamespace())

	initArgs := kernel.CreateProcessArgs{
		Filename:                args.Filename,
		Argv:                    args.Argv,
		Envv:                    args.Envv,
		WorkingDirectory:        args.WorkingDirectory,
		Credentials:             creds,
		FDTable:                 fdTable,
		Umask:                   0022,
		Limits:                  limitSet,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            l.Kernel.RootUTSNamespace(),
		IPCNamespace:            l.Kernel.RootIPCNamespace(),
		AbstractSocketNamespace: l.Kernel.RootAbstractSocketNamespace(),
		ContainerID:             args.ContainerID,
		PIDNamespace:            pidNs,
	}

	ctx := initArgs.NewContext(l.Kernel)
	defer fdTable.DecRef(ctx)

	// VFS2 is supported in multi-container mode by default.
	l.mu.RLock()
	mntns, ok := l.MountNamespacesMap[initArgs.ContainerID]
	if !ok {
		l.mu.RUnlock()
		return fmt.Errorf("mount namespace is nil for %s", initArgs.ContainerID)
	}
	initArgs.MountNamespaceVFS2 = mntns
	l.mu.RUnlock()
	initArgs.MountNamespaceVFS2.IncRef()

	resolved, err := user.ResolveExecutablePath(ctx, &initArgs)
	if err != nil {
		return err
	}
	initArgs.Filename = resolved

	fds, err := fd.NewFromFiles(args.Files)
	if err != nil {
		return fmt.Errorf("duplicating payload files: %w", err)
	}
	defer func() {
		for _, fd := range fds {
			_ = fd.Close()
		}
	}()

	tg, _, err := l.Kernel.CreateProcess(initArgs)
	if err != nil {
		return err
	}

	c := &Container{
		containerID: initArgs.ContainerID,
		tg:          tg,
		state:       stateCreated,
	}

	l.mu.Lock()
	if l.containerMap == nil {
		l.containerMap = make(map[string]*Container)
	}
	l.containerMap[initArgs.ContainerID] = c
	l.mu.Unlock()

	// Start the newly created process.
	l.Kernel.StartProcess(tg)
	log.Infof("Started the new container %v ", initArgs.ContainerID)

	l.updateContainerState(initArgs.ContainerID, stateRunning)
	return nil
}

// Pause pauses all tasks, blocking until they are stopped.
func (l *Lifecycle) Pause(_, _ *struct{}) error {
	l.Kernel.Pause()
	return nil
}

// Resume resumes all tasks.
func (l *Lifecycle) Resume(_, _ *struct{}) error {
	l.Kernel.Unpause()
	return nil
}

// Shutdown sends signal to destroy the sentry/sandbox.
func (l *Lifecycle) Shutdown(_, _ *struct{}) error {
	close(l.ShutdownCh)
	return nil
}

func (l *Lifecycle) getInitContainerProcess(containerID string) (*kernel.ThreadGroup, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.containerMap[containerID]
	if !ok {
		return nil, fmt.Errorf("container %v not started", containerID)
	}
	return c.tg, nil
}

// ContainerArgs is the set of arguments for container related APIs after
// starting the container.
type ContainerArgs struct {
	// ContainerID.
	ContainerID string `json:"containerID"`
	Signo       int32  `json:"signo"`
	SignalAll   bool   `json:"signalAll"`
}

// WaitContainer waits for the container to exit and returns the exit status.
func (l *Lifecycle) WaitContainer(args *ContainerArgs, waitStatus *uint32) error {
	tg, err := l.getInitContainerProcess(args.ContainerID)
	if err != nil {
		return err
	}

	tg.WaitExited()
	*waitStatus = uint32(tg.ExitStatus())
	if err := l.updateContainerState(args.ContainerID, stateStopped); err != nil {
		return err
	}
	return nil
}

// IsContainerRunning returns true if the container is running.
func (l *Lifecycle) IsContainerRunning(args *ContainerArgs, isRunning *bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.containerMap[args.ContainerID]
	if !ok || c.state != stateRunning {
		return nil
	}

	// The state will not be updated to "stopped" if the
	// WaitContainer(...) method is not called. In this case, check
	// whether the number of non-exited tasks in tg is zero to get
	// the correct state of the container.
	if c.tg.Count() == 0 {
		c.state = stateStopped
		return nil
	}
	*isRunning = true
	return nil
}

// SignalContainer signals the container in multi-container mode. It returns error if the
// container hasn't started or has exited.
func (l *Lifecycle) SignalContainer(args *ContainerArgs, _ *struct{}) error {
	tg, err := l.getInitContainerProcess(args.ContainerID)
	if err != nil {
		return err
	}

	l.mu.Lock()
	c, ok := l.containerMap[args.ContainerID]
	if !ok || c.state != stateRunning {
		l.mu.Unlock()
		return fmt.Errorf("%v container not running", args.ContainerID)
	}
	l.mu.Unlock()

	// Signalling a single process is supported only for the init process.
	if !args.SignalAll {
		if tg == nil {
			return fmt.Errorf("no process exists in %v", tg)
		}
		return l.Kernel.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: args.Signo})
	}

	l.Kernel.Pause()
	defer l.Kernel.Unpause()
	return l.Kernel.SendContainerSignal(args.ContainerID, &linux.SignalInfo{Signo: args.Signo})
}
