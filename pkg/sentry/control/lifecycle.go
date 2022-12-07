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
	"encoding/json"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	pb "gvisor.dev/gvisor/pkg/sentry/control/control_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/fdimport"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/user"
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

	// Secret_envv is a list of secret environment variables.
	//
	// NOTE: This field must never be logged!
	SecretEnvv []string `json:"secret_envv"`

	// WorkingDirectory defines the working directory for the new process.
	WorkingDirectory string `json:"wd"`

	// KUID is the UID to run with in the root user namespace. Defaults to
	// root if not set explicitly.
	KUID auth.KUID `json:"KUID"`

	// KGID is the GID to run with in the root user namespace. Defaults to
	// the root group if not set explicitly.
	KGID auth.KGID `json:"KGID"`

	// ContainerID is the container for the process being executed.
	ContainerID string `json:"container_id"`

	// Limits is the limit set for the process being executed.
	Limits map[string]limits.Limit `json:"limits"`

	// If HOME environment variable is not provided, and this flag is set,
	// then the HOME environment variable will be set inside the container
	// based on the user's home directory in /etc/passwd.
	ResolveHome bool `json:"resolve_home"`

	// If set, attempt to resolve the binary_path via the following procedure:
	// 1) If binary_path is absolute, it is used directly.
	// 2) If binary_path contains a slash, then it is resolved relative to the
	//    working_directory (or the root it working_directory is not set).
	// 3) Otherwise, search the PATH environment variable for the first directory
	//    that contains an executable file with name in binary_path.
	ResolveBinaryPath bool `json:"resolve_binary_path"`

	// DonatedFDs is the list of sentry-intrenal file descriptors that will
	// donated. They correspond to the donated files in FilePayload.
	DonatedFDs []int `json:"donated_fds"`

	// FilePayload determines the files to give to the new process.
	urpc.FilePayload
}

// String formats the StartContainerArgs without the SecretEnvv field.
func (sca StartContainerArgs) String() string {
	sca.SecretEnvv = make([]string, len(sca.SecretEnvv))
	for i := range sca.SecretEnvv {
		sca.SecretEnvv[i] = "(hidden)"
	}
	b, err := json.Marshal(sca)
	if err != nil {
		return fmt.Sprintf("error marshaling: %s", err)
	}
	return string(b)
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
	log.Infof("StartContainer: %v", args)
	if len(args.Files) != len(args.DonatedFDs) {
		return fmt.Errorf("FilePayload.Files and DonatedFDs must have same number of elements (%d != %d)", len(args.Files), len(args.DonatedFDs))
	}

	creds := auth.NewUserCredentials(
		args.KUID,
		args.KGID,
		nil, /* extraKGIDs */
		nil, /* capabilities */
		l.Kernel.RootUserNamespace())

	ls, err := limits.NewLinuxDistroLimitSet()
	if err != nil {
		return fmt.Errorf("error creating default limit set: %w", err)
	}
	for name, limit := range args.Limits {
		lt, ok := limits.FromLinuxResourceName[name]
		if !ok {
			return fmt.Errorf("unknown limit %q", name)
		}
		ls.SetUnchecked(lt, limit)
	}

	// Create a new pid namespace for the container. Each container must run
	// in its own pid namespace.
	pidNs := l.Kernel.RootPIDNamespace().NewChild(l.Kernel.RootUserNamespace())

	initArgs := kernel.CreateProcessArgs{
		Filename: args.Filename,
		Argv:     args.Argv,
		// Order Envv before SecretEnvv.
		Envv:                    append(args.Envv, args.SecretEnvv...),
		WorkingDirectory:        args.WorkingDirectory,
		Credentials:             creds,
		Umask:                   0022,
		Limits:                  ls,
		MaxSymlinkTraversals:    linux.MaxSymlinkTraversals,
		UTSNamespace:            l.Kernel.RootUTSNamespace(),
		IPCNamespace:            l.Kernel.RootIPCNamespace(),
		AbstractSocketNamespace: l.Kernel.RootAbstractSocketNamespace(),
		ContainerID:             args.ContainerID,
		PIDNamespace:            pidNs,
	}

	ctx := initArgs.NewContext(l.Kernel)

	// Import file descriptors.
	fdTable := l.Kernel.NewFDTable()
	defer fdTable.DecRef(ctx)
	hostFDs, err := fd.NewFromFiles(args.Files)
	if err != nil {
		return fmt.Errorf("error donating host files: %w", err)
	}
	defer func() {
		for _, hfd := range hostFDs {
			_ = hfd.Close()
		}
	}()
	fdMap := make(map[int]*fd.FD, len(args.DonatedFDs))
	for i, appFD := range args.DonatedFDs {
		fdMap[appFD] = hostFDs[i]
	}
	if _, err := fdimport.Import(ctx, fdTable, false, args.KUID, args.KGID, fdMap); err != nil {
		return fmt.Errorf("error importing host files: %w", err)
	}
	initArgs.FDTable = fdTable

	l.mu.RLock()
	mntns, ok := l.MountNamespacesMap[initArgs.ContainerID]
	if !ok {
		l.mu.RUnlock()
		return fmt.Errorf("mount namespace is nil for %s", initArgs.ContainerID)
	}
	initArgs.MountNamespace = mntns
	l.mu.RUnlock()
	initArgs.MountNamespace.IncRef()

	if args.ResolveBinaryPath {
		resolved, err := user.ResolveExecutablePath(ctx, &initArgs)
		if err != nil {
			return fmt.Errorf("failed to resolve binary path: %w", err)
		}
		initArgs.Filename = resolved
	}

	if args.ResolveHome {
		envVars, err := user.MaybeAddExecUserHome(ctx, initArgs.MountNamespace, creds.RealKUID, initArgs.Envv)
		if err != nil {
			return fmt.Errorf("failed to get user home dir: %w", err)
		}
		initArgs.Envv = envVars
	}

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

	if _, ok := l.containerMap[initArgs.ContainerID]; ok {
		return fmt.Errorf("container id: %v already exists", initArgs.ContainerID)
	}

	l.containerMap[initArgs.ContainerID] = c
	l.mu.Unlock()

	// Start the newly created process.
	l.Kernel.StartProcess(tg)
	log.Infof("Started the new container %v ", initArgs.ContainerID)
	eventchannel.LogEmit(&pb.ContainerStartedEvent{
		Started:     true,
		ContainerId: initArgs.ContainerID,
	})

	if err := l.updateContainerState(initArgs.ContainerID, stateRunning); err != nil {
		// Sanity check: shouldn't fail to update the state at this point.
		panic(fmt.Sprintf("Failed to set running state: %v", err))

	}

	// TODO(b/251490950): reap thread needs to synchronize with Save, so the
	// container state update doesn't race with state serialization.
	go l.reap(initArgs.ContainerID, tg) // S/R-SAFE: see above.

	return nil
}

func (l *Lifecycle) reap(containerID string, tg *kernel.ThreadGroup) {
	tg.WaitExited()
	if err := l.updateContainerState(containerID, stateStopped); err != nil {
		panic(err)
	}
	eventchannel.LogEmit(&pb.ContainerExitEvent{
		ContainerId: containerID,
		ExitStatus:  uint32(tg.ExitStatus()),
	})
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
	ContainerID string `json:"container_id"`
}

// GetExitStatus returns the container exit status if it has stopped.
func (l *Lifecycle) GetExitStatus(args *ContainerArgs, status *uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.containerMap[args.ContainerID]
	if !ok {
		return fmt.Errorf("container %q doesn't exist, or has not been started", args.ContainerID)
	}

	if c.state != stateStopped {
		return fmt.Errorf("container %q hasn't exited yet", args.ContainerID)
	}

	*status = uint32(c.tg.ExitStatus())
	eventchannel.LogEmit(&pb.ContainerExitEvent{
		ContainerId: args.ContainerID,
		ExitStatus:  *status,
	})
	return nil
}

// Reap notifies the sandbox that the caller is interested in the exit status via
// an exit event. The caller is responsible for handling any corresponding exit
// events, especially if they're interested in waiting for the exit.
func (l *Lifecycle) Reap(args *ContainerArgs, _ *struct{}) error {
	// Check if there are any real emitters registered. If there are no
	// emitters, the caller will never be notified, so fail immediately.
	if !eventchannel.HaveEmitters() {
		return fmt.Errorf("no event emitters configured")
	}

	l.mu.Lock()

	c, ok := l.containerMap[args.ContainerID]
	if !ok {
		l.mu.Unlock()
		return fmt.Errorf("no container with id %q", args.ContainerID)
	}

	// Once a container enters the stop state, the state never changes. It's
	// safe to cache a stopped state outside a l.mu critical section.
	isStopped := c.state == stateStopped
	l.mu.Unlock()

	if isStopped {
		// Already stopped, emit stop to ensure any callbacks registered after
		// the actual stop is called. This may be a duplicate event, but is
		// necessary in case the reap goroutine transitions the container to the
		// stop state before the caller starts observing the event channel.
		eventchannel.LogEmit(&pb.ContainerExitEvent{
			ContainerId: args.ContainerID,
			ExitStatus:  uint32(c.tg.ExitStatus()),
		})
	}

	// Caller now responsible for blocking on the exit event.
	return nil
}

// IsContainerRunning returns true if the container is running.
func (l *Lifecycle) IsContainerRunning(args *ContainerArgs, isRunning *bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.containerMap[args.ContainerID]
	// We may be racing with the reaper goroutine updating c.state, so also
	// check the number non-exited tasks.
	if !ok || c.state != stateRunning || c.tg.Count() == 0 {
		return nil
	}

	*isRunning = true
	return nil
}

// SignalContainerArgs is the set of arguments for signalling a container.
type SignalContainerArgs struct {
	ContainerID string `json:"container_id"`
	Signo       int32  `json:"signo"`
	SignalAll   bool   `json:"signalAll"`
}

// SignalContainer signals the container in multi-container mode. It returns error if the
// container hasn't started or has exited.
func (l *Lifecycle) SignalContainer(args *SignalContainerArgs, _ *struct{}) error {
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
