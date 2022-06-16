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

	// StartedCh is the channel used to send a message to the sentry that
	// all the containers in the sandbox have been started.
	StartedCh chan struct{}

	// mu protects the fields below.
	mu sync.RWMutex

	// containersStarted is the number of containers started in the sandbox.
	containersStarted int32

	// MountNamespacesMap is a map of container id/names and the mount
	// namespaces.
	MountNamespacesMap map[string]*vfs.MountNamespace
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
		PIDNamespace:            l.Kernel.RootPIDNamespace(),
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

	l.mu.Lock()
	numContainers := int32(len(l.MountNamespacesMap))

	// Start the newly created process.
	l.Kernel.StartProcess(tg)
	log.Infof("Started the new container %v ", l.containersStarted)
	l.containersStarted++
	if numContainers == l.containersStarted {
		l.StartedCh <- struct{}{}
	}
	l.mu.Unlock()
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
