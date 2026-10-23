// Copyright 2018 The gVisor Authors.
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

package sentryapi

import (
	"fmt"
	gtime "time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// ContMgrRootContainerStart starts a new sandbox with a root container.
const ContMgrRootContainerStart = "containerManager.StartRoot"

// ContMgrProcesses lists processes running in a container.
const ContMgrProcesses = "containerManager.Processes"

// ContMgrCreateSubcontainer creates a sub-container.
const ContMgrCreateSubcontainer = "containerManager.CreateSubcontainer"

// CreateArgs contains arguments to the Create method.
type CreateArgs struct {
	// CID is the ID of the container to start.
	CID string

	// FilePayload may contain a TTY file for the terminal, if enabled.
	urpc.FilePayload
}

// ContMgrStartSubcontainer starts a sub-container inside a running sandbox.
const ContMgrStartSubcontainer = "containerManager.StartSubcontainer"

// StartArgs contains arguments to the Start method.
type StartArgs struct {
	// Spec is the spec of the container to start.
	Spec *specs.Spec

	// Config is the runsc-specific configuration for the sandbox.
	Conf *config.Config

	// CID is the ID of the container to start.
	CID string

	// NumGoferFilestoreFDs is the number of gofer filestore FDs donated.
	NumGoferFilestoreFDs int

	// IsDevIoFilePresent indicates whether the dev gofer FD is present.
	IsDevIoFilePresent bool

	// GoferMountConfs contains information about how the gofer mounts have been
	// configured. The first entry is for rootfs and the following entries are
	// for bind mounts in Spec.Mounts (in the same order).
	GoferMountConfs []specutils.GoferMountConf

	// IsRootfsUpperTarFilePresent indicates whether the rootfs upper tar file is present.
	IsRootfsUpperTarFilePresent bool

	// FilePayload contains, in order:
	//   * stdin, stdout, and stderr (optional: if terminal is disabled).
	//   * file descriptors to gofer-backing host files (optional).
	//   * file descriptor for /dev gofer connection (optional)
	//   * file descriptor for rootfs upper tar file (optional)
	//   * file descriptors to connect to gofer to serve the root filesystem.
	urpc.FilePayload
}

// ContMgrDestroySubcontainer is used to stop a sub-container and free all
// associated resources in the sandbox.
const ContMgrDestroySubcontainer = "containerManager.DestroySubcontainer"

// ContMgrExecuteAsync executes a command in a container.
const ContMgrExecuteAsync = "containerManager.ExecuteAsync"

// ContMgrCheckpoint checkpoints a container.
const ContMgrCheckpoint = "containerManager.Checkpoint"

// ContMgrPortForward starts port forwarding with the sandbox.
const ContMgrPortForward = "containerManager.PortForward"

// PortForwardOpts contains options for port forwarding to a port in a
// container.
type PortForwardOpts struct {
	// FilePayload contains one fd for a UDS (or local port) used for port
	// forwarding.
	urpc.FilePayload

	// ContainerID is the container for the process being executed.
	ContainerID string
	// Port is the port to to forward.
	Port uint16
}

// ContMgrRestore restores a container from a statefile.
const ContMgrRestore = "containerManager.Restore"

// RestoreOpts contains options related to restoring a container's file system.
type RestoreOpts struct {
	// FilePayload contains, in order:
	// 1. checkpoint state file.
	// 2. optional checkpoint pages metadata file.
	// 3. optional checkpoint pages file.
	// 4. optional platform device file.
	urpc.FilePayload
	HavePagesFile  bool
	HaveDeviceFile bool
	Background     bool

	// If UseCheckpointGofer is true, the first file in FilePayload is a Unix
	// domain socket connected to a URPC server implementing
	// stateipc.AsyncFileServer and providing checkpoint files. In this case,
	// RestoreOpts.HavePagesFile is unknown and must be determined by
	// containerManager.Restore.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`

	// SplitFSRestore indicates if we should restore the filesystem from a
	// split filesystem checkpoint.
	SplitFSRestore bool `json:"split_fsrestore"`
}

// RestoreReply is the reply of ContMgrRestore and ContMgrRestoreSubcontainer.
type RestoreReply struct {
	// KernelStarted is set when the call restored the last container, which
	// starts the kernel.
	KernelStarted bool
}

// ContMgrRestoreSubcontainer restores a container from a statefile.
const ContMgrRestoreSubcontainer = "containerManager.RestoreSubcontainer"

// ContMgrPause pauses all tasks, blocking until they are stopped.
const ContMgrPause = "containerManager.Pause"

// ContMgrResume resumes all tasks.
const ContMgrResume = "containerManager.Resume"

// ContMgrWait waits on the init process of the container and returns its
// ExitStatus.
const ContMgrWait = "containerManager.Wait"

// ContMgrWaitPID waits on a process with a certain PID in the sandbox and
// return its ExitStatus.
const ContMgrWaitPID = "containerManager.WaitPID"

// WaitPIDArgs are arguments to the WaitPID method.
type WaitPIDArgs struct {
	// PID is the PID in the container's PID namespace.
	PID int32

	// CID is the container ID.
	CID string
}

// ContMgrWaitCheckpoint waits for the next Kernel checkpoint to complete.
const ContMgrWaitCheckpoint = "containerManager.WaitCheckpoint"

// ContMgrWaitRestore waits for the Kernel restore to complete.
const ContMgrWaitRestore = "containerManager.WaitRestore"

// ContMgrWaitFSCheckpoint waits for the next filesystem checkpoint save to
// complete.
const ContMgrWaitFSCheckpoint = "containerManager.WaitFSCheckpoint"

// ContMgrWaitFSRestore waits for filesystem checkpoint restore to complete
// for all current containers.
const ContMgrWaitFSRestore = "containerManager.WaitFSRestore"

// WaitFSRestoreArgs holds arguments to containerManager.WaitFSRestore.
type WaitFSRestoreArgs struct {
	// CID is the container ID.
	CID string
}

// ContMgrSignal sends a signal to a container.
const ContMgrSignal = "containerManager.Signal"

// SignalDeliveryMode enumerates different signal delivery modes.
type SignalDeliveryMode int

const (
	// DeliverToProcess delivers the signal to the container process with
	// the specified PID. If PID is 0, then the container init process is
	// signaled.
	DeliverToProcess SignalDeliveryMode = iota

	// DeliverToAllProcesses delivers the signal to all processes in the
	// container. PID must be 0.
	DeliverToAllProcesses

	// DeliverToForegroundProcessGroup delivers the signal to the
	// foreground process group in the same TTY session as the specified
	// process. If PID is 0, then the signal is delivered to the foreground
	// process group for the TTY for the init process.
	DeliverToForegroundProcessGroup

	// DeliverToProcessGroup delivers the signal to all processes in the
	// process group identified by a PGID.
	DeliverToProcessGroup
)

func (s SignalDeliveryMode) String() string {
	switch s {
	case DeliverToProcess:
		return "Process"
	case DeliverToAllProcesses:
		return "All"
	case DeliverToForegroundProcessGroup:
		return "Foreground Process Group"
	case DeliverToProcessGroup:
		return "Process Group"
	}
	return fmt.Sprintf("unknown signal delivery mode: %d", s)
}

// SignalArgs are arguments to the Signal method.
type SignalArgs struct {
	// CID is the container ID.
	CID string

	// Signo is the signal to send to the process.
	Signo int32

	// PID is the process ID in the given container that will be signaled,
	// relative to the root PID namespace, not the container's.
	// If 0, the root container will be signalled.
	PID int32

	// Mode is the signal delivery mode.
	Mode SignalDeliveryMode
}

// ContMgrCreateTraceSession starts a trace session.
const ContMgrCreateTraceSession = "containerManager.CreateTraceSession"

// CreateTraceSessionArgs are arguments to the CreateTraceSession method.
type CreateTraceSessionArgs struct {
	Config seccheck.SessionConfig
	Force  bool
	urpc.FilePayload
}

// ContMgrDeleteTraceSession deletes a trace session.
const ContMgrDeleteTraceSession = "containerManager.DeleteTraceSession"

// ContMgrListTraceSessions lists a trace session.
const ContMgrListTraceSessions = "containerManager.ListTraceSessions"

// ContMgrProcfsDump dumps sandbox procfs state.
const ContMgrProcfsDump = "containerManager.ProcfsDump"

// ContMgrMount mounts a filesystem in a container.
const ContMgrMount = "containerManager.Mount"

// MountArgs contains arguments to the Mount method.
type MountArgs struct {
	// ContainerID is the container in which we will mount the filesystem.
	ContainerID string

	// Source is the mount source.
	Source string

	// Destination is the mount target.
	Destination string

	// FsType is the filesystem type.
	FsType string

	// FilePayload contains the source image FD, if required by the filesystem.
	urpc.FilePayload
}

// ContMgrContainerRuntimeState returns the runtime state of a container.
const ContMgrContainerRuntimeState = "containerManager.ContainerRuntimeState"

// ContMgrFSSave saves a filesystem checkpoint.
const ContMgrFSSave = "containerManager.FSSave"

// FSSaveArgs holds arguments to FSSave.
type FSSaveArgs struct {
	// FilePayload contains the following fscheckpoint files in order:
	// 1. manifest file
	// 2. multi-tar file
	// 3. pages metadata file
	// 4. pages file
	urpc.FilePayload

	// Paths are the filesystem checkpoint bundles inside the containers to
	// save to the checkpoint.
	Paths []fscheckpoint.Bundle `json:"paths"`

	// Equivalent to kernel.FSSaveOpts fields.
	ExitAfterSaving bool `json:"exit_after_saving"`

	// If UseCheckpointGofer is true, FSSaveArgs.FilePayload should contain
	// exactly one FD, which is a Unix domain socket connected to a URPC server
	// implementing stateipc.AsyncFileServer.
	UseCheckpointGofer bool `json:"use_checkpoint_gofer"`
}

// ContMgrGetSavings gets the savings for restored sandboxes.
const ContMgrGetSavings = "containerManager.GetSavings"

// Savings holds the savings with restore.
type Savings struct {
	// CPUTimeSaved is the CPU time saved at restore.
	CPUTimeSaved gtime.Duration
	// WallTimeSaved is the wall time saved at restore.
	WallTimeSaved gtime.Duration
}

// ContMgrSetNetworkArgs sets network args in loader without creating links.
const ContMgrSetNetworkArgs = "containerManager.SetNetworkArgs"

// ContMgrGetNetworkConfig returns the network interfaces and routes applied
// during the creation of root container.
const ContMgrGetNetworkConfig = "containerManager.GetNetworkConfig"
