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

// Package container creates and manipulates containers.
package container

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sighandling"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/console"
	"gvisor.dev/gvisor/runsc/donation"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

const cgroupParentAnnotation = "dev.gvisor.spec.cgroup-parent"

// validateID validates the container id.
func validateID(id string) error {
	// See libcontainer/factory_linux.go.
	idRegex := regexp.MustCompile(`^[\w+\.-]+$`)
	if !idRegex.MatchString(id) {
		return fmt.Errorf("invalid container id: %v", id)
	}
	return nil
}

// Container represents a containerized application. When running, the
// container is associated with a single Sandbox.
//
// Container metadata can be saved and loaded to disk. Within a root directory,
// we maintain subdirectories for each container named with the container id.
// The container metadata is stored as a json within the container directory
// in a file named "meta.json". This metadata format is defined by us and is
// not part of the OCI spec.
//
// Containers must write their metadata files after any change to their internal
// states. The entire container directory is deleted when the container is
// destroyed.
//
// When the container is stopped, all processes that belong to the container
// must be stopped before Destroy() returns. containerd makes roughly the
// following calls to stop a container:
//   - First it attempts to kill the container process with
//     'runsc kill SIGTERM'. After some time, it escalates to SIGKILL. In a
//     separate thread, it's waiting on the container. As soon as the wait
//     returns, it moves on to the next step:
//   - It calls 'runsc kill --all SIGKILL' to stop every process that belongs to
//     the container. 'kill --all SIGKILL' waits for all processes before
//     returning.
//   - Containerd waits for stdin, stdout and stderr to drain and be closed.
//   - It calls 'runsc delete'. runc implementation kills --all SIGKILL once
//     again just to be sure, waits, and then proceeds with remaining teardown.
//
// Container is thread-unsafe.
type Container struct {
	// ID is the container ID.
	ID string `json:"id"`

	// Spec is the OCI runtime spec that configures this container.
	Spec *specs.Spec `json:"spec"`

	// BundleDir is the directory containing the container bundle.
	BundleDir string `json:"bundleDir"`

	// CreatedAt is the time the container was created.
	CreatedAt time.Time `json:"createdAt"`

	// Owner is the container owner.
	Owner string `json:"owner"`

	// ConsoleSocket is the path to a unix domain socket that will receive
	// the console FD.
	ConsoleSocket string `json:"consoleSocket"`

	// Status is the current container Status.
	Status Status `json:"status"`

	// GoferPid is the PID of the gofer running along side the sandbox. May
	// be 0 if the gofer has been killed.
	GoferPid int `json:"goferPid"`

	// Sandbox is the sandbox this container is running in. It's set when the
	// container is created and reset when the sandbox is destroyed.
	Sandbox *sandbox.Sandbox `json:"sandbox"`

	// CompatCgroup has the cgroup configuration for the container. For the single
	// container case, container cgroup is set in `c.Sandbox` only. CompactCgroup
	// is only set for multi-container, where the `c.Sandbox` cgroup represents
	// the entire pod.
	//
	// Note that CompatCgroup is created only for compatibility with tools
	// that expect container cgroups to exist. Setting limits here makes no change
	// to the container in question.
	CompatCgroup cgroup.CgroupJSON `json:"compatCgroup"`

	// Saver handles load from/save to the state file safely from multiple
	// processes.
	Saver StateFile `json:"saver"`

	// OverlayConf is the overlay configuration with which this container was
	// started.
	OverlayConf config.Overlay2 `json:"overlayConf"`

	//
	// Fields below this line are not saved in the state file and will not
	// be preserved across commands.
	//

	// goferIsChild is set if a gofer process is a child of the current process.
	//
	// This field isn't saved to json, because only a creator of a gofer
	// process will have it as a child process.
	goferIsChild bool
}

// Args is used to configure a new container.
type Args struct {
	// ID is the container unique identifier.
	ID string

	// Spec is the OCI spec that describes the container.
	Spec *specs.Spec

	// BundleDir is the directory containing the container bundle.
	BundleDir string

	// ConsoleSocket is the path to a unix domain socket that will receive
	// the console FD. It may be empty.
	ConsoleSocket string

	// PIDFile is the filename where the container's root process PID will be
	// written to. It may be empty.
	PIDFile string

	// UserLog is the filename to send user-visible logs to. It may be empty.
	//
	// It only applies for the init container.
	UserLog string

	// Attached indicates that the sandbox lifecycle is attached with the caller.
	// If the caller exits, the sandbox should exit too.
	//
	// It only applies for the init container.
	Attached bool

	// PassFiles are user-supplied files from the host to be exposed to the
	// sandboxed app.
	PassFiles map[int]*os.File

	// ExecFile is the host file used for program execution.
	ExecFile *os.File
}

// New creates the container in a new Sandbox process, unless the metadata
// indicates that an existing Sandbox should be used. The caller must call
// Destroy() on the container.
func New(conf *config.Config, args Args) (*Container, error) {
	log.Debugf("Create container, cid: %s, rootDir: %q", args.ID, conf.RootDir)
	if err := validateID(args.ID); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(conf.RootDir, 0711); err != nil {
		return nil, fmt.Errorf("creating container root directory %q: %v", conf.RootDir, err)
	}

	if err := modifySpecForDirectfs(conf, args.Spec); err != nil {
		return nil, fmt.Errorf("failed to modify spec for directfs: %v", err)
	}

	sandboxID := args.ID
	if !isRoot(args.Spec) {
		var ok bool
		sandboxID, ok = specutils.SandboxID(args.Spec)
		if !ok {
			return nil, fmt.Errorf("no sandbox ID found when creating container")
		}
	}

	c := &Container{
		ID:            args.ID,
		Spec:          args.Spec,
		ConsoleSocket: args.ConsoleSocket,
		BundleDir:     args.BundleDir,
		Status:        Creating,
		CreatedAt:     time.Now(),
		Owner:         os.Getenv("USER"),
		Saver: StateFile{
			RootDir: conf.RootDir,
			ID: FullID{
				SandboxID:   sandboxID,
				ContainerID: args.ID,
			},
		},
		OverlayConf: conf.GetOverlay2(),
	}
	// The Cleanup object cleans up partially created containers when an error
	// occurs. Any errors occurring during cleanup itself are ignored.
	cu := cleanup.Make(func() { _ = c.Destroy() })
	defer cu.Clean()

	// Lock the container metadata file to prevent concurrent creations of
	// containers with the same id.
	if err := c.Saver.LockForNew(); err != nil {
		return nil, fmt.Errorf("cannot lock container metadata file: %w", err)
	}
	defer c.Saver.UnlockOrDie()

	// If the metadata annotations indicate that this container should be started
	// in an existing sandbox, we must do so. These are the possible metadata
	// annotation states:
	//   1. No annotations: it means that there is a single container and this
	//      container is obviously the root. Both container and sandbox share the
	//      ID.
	//   2. Container type == sandbox: it means this is the root container
	//  		starting the sandbox. Both container and sandbox share the same ID.
	//   3. Container type == container: it means this is a subcontainer of an
	//      already started sandbox. In this case, container ID is different than
	//      the sandbox ID.
	if isRoot(args.Spec) {
		log.Debugf("Creating new sandbox for container, cid: %s", args.ID)

		if args.Spec.Linux == nil {
			args.Spec.Linux = &specs.Linux{}
		}
		// Don't force the use of cgroups in tests because they lack permission to do so.
		if args.Spec.Linux.CgroupsPath == "" && !conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
			args.Spec.Linux.CgroupsPath = "/" + args.ID
		}
		var subCgroup, parentCgroup, containerCgroup cgroup.Cgroup
		if !conf.IgnoreCgroups {
			var err error

			// Create and join cgroup before processes are created to ensure they are
			// part of the cgroup from the start (and all their children processes).
			parentCgroup, subCgroup, err = c.setupCgroupForRoot(conf, args.Spec)
			if err != nil {
				return nil, fmt.Errorf("cannot set up cgroup for root: %w", err)
			}
			// Join the child cgroup when using cgroupfs. Joining non leaf-node
			// cgroups is illegal in cgroupsv2 and will return EBUSY.
			if subCgroup != nil && !conf.SystemdCgroup && cgroup.IsOnlyV2() {
				containerCgroup = subCgroup
			} else {
				containerCgroup = parentCgroup
			}
		}
		c.CompatCgroup = cgroup.CgroupJSON{Cgroup: subCgroup}
		overlayFilestoreFiles, err := c.createOverlayFilestores()
		if err != nil {
			return nil, err
		}
		if err := runInCgroup(containerCgroup, func() error {
			ioFiles, specFile, err := c.createGoferProcess(args.Spec, conf, args.BundleDir, args.Attached)
			if err != nil {
				return fmt.Errorf("cannot create gofer process: %w", err)
			}

			// Start a new sandbox for this container. Any errors after this point
			// must destroy the container.
			sandArgs := &sandbox.Args{
				ID:                    sandboxID,
				Spec:                  args.Spec,
				BundleDir:             args.BundleDir,
				ConsoleSocket:         args.ConsoleSocket,
				UserLog:               args.UserLog,
				IOFiles:               ioFiles,
				MountsFile:            specFile,
				Cgroup:                containerCgroup,
				Attached:              args.Attached,
				OverlayFilestoreFiles: overlayFilestoreFiles,
				PassFiles:             args.PassFiles,
				ExecFile:              args.ExecFile,
			}
			sand, err := sandbox.New(conf, sandArgs)
			if err != nil {
				return fmt.Errorf("cannot create sandbox: %w", err)
			}
			c.Sandbox = sand
			return nil

		}); err != nil {
			return nil, err
		}
	} else {
		log.Debugf("Creating new container, cid: %s, sandbox: %s", c.ID, sandboxID)

		// Find the sandbox associated with this ID.
		fullID := FullID{
			SandboxID:   sandboxID,
			ContainerID: sandboxID,
		}
		sb, err := Load(conf.RootDir, fullID, LoadOpts{Exact: true})
		if err != nil {
			return nil, fmt.Errorf("cannot load sandbox: %w", err)
		}
		c.Sandbox = sb.Sandbox

		subCgroup, err := c.setupCgroupForSubcontainer(conf, args.Spec)
		if err != nil {
			return nil, err
		}
		c.CompatCgroup = cgroup.CgroupJSON{Cgroup: subCgroup}

		// If the console control socket file is provided, then create a new
		// pty master/slave pair and send the TTY to the sandbox process.
		var tty *os.File
		if c.ConsoleSocket != "" {
			// Create a new TTY pair and send the master on the provided socket.
			var err error
			tty, err = console.NewWithSocket(c.ConsoleSocket)
			if err != nil {
				return nil, fmt.Errorf("setting up console with socket %q: %w", c.ConsoleSocket, err)
			}
			// tty file is transferred to the sandbox, then it can be closed here.
			defer tty.Close()
		}

		if err := c.Sandbox.CreateSubcontainer(conf, c.ID, tty); err != nil {
			return nil, fmt.Errorf("cannot create subcontainer: %w", err)
		}
	}
	c.changeStatus(Created)

	// Save the metadata file.
	if err := c.saveLocked(); err != nil {
		return nil, err
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil {
		// Even though the hook name is Prestart, runc used to call it from create.
		// For this reason, it's now deprecated, but the spec requires it to be
		// called *before* CreateRuntime and CreateRuntime must be called in create.
		//
		// "For runtimes that implement the deprecated prestart hooks as
		// createRuntime hooks, createRuntime hooks MUST be called after the
		// prestart hooks."
		if err := executeHooks(c.Spec.Hooks.Prestart, c.State()); err != nil {
			return nil, err
		}
		if err := executeHooks(c.Spec.Hooks.CreateRuntime, c.State()); err != nil {
			return nil, err
		}
		if len(c.Spec.Hooks.CreateContainer) > 0 {
			log.Warningf("CreateContainer hook skipped because running inside container namespace is not supported")
		}
	}

	// Write the PID file. Containerd considers the call to create complete after
	// this file is created, so it must be the last thing we do.
	if args.PIDFile != "" {
		if err := ioutil.WriteFile(args.PIDFile, []byte(strconv.Itoa(c.SandboxPid())), 0644); err != nil {
			return nil, fmt.Errorf("error writing PID file: %v", err)
		}
	}

	cu.Release()
	return c, nil
}

// Start starts running the containerized process inside the sandbox.
func (c *Container) Start(conf *config.Config) error {
	log.Debugf("Start container, cid: %s", c.ID)

	if err := c.Saver.lock(BlockAcquire); err != nil {
		return err
	}
	unlock := cleanup.Make(c.Saver.UnlockOrDie)
	defer unlock.Clean()

	if err := c.requireStatus("start", Created); err != nil {
		return err
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil && len(c.Spec.Hooks.StartContainer) > 0 {
		log.Warningf("StartContainer hook skipped because running inside container namespace is not supported")
	}

	if isRoot(c.Spec) {
		if err := c.Sandbox.StartRoot(c.Spec, conf); err != nil {
			return err
		}
	} else {
		// Create an overlay filestore for the subcontainer if its overlay is
		// backed by a host file.
		overlayFilestoreFiles, err := c.createOverlayFilestores()
		if err != nil {
			return err
		}
		// Join cgroup to start gofer process to ensure it's part of the cgroup from
		// the start (and all their children processes).
		if err := runInCgroup(c.Sandbox.CgroupJSON.Cgroup, func() error {
			// Create the gofer process.
			goferFiles, mountsFile, err := c.createGoferProcess(c.Spec, conf, c.BundleDir, false)
			if err != nil {
				return err
			}
			defer func() {
				_ = mountsFile.Close()
				for _, f := range goferFiles {
					_ = f.Close()
				}
			}()

			cleanMounts, err := specutils.ReadMounts(mountsFile)
			if err != nil {
				return fmt.Errorf("reading mounts file: %v", err)
			}
			c.Spec.Mounts = cleanMounts

			// Setup stdios if the container is not using terminal. Otherwise TTY was
			// already setup in create.
			var stdios []*os.File
			if !c.Spec.Process.Terminal {
				stdios = []*os.File{os.Stdin, os.Stdout, os.Stderr}
			}

			return c.Sandbox.StartSubcontainer(c.Spec, conf, c.ID, stdios, goferFiles, overlayFilestoreFiles)
		}); err != nil {
			return err
		}
	}

	// "If any poststart hook fails, the runtime MUST log a warning, but
	// the remaining hooks and lifecycle continue as if the hook had
	// succeeded" -OCI spec.
	if c.Spec.Hooks != nil {
		executeHooksBestEffort(c.Spec.Hooks.Poststart, c.State())
	}

	c.changeStatus(Running)
	if err := c.saveLocked(); err != nil {
		return err
	}

	// Release lock before adjusting OOM score because the lock is acquired there.
	unlock.Clean()

	// Adjust the oom_score_adj for sandbox. This must be done after saveLocked().
	if err := adjustSandboxOOMScoreAdj(c.Sandbox, c.Spec, c.Saver.RootDir, false); err != nil {
		return err
	}

	// Set container's oom_score_adj to the gofer since it is dedicated to
	// the container, in case the gofer uses up too much memory.
	return c.adjustGoferOOMScoreAdj()
}

// Restore takes a container and replaces its kernel and file system
// to restore a container from its state file.
func (c *Container) Restore(spec *specs.Spec, conf *config.Config, restoreFile string) error {
	log.Debugf("Restore container, cid: %s", c.ID)
	if err := c.Saver.lock(BlockAcquire); err != nil {
		return err
	}
	defer c.Saver.UnlockOrDie()

	if err := c.requireStatus("restore", Created); err != nil {
		return err
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil && len(c.Spec.Hooks.StartContainer) > 0 {
		log.Warningf("StartContainer hook skipped because running inside container namespace is not supported")
	}

	if err := c.Sandbox.Restore(c.ID, spec, conf, restoreFile); err != nil {
		return err
	}
	c.changeStatus(Running)
	return c.saveLocked()
}

// Run is a helper that calls Create + Start + Wait.
func Run(conf *config.Config, args Args) (unix.WaitStatus, error) {
	log.Debugf("Run container, cid: %s, rootDir: %q", args.ID, conf.RootDir)
	c, err := New(conf, args)
	if err != nil {
		return 0, fmt.Errorf("creating container: %v", err)
	}
	// Clean up partially created container if an error occurs.
	// Any errors returned by Destroy() itself are ignored.
	cu := cleanup.Make(func() {
		c.Destroy()
	})
	defer cu.Clean()

	if conf.RestoreFile != "" {
		log.Debugf("Restore: %v", conf.RestoreFile)
		if err := c.Restore(args.Spec, conf, conf.RestoreFile); err != nil {
			return 0, fmt.Errorf("starting container: %v", err)
		}
	} else {
		if err := c.Start(conf); err != nil {
			return 0, fmt.Errorf("starting container: %v", err)
		}
	}

	// If we allocate a terminal, forward signals to the sandbox process.
	// Otherwise, Ctrl+C will terminate this process and its children,
	// including the terminal.
	if c.Spec.Process.Terminal {
		stopForwarding := c.ForwardSignals(0, true /* fgProcess */)
		defer stopForwarding()
	}

	if args.Attached {
		return c.Wait()
	}
	cu.Release()
	return 0, nil
}

// Execute runs the specified command in the container. It returns the PID of
// the newly created process.
func (c *Container) Execute(conf *config.Config, args *control.ExecArgs) (int32, error) {
	log.Debugf("Execute in container, cid: %s, args: %+v", c.ID, args)
	if err := c.requireStatus("execute in", Created, Running); err != nil {
		return 0, err
	}
	args.ContainerID = c.ID
	return c.Sandbox.Execute(conf, args)
}

// Event returns events for the container.
func (c *Container) Event() (*boot.EventOut, error) {
	log.Debugf("Getting events for container, cid: %s", c.ID)
	if err := c.requireStatus("get events for", Created, Running, Paused); err != nil {
		return nil, err
	}
	event, err := c.Sandbox.Event(c.ID)
	if err != nil {
		return nil, err
	}

	// Some stats can utilize host cgroups for accuracy.
	c.populateStats(event)

	return event, nil
}

// PortForward starts port forwarding to the container.
func (c *Container) PortForward(opts *boot.PortForwardOpts) error {
	if err := c.requireStatus("port forward", Running); err != nil {
		return err
	}
	opts.ContainerID = c.ID
	return c.Sandbox.PortForward(opts)
}

// SandboxPid returns the Getpid of the sandbox the container is running in, or -1 if the
// container is not running.
func (c *Container) SandboxPid() int {
	if err := c.requireStatus("get PID", Created, Running, Paused); err != nil {
		return -1
	}
	return c.Sandbox.Getpid()
}

// Wait waits for the container to exit, and returns its WaitStatus.
// Call to wait on a stopped container is needed to retrieve the exit status
// and wait returns immediately.
func (c *Container) Wait() (unix.WaitStatus, error) {
	log.Debugf("Wait on container, cid: %s", c.ID)
	ws, err := c.Sandbox.Wait(c.ID)
	if err == nil {
		// Wait succeeded, container is not running anymore.
		c.changeStatus(Stopped)
	}
	return ws, err
}

// WaitRootPID waits for process 'pid' in the sandbox's PID namespace and
// returns its WaitStatus.
func (c *Container) WaitRootPID(pid int32) (unix.WaitStatus, error) {
	log.Debugf("Wait on process %d in sandbox, cid: %s", pid, c.Sandbox.ID)
	if !c.IsSandboxRunning() {
		return 0, fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.WaitPID(c.Sandbox.ID, pid)
}

// WaitPID waits for process 'pid' in the container's PID namespace and returns
// its WaitStatus.
func (c *Container) WaitPID(pid int32) (unix.WaitStatus, error) {
	log.Debugf("Wait on process %d in container, cid: %s", pid, c.ID)
	if !c.IsSandboxRunning() {
		return 0, fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.WaitPID(c.ID, pid)
}

// SignalContainer sends the signal to the container. If all is true and signal
// is SIGKILL, then waits for all processes to exit before returning.
// SignalContainer returns an error if the container is already stopped.
// TODO(b/113680494): Distinguish different error types.
func (c *Container) SignalContainer(sig unix.Signal, all bool) error {
	log.Debugf("Signal container, cid: %s, signal: %v (%d)", c.ID, sig, sig)
	// Signaling container in Stopped state is allowed. When all=false,
	// an error will be returned anyway; when all=true, this allows
	// sending signal to other processes inside the container even
	// after the init process exits. This is especially useful for
	// container cleanup.
	if err := c.requireStatus("signal", Running, Stopped); err != nil {
		return err
	}
	if !c.IsSandboxRunning() {
		return fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.SignalContainer(c.ID, sig, all)
}

// SignalProcess sends sig to a specific process in the container.
func (c *Container) SignalProcess(sig unix.Signal, pid int32) error {
	log.Debugf("Signal process %d in container, cid: %s, signal: %v (%d)", pid, c.ID, sig, sig)
	if err := c.requireStatus("signal a process inside", Running); err != nil {
		return err
	}
	if !c.IsSandboxRunning() {
		return fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.SignalProcess(c.ID, int32(pid), sig, false)
}

// ForwardSignals forwards all signals received by the current process to the
// container process inside the sandbox. It returns a function that will stop
// forwarding signals.
func (c *Container) ForwardSignals(pid int32, fgProcess bool) func() {
	log.Debugf("Forwarding all signals to container, cid: %s, PIDPID: %d, fgProcess: %t", c.ID, pid, fgProcess)
	stop := sighandling.StartSignalForwarding(func(sig linux.Signal) {
		log.Debugf("Forwarding signal %d to container, cid: %s, PID: %d, fgProcess: %t", sig, c.ID, pid, fgProcess)
		if err := c.Sandbox.SignalProcess(c.ID, pid, unix.Signal(sig), fgProcess); err != nil {
			log.Warningf("error forwarding signal %d to container %q: %v", sig, c.ID, err)
		}
	})
	return func() {
		log.Debugf("Done forwarding signals to container, cid: %s, PID: %d, fgProcess: %t", c.ID, pid, fgProcess)
		stop()
	}
}

// Checkpoint sends the checkpoint call to the container.
// The statefile will be written to f, the file at the specified image-path.
func (c *Container) Checkpoint(f *os.File) error {
	log.Debugf("Checkpoint container, cid: %s", c.ID)
	if err := c.requireStatus("checkpoint", Created, Running, Paused); err != nil {
		return err
	}
	return c.Sandbox.Checkpoint(c.ID, f)
}

// Pause suspends the container and its kernel.
// The call only succeeds if the container's status is created or running.
func (c *Container) Pause() error {
	log.Debugf("Pausing container, cid: %s", c.ID)
	if err := c.Saver.lock(BlockAcquire); err != nil {
		return err
	}
	defer c.Saver.UnlockOrDie()

	if c.Status != Created && c.Status != Running {
		return fmt.Errorf("cannot pause container %q in state %v", c.ID, c.Status)
	}

	if err := c.Sandbox.Pause(c.ID); err != nil {
		return fmt.Errorf("pausing container %q: %v", c.ID, err)
	}
	c.changeStatus(Paused)
	return c.saveLocked()
}

// Resume unpauses the container and its kernel.
// The call only succeeds if the container's status is paused.
func (c *Container) Resume() error {
	log.Debugf("Resuming container, cid: %s", c.ID)
	if err := c.Saver.lock(BlockAcquire); err != nil {
		return err
	}
	defer c.Saver.UnlockOrDie()

	if c.Status != Paused {
		return fmt.Errorf("cannot resume container %q in state %v", c.ID, c.Status)
	}
	if err := c.Sandbox.Resume(c.ID); err != nil {
		return fmt.Errorf("resuming container: %v", err)
	}
	c.changeStatus(Running)
	return c.saveLocked()
}

// State returns the metadata of the container.
func (c *Container) State() specs.State {
	return specs.State{
		Version:     specs.Version,
		ID:          c.ID,
		Status:      c.Status,
		Pid:         c.SandboxPid(),
		Bundle:      c.BundleDir,
		Annotations: c.Spec.Annotations,
	}
}

// Processes retrieves the list of processes and associated metadata inside a
// container.
func (c *Container) Processes() ([]*control.Process, error) {
	if err := c.requireStatus("get processes of", Running, Paused); err != nil {
		return nil, err
	}
	return c.Sandbox.Processes(c.ID)
}

// Destroy stops all processes and frees all resources associated with the
// container.
func (c *Container) Destroy() error {
	log.Debugf("Destroy container, cid: %s", c.ID)

	if err := c.Saver.lock(BlockAcquire); err != nil {
		return err
	}
	defer func() {
		c.Saver.UnlockOrDie()
		_ = c.Saver.close()
	}()

	// Stored for later use as stop() sets c.Sandbox to nil.
	sb := c.Sandbox

	// We must perform the following cleanup steps:
	//	* stop the container and gofer processes,
	//	* remove the container filesystem on the host, and
	//	* delete the container metadata directory.
	//
	// It's possible for one or more of these steps to fail, but we should
	// do our best to perform all of the cleanups. Hence, we keep a slice
	// of errors return their concatenation.
	var errs []string
	if err := c.stop(); err != nil {
		err = fmt.Errorf("stopping container: %v", err)
		log.Warningf("%v", err)
		errs = append(errs, err.Error())
	}

	if err := c.Saver.Destroy(); err != nil {
		err = fmt.Errorf("deleting container state files: %v", err)
		log.Warningf("%v", err)
		errs = append(errs, err.Error())
	}

	if c.OverlayConf.IsBackedBySelf() {
		// Clean up overlay filestore files created in their respective mounts.
		c.forEachOverlayMount(func(mountSrc string) error {
			// Persevere through errors. Always return nil. A non-nil error will halt
			// forEachOverlayMount(). But we want to clean up as much as we can.
			mountSrcInfo, err := os.Stat(mountSrc)
			if err != nil {
				err = fmt.Errorf("failed to stat mount %q to see if it were a dirctory: %v", mountSrc, err)
				log.Warningf("%v", err)
				errs = append(errs, err.Error())
				return nil
			}
			// mountSrc only contains the filestore file if it is a directory.
			if !mountSrcInfo.IsDir() {
				return nil
			}
			filestorePath := boot.SelfOverlayFilestorePath(mountSrc, c.sandboxID())
			if err := os.Remove(filestorePath); err != nil {
				err = fmt.Errorf("failed to delete filestore file %q: %v", filestorePath, err)
				log.Warningf("%v", err)
				errs = append(errs, err.Error())
			}
			return nil
		})
	}

	c.changeStatus(Stopped)

	// Adjust oom_score_adj for the sandbox. This must be done after the container
	// is stopped and the directory at c.Root is removed.
	//
	// Use 'sb' to tell whether it has been executed before because Destroy must
	// be idempotent.
	if sb != nil {
		if err := adjustSandboxOOMScoreAdj(sb, c.Spec, c.Saver.RootDir, true); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// "If any poststop hook fails, the runtime MUST log a warning, but the
	// remaining hooks and lifecycle continue as if the hook had
	// succeeded" - OCI spec.
	//
	// Based on the OCI, "The post-stop hooks MUST be called after the container
	// is deleted but before the delete operation returns"
	// Run it here to:
	// 1) Conform to the OCI.
	// 2) Make sure it only runs once, because the root has been deleted, the
	// container can't be loaded again.
	if c.Spec.Hooks != nil {
		executeHooksBestEffort(c.Spec.Hooks.Poststop, c.State())
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(errs, "\n"))
}

func (c *Container) sandboxID() string {
	return c.Saver.ID.SandboxID
}

// createOverlayFilestores creates the regular files that will back the tmpfs
// upper mount for overlay mounts. It may return (nil, nil) if overlay is not
// configured to be backed by host files.
func (c *Container) createOverlayFilestores() ([]*os.File, error) {
	if !c.OverlayConf.IsBackedByHostFile() {
		return nil, nil
	}
	var (
		filestoreFiles []*os.File
		err            error
	)
	if c.OverlayConf.IsBackedBySelf() {
		filestoreFiles, err = c.createOverlayFilestoreInSelf()
	} else {
		filestoreFiles, err = c.createOverlayFilestoreInDir()
	}
	if err != nil {
		return nil, err
	}
	for _, f := range filestoreFiles {
		// Perform this work around outside the sandbox. The sandbox may already be
		// running with seccomp filters that do not allow this.
		pgalloc.IMAWorkAroundForMemFile(f.Fd())
	}
	return filestoreFiles, nil
}

// Precondition: Overlay2.IsBackedByHostFile() && Overlay2.IsBackedBySelf().
func (c *Container) createOverlayFilestoreInSelf() ([]*os.File, error) {
	var filestoreFiles []*os.File
	err := c.forEachOverlayMount(func(mountSrc string) error {
		mountSrcInfo, err := os.Stat(mountSrc)
		if err != nil {
			return fmt.Errorf("failed to stat mount %q to see if it were a dirctory: %v", mountSrc, err)
		}
		if !mountSrcInfo.IsDir() {
			log.Warningf("overlay2 self medium is only supported for directory mounts, but mount %q is not a directory, falling back to memory", mountSrc)
			return nil
		}
		// Create the self overlay filestore file.
		filestorePath := boot.SelfOverlayFilestorePath(mountSrc, c.sandboxID())
		filestoreFD, err := unix.Open(filestorePath, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, 0666)
		if err != nil {
			if err == unix.EEXIST {
				// Note that if the same submount is mounted multiple times within the
				// same sandbox, then the overlay option doesn't work correctly.
				// Because each overlay mount is independent and changes to one are not
				// visible to the other. Given "overlay on repeated submounts" is
				// already broken, we don't support such a scenario with the self
				// medium. The filestore file will already exist for such a case.
				return fmt.Errorf("%q mount source already has a filestore file at %q; repeated submounts are not suppported with self medium", mountSrc, filestorePath)
			}
			return fmt.Errorf("failed to create filestore file inside %q: %v", mountSrc, err)
		}
		// Filestore in self should be a named path because it needs to be
		// discoverable via path traversal so that k8s can scan the filesystem
		// and apply any limits appropriately (like local ephemeral storage
		// limits). So don't delte it. These files will be unlinked when the
		// container is destroyed. This makes self medium appropriate for k8s.
		filestoreFiles = append(filestoreFiles, os.NewFile(uintptr(filestoreFD), filestorePath))
		return nil
	})
	return filestoreFiles, err
}

// Precondition: Overlay2.IsBackedByHostFile() && !Overlay2.IsBackedBySelf().
func (c *Container) createOverlayFilestoreInDir() ([]*os.File, error) {
	filestoreDir := c.OverlayConf.HostFileDir()
	fileInfo, err := os.Stat(filestoreDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat overlay filestore directory %q: %v", filestoreDir, err)
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("overlay2 flag should specify an existing directory")
	}
	var filestoreFiles []*os.File
	if err := c.forEachOverlayMount(func(_ string) error {
		// Create an unnamed temporary file in filestore directory which will be
		// deleted when the last FD on it is closed. We don't use O_TMPFILE because
		// it is not supported on all filesystems. So we simulate it by creating a
		// named file and then immediately unlinking it while keeping an FD on it.
		// This file will be deleted when the container exits.
		filestoreFile, err := os.CreateTemp(filestoreDir, "runsc-overlay-filestore-")
		if err != nil {
			return fmt.Errorf("failed to create a temporary file inside %q: %v", filestoreDir, err)
		}
		if err := unix.Unlink(filestoreFile.Name()); err != nil {
			return fmt.Errorf("failed to unlink temporary file %q: %v", filestoreFile.Name(), err)
		}
		filestoreFiles = append(filestoreFiles, filestoreFile)
		return nil
	}); err != nil {
		return nil, err
	}
	return filestoreFiles, nil
}

// forEachOverlayMount calls fn on all mounts that runsc/boot/vfs.go will
// configure filestore-based overlays on. See containerMounter.configureOverlay().
//
// Precondition: Overlay2.IsBackedByHostFile().
func (c *Container) forEachOverlayMount(fn func(srcDir string) error) error {
	if c.OverlayConf.RootMount && !c.Spec.Root.Readonly {
		if err := fn(c.Spec.Root.Path); err != nil {
			return err
		}
	}
	if !c.OverlayConf.SubMounts {
		return nil
	}
	for i := range c.Spec.Mounts {
		if c.Spec.Mounts[i].Type != boot.Bind {
			continue
		}
		if boot.ParseMountOptions(c.Spec.Mounts[i].Options).ReadOnly {
			continue
		}
		mountSrc := c.Spec.Mounts[i].Source
		if err := fn(mountSrc); err != nil {
			return err
		}
	}
	return nil
}

// saveLocked saves the container metadata to a file.
//
// Precondition: container must be locked with container.lock().
func (c *Container) saveLocked() error {
	log.Debugf("Save container, cid: %s", c.ID)
	if err := c.Saver.SaveLocked(c); err != nil {
		return fmt.Errorf("saving container metadata: %v", err)
	}
	return nil
}

// stop stops the container (for regular containers) or the sandbox (for
// root containers), and waits for the container or sandbox and the gofer
// to stop. If any of them doesn't stop before timeout, an error is returned.
func (c *Container) stop() error {
	var parentCgroup cgroup.Cgroup

	if c.Sandbox != nil {
		log.Debugf("Destroying container, cid: %s", c.ID)
		if err := c.Sandbox.DestroyContainer(c.ID); err != nil {
			return fmt.Errorf("destroying container %q: %v", c.ID, err)
		}
		// Only uninstall parentCgroup for sandbox stop.
		if c.Sandbox.IsRootContainer(c.ID) {
			parentCgroup = c.Sandbox.CgroupJSON.Cgroup
		}
		// Only set sandbox to nil after it has been told to destroy the container.
		c.Sandbox = nil
	}

	// Try killing gofer if it does not exit with container.
	if c.GoferPid != 0 {
		log.Debugf("Killing gofer for container, cid: %s, PID: %d", c.ID, c.GoferPid)
		if err := unix.Kill(c.GoferPid, unix.SIGKILL); err != nil {
			// The gofer may already be stopped, log the error.
			log.Warningf("Error sending signal %d to gofer %d: %v", unix.SIGKILL, c.GoferPid, err)
		}
	}

	if err := c.waitForStopped(); err != nil {
		return err
	}

	// Delete container cgroup if any.
	if c.CompatCgroup.Cgroup != nil {
		if err := c.CompatCgroup.Cgroup.Uninstall(); err != nil {
			return err
		}
	}
	// Gofer is running inside parentCgroup, so Cgroup.Uninstall has to be called
	// after the gofer has stopped.
	if parentCgroup != nil {
		if err := parentCgroup.Uninstall(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Container) waitForStopped() error {
	if c.GoferPid == 0 {
		return nil
	}

	if c.IsSandboxRunning() {
		if err := c.SignalContainer(unix.Signal(0), false); err == nil {
			return fmt.Errorf("container is still running")
		}
	}

	if c.goferIsChild {
		// The gofer process is a child of the current process,
		// so we can wait it and collect its zombie.
		if _, err := unix.Wait4(int(c.GoferPid), nil, 0, nil); err != nil {
			return fmt.Errorf("error waiting the gofer process: %v", err)
		}
		c.GoferPid = 0
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
	op := func() error {
		if err := unix.Kill(c.GoferPid, 0); err == nil {
			return fmt.Errorf("gofer is still running")
		}
		c.GoferPid = 0
		return nil
	}
	return backoff.Retry(op, b)
}

func (c *Container) createGoferProcess(spec *specs.Spec, conf *config.Config, bundleDir string, attached bool) ([]*os.File, *os.File, error) {
	donations := donation.Agency{}
	defer donations.Close()

	if err := donations.OpenAndDonate("log-fd", conf.LogFilename, os.O_CREATE|os.O_WRONLY|os.O_APPEND); err != nil {
		return nil, nil, err
	}
	if conf.DebugLog != "" {
		test := ""
		if len(conf.TestOnlyTestNameEnv) != 0 {
			// Fetch test name if one is provided and the test only flag was set.
			if t, ok := specutils.EnvVar(spec.Process.Env, conf.TestOnlyTestNameEnv); ok {
				test = t
			}
		}
		if specutils.IsDebugCommand(conf, "gofer") {
			if err := donations.DonateDebugLogFile("debug-log-fd", conf.DebugLog, "gofer", test); err != nil {
				return nil, nil, err
			}
		}
	}

	// Start with the general config flags.
	cmd := exec.Command(specutils.ExePath, conf.ToFlags()...)
	cmd.SysProcAttr = &unix.SysProcAttr{
		// Detach from session. Otherwise, signals sent to the foreground process
		// will also be forwarded by this process, resulting in duplicate signals.
		Setsid: true,
	}

	// Set Args[0] to make easier to spot the gofer process. Otherwise it's
	// shown as `exe`.
	cmd.Args[0] = "runsc-gofer"

	// Tranfer FDs that need to be present before the "gofer" command.
	// Start at 3 because 0, 1, and 2 are taken by stdin/out/err.
	nextFD := donations.Transfer(cmd, 3)

	cmd.Args = append(cmd.Args, "gofer", "--bundle", bundleDir)

	// Open the spec file to donate to the sandbox.
	specFile, err := specutils.OpenSpec(bundleDir)
	if err != nil {
		return nil, nil, fmt.Errorf("opening spec file: %v", err)
	}
	donations.DonateAndClose("spec-fd", specFile)

	// Donate any profile FDs to the gofer.
	if err := c.donateGoferProfileFDs(conf, &donations); err != nil {
		return nil, nil, fmt.Errorf("donating gofer profile fds: %w", err)
	}

	// Create pipe that allows gofer to send mount list to sandbox after all paths
	// have been resolved.
	mountsSand, mountsGofer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	donations.DonateAndClose("mounts-fd", mountsGofer)

	// Add root mount and then add any other additional mounts.
	mountCount := 1
	for _, m := range spec.Mounts {
		if specutils.IsGoferMount(m) {
			mountCount++
		}
	}

	sandEnds := make([]*os.File, 0, mountCount)
	for i := 0; i < mountCount; i++ {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		sandEnds = append(sandEnds, os.NewFile(uintptr(fds[0]), "sandbox IO FD"))

		goferEnd := os.NewFile(uintptr(fds[1]), "gofer IO FD")
		donations.DonateAndClose("io-fds", goferEnd)
	}

	if attached {
		// The gofer is attached to the lifetime of this process, so it
		// should synchronously die when this process dies.
		cmd.SysProcAttr.Pdeathsig = unix.SIGKILL
	}

	// Enter new namespaces to isolate from the rest of the system. Don't unshare
	// cgroup because gofer is added to a cgroup in the caller's namespace.
	nss := []specs.LinuxNamespace{
		{Type: specs.IPCNamespace},
		{Type: specs.MountNamespace},
		{Type: specs.NetworkNamespace},
		{Type: specs.PIDNamespace},
		{Type: specs.UTSNamespace},
	}

	rootlessEUID := unix.Getuid() != 0
	// Setup any uid/gid mappings, and create or join the configured user
	// namespace so the gofer's view of the filesystem aligns with the
	// users in the sandbox.
	if !rootlessEUID {
		userNS := specutils.FilterNS([]specs.LinuxNamespaceType{specs.UserNamespace}, spec)
		nss = append(nss, userNS...)
		specutils.SetUIDGIDMappings(cmd, spec)
		if len(userNS) != 0 {
			// We need to set UID and GID to have capabilities in a new user namespace.
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
		}
	} else {
		userNS := specutils.FilterNS([]specs.LinuxNamespaceType{specs.UserNamespace}, spec)
		if len(userNS) == 0 {
			return nil, nil, fmt.Errorf("unable to run a rootless container without userns")
		}
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		syncFile := os.NewFile(uintptr(fds[0]), "sync FD")
		defer syncFile.Close()

		f := os.NewFile(uintptr(fds[1]), "sync other FD")
		donations.DonateAndClose("sync-userns-fd", f)
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &unix.SysProcAttr{}
		}
		cmd.SysProcAttr.AmbientCaps = []uintptr{
			unix.CAP_CHOWN,
			unix.CAP_DAC_OVERRIDE,
			unix.CAP_DAC_READ_SEARCH,
			unix.CAP_FOWNER,
			unix.CAP_FSETID,
			unix.CAP_SYS_CHROOT,
			unix.CAP_SETUID,
			unix.CAP_SETGID,
			unix.CAP_SYS_ADMIN,
			unix.CAP_SETPCAP,
		}
		nss = append(nss, specs.LinuxNamespace{Type: specs.UserNamespace})
	}

	donations.Transfer(cmd, nextFD)

	// Start the gofer in the given namespace.
	donation.LogDonations(cmd)
	log.Debugf("Starting gofer: %s %v", cmd.Path, cmd.Args)
	if err := specutils.StartInNS(cmd, nss); err != nil {
		return nil, nil, fmt.Errorf("gofer: %v", err)
	}

	if rootlessEUID {
		log.Debugf("Setting user mappings")
		args := []string{strconv.Itoa(cmd.Process.Pid)}
		for _, idMap := range spec.Linux.UIDMappings {
			log.Infof("Mapping host uid %d to container uid %d (size=%d)",
				idMap.HostID, idMap.ContainerID, idMap.Size)
			args = append(args,
				strconv.Itoa(int(idMap.ContainerID)),
				strconv.Itoa(int(idMap.HostID)),
				strconv.Itoa(int(idMap.Size)),
			)
		}

		out, err := exec.Command("newuidmap", args...).CombinedOutput()
		log.Debugf("newuidmap: %#v\n%s", args, out)
		if err != nil {
			return nil, nil, fmt.Errorf("newuidmap failed: %w", err)
		}

		args = []string{strconv.Itoa(cmd.Process.Pid)}
		for _, idMap := range spec.Linux.GIDMappings {
			log.Infof("Mapping host uid %d to container uid %d (size=%d)",
				idMap.HostID, idMap.ContainerID, idMap.Size)
			args = append(args,
				strconv.Itoa(int(idMap.ContainerID)),
				strconv.Itoa(int(idMap.HostID)),
				strconv.Itoa(int(idMap.Size)),
			)
		}
		out, err = exec.Command("newgidmap", args...).CombinedOutput()
		log.Debugf("newgidmap: %#v\n%s", args, out)
		if err != nil {
			return nil, nil, fmt.Errorf("newgidmap failed: %w", err)
		}
	}

	log.Infof("Gofer started, PID: %d", cmd.Process.Pid)
	c.GoferPid = cmd.Process.Pid
	c.goferIsChild = true
	return sandEnds, mountsSand, nil
}

// changeStatus transitions from one status to another ensuring that the
// transition is valid.
func (c *Container) changeStatus(s Status) {
	switch s {
	case Creating:
		// Initial state, never transitions to it.
		panic(fmt.Sprintf("invalid state transition: %v => %v", c.Status, s))

	case Created:
		if c.Status != Creating {
			panic(fmt.Sprintf("invalid state transition: %v => %v", c.Status, s))
		}
		if c.Sandbox == nil {
			panic("sandbox cannot be nil")
		}

	case Paused:
		if c.Status != Running {
			panic(fmt.Sprintf("invalid state transition: %v => %v", c.Status, s))
		}
		if c.Sandbox == nil {
			panic("sandbox cannot be nil")
		}

	case Running:
		if c.Status != Created && c.Status != Paused {
			panic(fmt.Sprintf("invalid state transition: %v => %v", c.Status, s))
		}
		if c.Sandbox == nil {
			panic("sandbox cannot be nil")
		}

	case Stopped:
		if c.Status != Creating && c.Status != Created && c.Status != Running && c.Status != Stopped {
			panic(fmt.Sprintf("invalid state transition: %v => %v", c.Status, s))
		}

	default:
		panic(fmt.Sprintf("invalid new state: %v", s))
	}
	c.Status = s
}

// IsSandboxRunning returns true if the sandbox exists and is running.
func (c *Container) IsSandboxRunning() bool {
	return c.Sandbox != nil && c.Sandbox.IsRunning()
}

func (c *Container) requireStatus(action string, statuses ...Status) error {
	for _, s := range statuses {
		if c.Status == s {
			return nil
		}
	}
	return fmt.Errorf("cannot %s container %q in state %s", action, c.ID, c.Status)
}

func isRoot(spec *specs.Spec) bool {
	return specutils.SpecContainerType(spec) != specutils.ContainerTypeContainer
}

// runInCgroup executes fn inside the specified cgroup. If cg is nil, execute
// it in the current context.
func runInCgroup(cg cgroup.Cgroup, fn func() error) error {
	if cg == nil {
		return fn()
	}
	restore, err := cg.Join()
	if err != nil {
		return err
	}
	defer restore()
	return fn()
}

// adjustGoferOOMScoreAdj sets the oom_store_adj for the container's gofer.
func (c *Container) adjustGoferOOMScoreAdj() error {
	if c.GoferPid == 0 || c.Spec.Process.OOMScoreAdj == nil {
		return nil
	}
	return setOOMScoreAdj(c.GoferPid, *c.Spec.Process.OOMScoreAdj)
}

// adjustSandboxOOMScoreAdj sets the oom_score_adj for the sandbox.
// oom_score_adj is set to the lowest oom_score_adj among the containers
// running in the sandbox.
//
// TODO(gvisor.dev/issue/238): This call could race with other containers being
// created at the same time and end up setting the wrong oom_score_adj to the
// sandbox. Use rpc client to synchronize.
func adjustSandboxOOMScoreAdj(s *sandbox.Sandbox, spec *specs.Spec, rootDir string, destroy bool) error {
	// Adjustment can be skipped if the root container is exiting, because it
	// brings down the entire sandbox.
	if isRoot(spec) && destroy {
		return nil
	}

	containers, err := loadSandbox(rootDir, s.ID)
	if err != nil {
		return fmt.Errorf("loading sandbox containers: %v", err)
	}

	// Do nothing if the sandbox has been terminated.
	if len(containers) == 0 {
		return nil
	}

	// Get the lowest score for all containers.
	var lowScore int
	scoreFound := false
	for _, container := range containers {
		// Special multi-container support for CRI. Ignore the root container when
		// calculating oom_score_adj for the sandbox because it is the
		// infrastructure (pause) container and always has a very low oom_score_adj.
		//
		// We will use OOMScoreAdj in the single-container case where the
		// containerd container-type annotation is not present.
		if specutils.SpecContainerType(container.Spec) == specutils.ContainerTypeSandbox {
			continue
		}

		if container.Spec.Process.OOMScoreAdj != nil && (!scoreFound || *container.Spec.Process.OOMScoreAdj < lowScore) {
			scoreFound = true
			lowScore = *container.Spec.Process.OOMScoreAdj
		}
	}

	// If the container is destroyed and remaining containers have no
	// oomScoreAdj specified then we must revert to the original oom_score_adj
	// saved with the root container.
	if !scoreFound && destroy {
		lowScore = containers[0].Sandbox.OriginalOOMScoreAdj
		scoreFound = true
	}

	// Only set oom_score_adj if one of the containers has oom_score_adj set. If
	// not, oom_score_adj is inherited from the parent process.
	//
	// See: https://github.com/opencontainers/runtime-spec/blob/master/config.md#linux-process
	if !scoreFound {
		return nil
	}

	// Set the lowest of all containers oom_score_adj to the sandbox.
	return setOOMScoreAdj(s.Getpid(), lowScore)
}

// setOOMScoreAdj sets oom_score_adj to the given value for the given PID.
// /proc must be available and mounted read-write. scoreAdj should be between
// -1000 and 1000. It's a noop if the process has already exited.
func setOOMScoreAdj(pid int, scoreAdj int) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), os.O_WRONLY, 0644)
	if err != nil {
		// Ignore NotExist errors because it can race with process exit.
		if os.IsNotExist(err) {
			log.Warningf("Process (%d) not found setting oom_score_adj", pid)
			return nil
		}
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(strconv.Itoa(scoreAdj)); err != nil {
		if errors.Is(err, unix.ESRCH) {
			log.Warningf("Process (%d) exited while setting oom_score_adj", pid)
			return nil
		}
		return fmt.Errorf("setting oom_score_adj to %q: %v", scoreAdj, err)
	}
	return nil
}

// populateStats populates event with stats estimates based on cgroups and the
// sentry's accounting.
// TODO(gvisor.dev/issue/172): This is an estimation; we should do more
// detailed accounting.
func (c *Container) populateStats(event *boot.EventOut) {
	// The events command, when run for all running containers, should
	// account for the full cgroup CPU usage. We split cgroup usage
	// proportionally according to the sentry-internal usage measurements,
	// only counting Running containers.
	log.Debugf("event.ContainerUsage: %v", event.ContainerUsage)
	var containerUsage uint64
	var allContainersUsage uint64
	for ID, usage := range event.ContainerUsage {
		allContainersUsage += usage
		if ID == c.ID {
			containerUsage = usage
		}
	}

	cgroup, err := c.Sandbox.NewCGroup()
	if err != nil {
		// No cgroup, so rely purely on the sentry's accounting.
		log.Warningf("events: no cgroups")
		event.Event.Data.CPU.Usage.Total = containerUsage
		return
	}

	// Get the host cgroup CPU usage.
	cgroupsUsage, err := cgroup.CPUUsage()
	if err != nil {
		// No cgroup usage, so rely purely on the sentry's accounting.
		log.Warningf("events: failed when getting cgroup CPU usage for container: %v", err)
		event.Event.Data.CPU.Usage.Total = containerUsage
		return
	}

	// If the sentry reports no CPU usage, fall back on cgroups and split usage
	// equally across containers.
	if allContainersUsage == 0 {
		log.Warningf("events: no sentry CPU usage reported")
		allContainersUsage = cgroupsUsage
		containerUsage = cgroupsUsage / uint64(len(event.ContainerUsage))
	}

	// Scaling can easily overflow a uint64 (e.g. a containerUsage and
	// cgroupsUsage of 16 seconds each will overflow), so use floats.
	total := float64(containerUsage) * (float64(cgroupsUsage) / float64(allContainersUsage))
	log.Debugf("Usage, container: %d, cgroups: %d, all: %d, total: %.0f", containerUsage, cgroupsUsage, allContainersUsage, total)
	event.Event.Data.CPU.Usage.Total = uint64(total)
	return
}

// setupCgroupForRoot configures and returns cgroup for the sandbox and the
// root container. If `cgroupParentAnnotation` is set, use that path as the
// sandbox cgroup and use Spec.Linux.CgroupsPath as the root container cgroup.
func (c *Container) setupCgroupForRoot(conf *config.Config, spec *specs.Spec) (cgroup.Cgroup, cgroup.Cgroup, error) {
	var parentCgroup cgroup.Cgroup
	if parentPath, ok := spec.Annotations[cgroupParentAnnotation]; ok {
		var err error
		parentCgroup, err = cgroup.NewFromPath(parentPath, conf.SystemdCgroup)
		if err != nil {
			return nil, nil, err
		}
	} else {
		var err error
		parentCgroup, err = cgroup.NewFromSpec(spec, conf.SystemdCgroup)
		if parentCgroup == nil || err != nil {
			return nil, nil, err
		}
	}

	var err error
	parentCgroup, err = cgroupInstall(conf, parentCgroup, spec.Linux.Resources)
	if parentCgroup == nil || err != nil {
		return nil, nil, err
	}

	subCgroup, err := c.setupCgroupForSubcontainer(conf, spec)
	if err != nil {
		_ = parentCgroup.Uninstall()
		return nil, nil, err
	}
	return parentCgroup, subCgroup, nil
}

// setupCgroupForSubcontainer sets up empty cgroups for subcontainers. Since
// subcontainers run exclusively inside the sandbox, subcontainer cgroups on the
// host have no effect on them. However, some tools (e.g. cAdvisor) uses cgroups
// paths to discover new containers and report stats for them.
func (c *Container) setupCgroupForSubcontainer(conf *config.Config, spec *specs.Spec) (cgroup.Cgroup, error) {
	if isRoot(spec) {
		if _, ok := spec.Annotations[cgroupParentAnnotation]; !ok {
			return nil, nil
		}
	}

	cg, err := cgroup.NewFromSpec(spec, conf.SystemdCgroup)
	if cg == nil || err != nil {
		return nil, err
	}
	// Use empty resources, just want the directory structure created.
	return cgroupInstall(conf, cg, &specs.LinuxResources{})
}

// donateGoferProfileFDs will open profile files and donate their FDs to the
// gofer.
func (c *Container) donateGoferProfileFDs(conf *config.Config, donations *donation.Agency) error {
	// The gofer profile files are named based on the provided flag, but
	// suffixed with "gofer" and the container ID to avoid collisions with
	// sentry profile files or profile files from other gofers.
	//
	// TODO(b/243183772): Merge gofer profile data with sentry profile data
	// into a single file.
	profSuffix := ".gofer." + c.ID
	const profFlags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if conf.ProfileBlock != "" {
		if err := donations.OpenAndDonate("profile-block-fd", conf.ProfileBlock+profSuffix, profFlags); err != nil {
			return err
		}
	}
	if conf.ProfileCPU != "" {
		if err := donations.OpenAndDonate("profile-cpu-fd", conf.ProfileCPU+profSuffix, profFlags); err != nil {
			return err
		}
	}
	if conf.ProfileHeap != "" {
		if err := donations.OpenAndDonate("profile-heap-fd", conf.ProfileHeap+profSuffix, profFlags); err != nil {
			return err
		}
	}
	if conf.ProfileMutex != "" {
		if err := donations.OpenAndDonate("profile-mutex-fd", conf.ProfileMutex+profSuffix, profFlags); err != nil {
			return err
		}
	}
	if conf.TraceFile != "" {
		if err := donations.OpenAndDonate("trace-fd", conf.TraceFile+profSuffix, profFlags); err != nil {
			return err
		}
	}
	return nil
}

// cgroupInstall creates cgroups dir structure and sets their respective
// resources. In case of success, returns the cgroups instance and nil error.
// For rootless, it's possible that cgroups operations fail, in this case the
// error is suppressed and a nil cgroups instance is returned to indicate that
// no cgroups was configured.
func cgroupInstall(conf *config.Config, cg cgroup.Cgroup, res *specs.LinuxResources) (cgroup.Cgroup, error) {
	if err := cg.Install(res); err != nil {
		switch {
		case (errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS)) && conf.Rootless:
			log.Warningf("Skipping cgroup configuration in rootless mode: %v", err)
			return nil, nil
		default:
			return nil, fmt.Errorf("configuring cgroup: %v", err)
		}
	}
	return cg, nil
}

func modifySpecForDirectfs(conf *config.Config, spec *specs.Spec) error {
	if !conf.DirectFS || conf.TestOnlyAllowRunAsCurrentUserWithoutChroot {
		return nil
	}
	if conf.Network == config.NetworkHost {
		// Hostnet feature requires the sandbox to run in the current user
		// namespace, in which the network namespace is configured.
		return nil
	}
	if _, ok := specutils.GetNS(specs.UserNamespace, spec); ok {
		// If the spec already defines a userns, use that.
		return nil
	}
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	if len(spec.Linux.UIDMappings) > 0 || len(spec.Linux.GIDMappings) > 0 {
		// The spec can only define UID/GID mappings with a userns (checked above).
		return fmt.Errorf("spec defines UID/GID mappings without defining userns")
	}
	// Run the sandbox in a new user namespace with identity UID/GID mappings.
	spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
	// The maximum range of UID/GID mapping should be the largest uint32 integer.
	// This is similar to what Linux does for identity mappings. Also note:
	// "This leaves 4294967295 (the 32-bit signed -1 value) unmapped. This is
	// deliberate: (uid_t) -1 is used in several interfaces (e.g., setreuid(2))
	// as a way to specify "no user ID".  Leaving (uid_t) -1 unmapped and
	// unusable guarantees that there will be no confusion when using these
	// interfaces." -- user_namespaces(7).
	maxRange := ^uint32(0)
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{
			ContainerID: 0,
			HostID:      0,
			Size:        maxRange,
		},
	}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{
			ContainerID: 0,
			HostID:      0,
			Size:        maxRange,
		},
	}
	return nil
}
