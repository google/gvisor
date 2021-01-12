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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/sighandling"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/console"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

// validateID validates the container id.
func validateID(id string) error {
	// See libcontainer/factory_linux.go.
	idRegex := regexp.MustCompile(`^[\w+-\.]+$`)
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

	// Saver handles load from/save to the state file safely from multiple
	// processes.
	Saver StateFile `json:"saver"`

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
	}
	// The Cleanup object cleans up partially created containers when an error
	// occurs. Any errors occurring during cleanup itself are ignored.
	cu := cleanup.Make(func() { _ = c.Destroy() })
	defer cu.Clean()

	// Lock the container metadata file to prevent concurrent creations of
	// containers with the same id.
	if err := c.Saver.lockForNew(); err != nil {
		return nil, err
	}
	defer c.Saver.unlock()

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

		// Create and join cgroup before processes are created to ensure they are
		// part of the cgroup from the start (and all their children processes).
		cg, err := cgroup.New(args.Spec)
		if err != nil {
			return nil, err
		}
		if cg != nil {
			// If there is cgroup config, install it before creating sandbox process.
			if err := cg.Install(args.Spec.Linux.Resources); err != nil {
				switch {
				case errors.Is(err, syscall.EACCES) && conf.Rootless:
					log.Warningf("Skipping cgroup configuration in rootless mode: %v", err)
					cg = nil
				default:
					return nil, fmt.Errorf("configuring cgroup: %v", err)
				}
			}
		}
		if err := runInCgroup(cg, func() error {
			ioFiles, specFile, err := c.createGoferProcess(args.Spec, conf, args.BundleDir, args.Attached)
			if err != nil {
				return err
			}

			// Start a new sandbox for this container. Any errors after this point
			// must destroy the container.
			sandArgs := &sandbox.Args{
				ID:            sandboxID,
				Spec:          args.Spec,
				BundleDir:     args.BundleDir,
				ConsoleSocket: args.ConsoleSocket,
				UserLog:       args.UserLog,
				IOFiles:       ioFiles,
				MountsFile:    specFile,
				Cgroup:        cg,
				Attached:      args.Attached,
			}
			sand, err := sandbox.New(conf, sandArgs)
			if err != nil {
				return err
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
			return nil, err
		}
		c.Sandbox = sb.Sandbox

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

		if err := c.Sandbox.CreateContainer(c.ID, tty); err != nil {
			return nil, err
		}
	}
	c.changeStatus(Created)

	// Save the metadata file.
	if err := c.saveLocked(); err != nil {
		return nil, err
	}

	// Write the PID file. Containerd considers the create complete after
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

	if err := c.Saver.lock(); err != nil {
		return err
	}
	unlock := cleanup.Make(func() { c.Saver.unlock() })
	defer unlock.Clean()

	if err := c.requireStatus("start", Created); err != nil {
		return err
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil {
		if err := executeHooks(c.Spec.Hooks.Prestart, c.State()); err != nil {
			return err
		}
	}

	if isRoot(c.Spec) {
		if err := c.Sandbox.StartRoot(c.Spec, conf); err != nil {
			return err
		}
	} else {
		// Join cgroup to start gofer process to ensure it's part of the cgroup from
		// the start (and all their children processes).
		if err := runInCgroup(c.Sandbox.Cgroup, func() error {
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

			return c.Sandbox.StartContainer(c.Spec, conf, c.ID, stdios, goferFiles)
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
	if err := c.Saver.lock(); err != nil {
		return err
	}
	defer c.Saver.unlock()

	if err := c.requireStatus("restore", Created); err != nil {
		return err
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil {
		if err := executeHooks(c.Spec.Hooks.Prestart, c.State()); err != nil {
			return err
		}
	}

	if err := c.Sandbox.Restore(c.ID, spec, conf, restoreFile); err != nil {
		return err
	}
	c.changeStatus(Running)
	return c.saveLocked()
}

// Run is a helper that calls Create + Start + Wait.
func Run(conf *config.Config, args Args) (syscall.WaitStatus, error) {
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
	if args.Attached {
		return c.Wait()
	}
	cu.Release()
	return 0, nil
}

// Execute runs the specified command in the container. It returns the PID of
// the newly created process.
func (c *Container) Execute(args *control.ExecArgs) (int32, error) {
	log.Debugf("Execute in container, cid: %s, args: %+v", c.ID, args)
	if err := c.requireStatus("execute in", Created, Running); err != nil {
		return 0, err
	}
	args.ContainerID = c.ID
	return c.Sandbox.Execute(args)
}

// Event returns events for the container.
func (c *Container) Event() (*boot.Event, error) {
	log.Debugf("Getting events for container, cid: %s", c.ID)
	if err := c.requireStatus("get events for", Created, Running, Paused); err != nil {
		return nil, err
	}
	return c.Sandbox.Event(c.ID)
}

// SandboxPid returns the Pid of the sandbox the container is running in, or -1 if the
// container is not running.
func (c *Container) SandboxPid() int {
	if err := c.requireStatus("get PID", Created, Running, Paused); err != nil {
		return -1
	}
	return c.Sandbox.Pid
}

// Wait waits for the container to exit, and returns its WaitStatus.
// Call to wait on a stopped container is needed to retrieve the exit status
// and wait returns immediately.
func (c *Container) Wait() (syscall.WaitStatus, error) {
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
func (c *Container) WaitRootPID(pid int32) (syscall.WaitStatus, error) {
	log.Debugf("Wait on process %d in sandbox, cid: %s", pid, c.Sandbox.ID)
	if !c.IsSandboxRunning() {
		return 0, fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.WaitPID(c.Sandbox.ID, pid)
}

// WaitPID waits for process 'pid' in the container's PID namespace and returns
// its WaitStatus.
func (c *Container) WaitPID(pid int32) (syscall.WaitStatus, error) {
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
func (c *Container) SignalContainer(sig syscall.Signal, all bool) error {
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
func (c *Container) SignalProcess(sig syscall.Signal, pid int32) error {
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
		if err := c.Sandbox.SignalProcess(c.ID, pid, syscall.Signal(sig), fgProcess); err != nil {
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
	if err := c.Saver.lock(); err != nil {
		return err
	}
	defer c.Saver.unlock()

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
	if err := c.Saver.lock(); err != nil {
		return err
	}
	defer c.Saver.unlock()

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
		Version: specs.Version,
		ID:      c.ID,
		Status:  c.Status.String(),
		Pid:     c.SandboxPid(),
		Bundle:  c.BundleDir,
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

	if err := c.Saver.lock(); err != nil {
		return err
	}
	defer func() {
		c.Saver.unlock()
		c.Saver.close()
	}()

	// Stored for later use as stop() sets c.Sandbox to nil.
	sb := c.Sandbox

	// We must perform the following cleanup steps:
	// * stop the container and gofer processes,
	// * remove the container filesystem on the host, and
	// * delete the container metadata directory.
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

	if err := c.Saver.destroy(); err != nil {
		err = fmt.Errorf("deleting container state files: %v", err)
		log.Warningf("%v", err)
		errs = append(errs, err.Error())
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

// saveLocked saves the container metadata to a file.
//
// Precondition: container must be locked with container.lock().
func (c *Container) saveLocked() error {
	log.Debugf("Save container, cid: %s", c.ID)
	if err := c.Saver.saveLocked(c); err != nil {
		return fmt.Errorf("saving container metadata: %v", err)
	}
	return nil
}

// stop stops the container (for regular containers) or the sandbox (for
// root containers), and waits for the container or sandbox and the gofer
// to stop. If any of them doesn't stop before timeout, an error is returned.
func (c *Container) stop() error {
	var cgroup *cgroup.Cgroup

	if c.Sandbox != nil {
		log.Debugf("Destroying container, cid: %s", c.ID)
		if err := c.Sandbox.DestroyContainer(c.ID); err != nil {
			return fmt.Errorf("destroying container %q: %v", c.ID, err)
		}
		// Only uninstall cgroup for sandbox stop.
		if c.Sandbox.IsRootContainer(c.ID) {
			cgroup = c.Sandbox.Cgroup
		}
		// Only set sandbox to nil after it has been told to destroy the container.
		c.Sandbox = nil
	}

	// Try killing gofer if it does not exit with container.
	if c.GoferPid != 0 {
		log.Debugf("Killing gofer for container, cid: %s, PID: %d", c.ID, c.GoferPid)
		if err := syscall.Kill(c.GoferPid, syscall.SIGKILL); err != nil {
			// The gofer may already be stopped, log the error.
			log.Warningf("Error sending signal %d to gofer %d: %v", syscall.SIGKILL, c.GoferPid, err)
		}
	}

	if err := c.waitForStopped(); err != nil {
		return err
	}

	// Gofer is running in cgroups, so Cgroup.Uninstall has to be called after it.
	if cgroup != nil {
		if err := cgroup.Uninstall(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Container) waitForStopped() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := backoff.WithContext(backoff.NewConstantBackOff(100*time.Millisecond), ctx)
	op := func() error {
		if c.IsSandboxRunning() {
			if err := c.SignalContainer(syscall.Signal(0), false); err == nil {
				return fmt.Errorf("container is still running")
			}
		}
		if c.GoferPid == 0 {
			return nil
		}
		if c.goferIsChild {
			// The gofer process is a child of the current process,
			// so we can wait it and collect its zombie.
			wpid, err := syscall.Wait4(int(c.GoferPid), nil, syscall.WNOHANG, nil)
			if err != nil {
				return fmt.Errorf("error waiting the gofer process: %v", err)
			}
			if wpid == 0 {
				return fmt.Errorf("gofer is still running")
			}

		} else if err := syscall.Kill(c.GoferPid, 0); err == nil {
			return fmt.Errorf("gofer is still running")
		}
		c.GoferPid = 0
		return nil
	}
	return backoff.Retry(op, b)
}

func (c *Container) createGoferProcess(spec *specs.Spec, conf *config.Config, bundleDir string, attached bool) ([]*os.File, *os.File, error) {
	// Start with the general config flags.
	args := conf.ToFlags()

	var goferEnds []*os.File

	// nextFD is the next available file descriptor for the gofer process.
	// It starts at 3 because 0-2 are used by stdin/stdout/stderr.
	nextFD := 3

	if conf.LogFilename != "" {
		logFile, err := os.OpenFile(conf.LogFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("opening log file %q: %v", conf.LogFilename, err)
		}
		defer logFile.Close()
		goferEnds = append(goferEnds, logFile)
		args = append(args, "--log-fd="+strconv.Itoa(nextFD))
		nextFD++
	}

	if conf.DebugLog != "" {
		test := ""
		if len(conf.TestOnlyTestNameEnv) != 0 {
			// Fetch test name if one is provided and the test only flag was set.
			if t, ok := specutils.EnvVar(spec.Process.Env, conf.TestOnlyTestNameEnv); ok {
				test = t
			}
		}
		debugLogFile, err := specutils.DebugLogFile(conf.DebugLog, "gofer", test)
		if err != nil {
			return nil, nil, fmt.Errorf("opening debug log file in %q: %v", conf.DebugLog, err)
		}
		defer debugLogFile.Close()
		goferEnds = append(goferEnds, debugLogFile)
		args = append(args, "--debug-log-fd="+strconv.Itoa(nextFD))
		nextFD++
	}

	args = append(args, "gofer", "--bundle", bundleDir)

	// Open the spec file to donate to the sandbox.
	specFile, err := specutils.OpenSpec(bundleDir)
	if err != nil {
		return nil, nil, fmt.Errorf("opening spec file: %v", err)
	}
	defer specFile.Close()
	goferEnds = append(goferEnds, specFile)
	args = append(args, "--spec-fd="+strconv.Itoa(nextFD))
	nextFD++

	// Create pipe that allows gofer to send mount list to sandbox after all paths
	// have been resolved.
	mountsSand, mountsGofer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer mountsGofer.Close()
	goferEnds = append(goferEnds, mountsGofer)
	args = append(args, fmt.Sprintf("--mounts-fd=%d", nextFD))
	nextFD++

	// Add root mount and then add any other additional mounts.
	mountCount := 1
	for _, m := range spec.Mounts {
		if specutils.Is9PMount(m) {
			mountCount++
		}
	}

	sandEnds := make([]*os.File, 0, mountCount)
	for i := 0; i < mountCount; i++ {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, nil, err
		}
		sandEnds = append(sandEnds, os.NewFile(uintptr(fds[0]), "sandbox IO FD"))

		goferEnd := os.NewFile(uintptr(fds[1]), "gofer IO FD")
		defer goferEnd.Close()
		goferEnds = append(goferEnds, goferEnd)

		args = append(args, fmt.Sprintf("--io-fds=%d", nextFD))
		nextFD++
	}

	binPath := specutils.ExePath
	cmd := exec.Command(binPath, args...)
	cmd.ExtraFiles = goferEnds
	cmd.Args[0] = "runsc-gofer"

	if attached {
		// The gofer is attached to the lifetime of this process, so it
		// should synchronously die when this process dies.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGKILL,
		}
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

	// Setup any uid/gid mappings, and create or join the configured user
	// namespace so the gofer's view of the filesystem aligns with the
	// users in the sandbox.
	userNS := specutils.FilterNS([]specs.LinuxNamespaceType{specs.UserNamespace}, spec)
	nss = append(nss, userNS...)
	specutils.SetUIDGIDMappings(cmd, spec)
	if len(userNS) != 0 {
		// We need to set UID and GID to have capabilities in a new user namespace.
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: 0, Gid: 0}
	}

	// Start the gofer in the given namespace.
	log.Debugf("Starting gofer: %s %v", binPath, args)
	if err := specutils.StartInNS(cmd, nss); err != nil {
		return nil, nil, fmt.Errorf("gofer: %v", err)
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
func runInCgroup(cg *cgroup.Cgroup, fn func() error) error {
	if cg == nil {
		return fn()
	}
	restore, err := cg.Join()
	defer restore()
	if err != nil {
		return err
	}
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
	return setOOMScoreAdj(s.Pid, lowScore)
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
		if errors.Is(err, syscall.ESRCH) {
			log.Warningf("Process (%d) exited while setting oom_score_adj", pid)
			return nil
		}
		return fmt.Errorf("setting oom_score_adj to %q: %v", scoreAdj, err)
	}
	return nil
}
