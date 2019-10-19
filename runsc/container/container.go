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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/gofrs/flock"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cgroup"
	"gvisor.dev/gvisor/runsc/sandbox"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// metadataFilename is the name of the metadata file relative to the
	// container root directory that holds sandbox metadata.
	metadataFilename = "meta.json"

	// metadataLockFilename is the name of a lock file in the container
	// root directory that is used to prevent concurrent modifications to
	// the container state and metadata.
	metadataLockFilename = "meta.lock"
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
type Container struct {
	// ID is the container ID.
	ID string `json:"id"`

	// Spec is the OCI runtime spec that configures this container.
	Spec *specs.Spec `json:"spec"`

	// BundleDir is the directory containing the container bundle.
	BundleDir string `json:"bundleDir"`

	// Root is the directory containing the container metadata file. If this
	// container is the root container, Root and RootContainerDir will be the
	// same.
	Root string `json:"root"`

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

	// goferIsChild is set if a gofer process is a child of the current process.
	//
	// This field isn't saved to json, because only a creator of a gofer
	// process will have it as a child process.
	goferIsChild bool

	// Sandbox is the sandbox this container is running in. It's set when the
	// container is created and reset when the sandbox is destroyed.
	Sandbox *sandbox.Sandbox `json:"sandbox"`

	// RootContainerDir is the root directory containing the metadata file of the
	// sandbox root container. It's used to lock in order to serialize creating
	// and deleting this Container's metadata directory. If this container is the
	// root container, this is the same as Root.
	RootContainerDir string
}

// loadSandbox loads all containers that belong to the sandbox with the given
// ID.
func loadSandbox(rootDir, id string) ([]*Container, error) {
	cids, err := List(rootDir)
	if err != nil {
		return nil, err
	}

	// Load the container metadata.
	var containers []*Container
	for _, cid := range cids {
		container, err := Load(rootDir, cid)
		if err != nil {
			// Container file may not exist if it raced with creation/deletion or
			// directory was left behind. Load provides a snapshot in time, so it's
			// fine to skip it.
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("loading container %q: %v", id, err)
		}
		if container.Sandbox.ID == id {
			containers = append(containers, container)
		}
	}
	return containers, nil
}

// Load loads a container with the given id from a metadata file. id may be an
// abbreviation of the full container id, in which case Load loads the
// container to which id unambiguously refers to.
// Returns ErrNotExist if container doesn't exist.
func Load(rootDir, id string) (*Container, error) {
	log.Debugf("Load container %q %q", rootDir, id)
	if err := validateID(id); err != nil {
		return nil, fmt.Errorf("validating id: %v", err)
	}

	cRoot, err := findContainerRoot(rootDir, id)
	if err != nil {
		// Preserve error so that callers can distinguish 'not found' errors.
		return nil, err
	}

	// Lock the container metadata to prevent other runsc instances from
	// writing to it while we are reading it.
	unlock, err := lockContainerMetadata(cRoot)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Read the container metadata file and create a new Container from it.
	metaFile := filepath.Join(cRoot, metadataFilename)
	metaBytes, err := ioutil.ReadFile(metaFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Preserve error so that callers can distinguish 'not found' errors.
			return nil, err
		}
		return nil, fmt.Errorf("reading container metadata file %q: %v", metaFile, err)
	}
	var c Container
	if err := json.Unmarshal(metaBytes, &c); err != nil {
		return nil, fmt.Errorf("unmarshaling container metadata from %q: %v", metaFile, err)
	}

	// If the status is "Running" or "Created", check that the sandbox
	// process still exists, and set it to Stopped if it does not.
	//
	// This is inherently racy.
	if c.Status == Running || c.Status == Created {
		// Check if the sandbox process is still running.
		if !c.isSandboxRunning() {
			// Sandbox no longer exists, so this container definitely does not exist.
			c.changeStatus(Stopped)
		} else if c.Status == Running {
			// Container state should reflect the actual state of the application, so
			// we don't consider gofer process here.
			if err := c.SignalContainer(syscall.Signal(0), false); err != nil {
				c.changeStatus(Stopped)
			}
		}
	}

	return &c, nil
}

func findContainerRoot(rootDir, partialID string) (string, error) {
	// Check whether the id fully specifies an existing container.
	cRoot := filepath.Join(rootDir, partialID)
	if _, err := os.Stat(cRoot); err == nil {
		return cRoot, nil
	}

	// Now see whether id could be an abbreviation of exactly 1 of the
	// container ids. If id is ambiguous (it could match more than 1
	// container), it is an error.
	cRoot = ""
	ids, err := List(rootDir)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		if strings.HasPrefix(id, partialID) {
			if cRoot != "" {
				return "", fmt.Errorf("id %q is ambiguous and could refer to multiple containers: %q, %q", partialID, cRoot, id)
			}
			cRoot = id
		}
	}
	if cRoot == "" {
		return "", os.ErrNotExist
	}
	log.Debugf("abbreviated id %q resolves to full id %q", partialID, cRoot)
	return filepath.Join(rootDir, cRoot), nil
}

// List returns all container ids in the given root directory.
func List(rootDir string) ([]string, error) {
	log.Debugf("List containers %q", rootDir)
	fs, err := ioutil.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("reading dir %q: %v", rootDir, err)
	}
	var out []string
	for _, f := range fs {
		// Filter out directories that do no belong to a container.
		cid := f.Name()
		if validateID(cid) == nil {
			if _, err := os.Stat(filepath.Join(rootDir, cid, metadataFilename)); err == nil {
				out = append(out, f.Name())
			}
		}
	}
	return out, nil
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
func New(conf *boot.Config, args Args) (*Container, error) {
	log.Debugf("Create container %q in root dir: %s", args.ID, conf.RootDir)
	if err := validateID(args.ID); err != nil {
		return nil, err
	}

	unlockRoot, err := maybeLockRootContainer(args.Spec, conf.RootDir)
	if err != nil {
		return nil, err
	}
	defer unlockRoot()

	// Lock the container metadata file to prevent concurrent creations of
	// containers with the same id.
	containerRoot := filepath.Join(conf.RootDir, args.ID)
	unlock, err := lockContainerMetadata(containerRoot)
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Check if the container already exists by looking for the metadata
	// file.
	if _, err := os.Stat(filepath.Join(containerRoot, metadataFilename)); err == nil {
		return nil, fmt.Errorf("container with id %q already exists", args.ID)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("looking for existing container in %q: %v", containerRoot, err)
	}

	c := &Container{
		ID:               args.ID,
		Spec:             args.Spec,
		ConsoleSocket:    args.ConsoleSocket,
		BundleDir:        args.BundleDir,
		Root:             containerRoot,
		Status:           Creating,
		CreatedAt:        time.Now(),
		Owner:            os.Getenv("USER"),
		RootContainerDir: conf.RootDir,
	}
	// The Cleanup object cleans up partially created containers when an error occurs.
	// Any errors occuring during cleanup itself are ignored.
	cu := specutils.MakeCleanup(func() { _ = c.Destroy() })
	defer cu.Clean()

	// If the metadata annotations indicate that this container should be
	// started in an existing sandbox, we must do so. The metadata will
	// indicate the ID of the sandbox, which is the same as the ID of the
	// init container in the sandbox.
	if isRoot(args.Spec) {
		log.Debugf("Creating new sandbox for container %q", args.ID)

		// Create and join cgroup before processes are created to ensure they are
		// part of the cgroup from the start (and all their children processes).
		cg, err := cgroup.New(args.Spec)
		if err != nil {
			return nil, err
		}
		if cg != nil {
			// If there is cgroup config, install it before creating sandbox process.
			if err := cg.Install(args.Spec.Linux.Resources); err != nil {
				return nil, fmt.Errorf("configuring cgroup: %v", err)
			}
		}
		if err := runInCgroup(cg, func() error {
			ioFiles, specFile, err := c.createGoferProcess(args.Spec, conf, args.BundleDir)
			if err != nil {
				return err
			}

			// Start a new sandbox for this container. Any errors after this point
			// must destroy the container.
			sandArgs := &sandbox.Args{
				ID:            args.ID,
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
		// This is sort of confusing. For a sandbox with a root
		// container and a child container in it, runsc sees:
		// * A container struct whose sandbox ID is equal to the
		//   container ID. This is the root container that is tied to
		//   the creation of the sandbox.
		// * A container struct whose sandbox ID is equal to the above
		//   container/sandbox ID, but that has a different container
		//   ID. This is the child container.
		sbid, ok := specutils.SandboxID(args.Spec)
		if !ok {
			return nil, fmt.Errorf("no sandbox ID found when creating container")
		}
		log.Debugf("Creating new container %q in sandbox %q", c.ID, sbid)

		// Find the sandbox associated with this ID.
		sb, err := Load(conf.RootDir, sbid)
		if err != nil {
			return nil, err
		}
		c.Sandbox = sb.Sandbox
		if err := c.Sandbox.CreateContainer(c.ID); err != nil {
			return nil, err
		}
	}
	c.changeStatus(Created)

	// Save the metadata file.
	if err := c.save(); err != nil {
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
func (c *Container) Start(conf *boot.Config) error {
	log.Debugf("Start container %q", c.ID)

	unlockRoot, err := maybeLockRootContainer(c.Spec, c.RootContainerDir)
	if err != nil {
		return err
	}
	defer unlockRoot()

	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()
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
		// Join cgroup to strt gofer process to ensure it's part of the cgroup from
		// the start (and all their children processes).
		if err := runInCgroup(c.Sandbox.Cgroup, func() error {
			// Create the gofer process.
			ioFiles, mountsFile, err := c.createGoferProcess(c.Spec, conf, c.BundleDir)
			if err != nil {
				return err
			}
			defer mountsFile.Close()

			cleanMounts, err := specutils.ReadMounts(mountsFile)
			if err != nil {
				return fmt.Errorf("reading mounts file: %v", err)
			}
			c.Spec.Mounts = cleanMounts

			return c.Sandbox.StartContainer(c.Spec, conf, c.ID, ioFiles)
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
	if err := c.save(); err != nil {
		return err
	}

	// Adjust the oom_score_adj for sandbox. This must be done after
	// save().
	err = adjustSandboxOOMScoreAdj(c.Sandbox, c.RootContainerDir, false)
	if err != nil {
		return err
	}

	// Set container's oom_score_adj to the gofer since it is dedicated to
	// the container, in case the gofer uses up too much memory.
	return c.adjustGoferOOMScoreAdj()
}

// Restore takes a container and replaces its kernel and file system
// to restore a container from its state file.
func (c *Container) Restore(spec *specs.Spec, conf *boot.Config, restoreFile string) error {
	log.Debugf("Restore container %q", c.ID)
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

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
	return c.save()
}

// Run is a helper that calls Create + Start + Wait.
func Run(conf *boot.Config, args Args) (syscall.WaitStatus, error) {
	log.Debugf("Run container %q in root dir: %s", args.ID, conf.RootDir)
	c, err := New(conf, args)
	if err != nil {
		return 0, fmt.Errorf("creating container: %v", err)
	}
	// Clean up partially created container if an error occurs.
	// Any errors returned by Destroy() itself are ignored.
	cu := specutils.MakeCleanup(func() {
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
	log.Debugf("Execute in container %q, args: %+v", c.ID, args)
	if err := c.requireStatus("execute in", Created, Running); err != nil {
		return 0, err
	}
	args.ContainerID = c.ID
	return c.Sandbox.Execute(args)
}

// Event returns events for the container.
func (c *Container) Event() (*boot.Event, error) {
	log.Debugf("Getting events for container %q", c.ID)
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
	log.Debugf("Wait on container %q", c.ID)
	return c.Sandbox.Wait(c.ID)
}

// WaitRootPID waits for process 'pid' in the sandbox's PID namespace and
// returns its WaitStatus.
func (c *Container) WaitRootPID(pid int32) (syscall.WaitStatus, error) {
	log.Debugf("Wait on PID %d in sandbox %q", pid, c.Sandbox.ID)
	if !c.isSandboxRunning() {
		return 0, fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.WaitPID(c.Sandbox.ID, pid)
}

// WaitPID waits for process 'pid' in the container's PID namespace and returns
// its WaitStatus.
func (c *Container) WaitPID(pid int32) (syscall.WaitStatus, error) {
	log.Debugf("Wait on PID %d in container %q", pid, c.ID)
	if !c.isSandboxRunning() {
		return 0, fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.WaitPID(c.ID, pid)
}

// SignalContainer sends the signal to the container. If all is true and signal
// is SIGKILL, then waits for all processes to exit before returning.
// SignalContainer returns an error if the container is already stopped.
// TODO(b/113680494): Distinguish different error types.
func (c *Container) SignalContainer(sig syscall.Signal, all bool) error {
	log.Debugf("Signal container %q: %v", c.ID, sig)
	// Signaling container in Stopped state is allowed. When all=false,
	// an error will be returned anyway; when all=true, this allows
	// sending signal to other processes inside the container even
	// after the init process exits. This is especially useful for
	// container cleanup.
	if err := c.requireStatus("signal", Running, Stopped); err != nil {
		return err
	}
	if !c.isSandboxRunning() {
		return fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.SignalContainer(c.ID, sig, all)
}

// SignalProcess sends sig to a specific process in the container.
func (c *Container) SignalProcess(sig syscall.Signal, pid int32) error {
	log.Debugf("Signal process %d in container %q: %v", pid, c.ID, sig)
	if err := c.requireStatus("signal a process inside", Running); err != nil {
		return err
	}
	if !c.isSandboxRunning() {
		return fmt.Errorf("sandbox is not running")
	}
	return c.Sandbox.SignalProcess(c.ID, int32(pid), sig, false)
}

// ForwardSignals forwards all signals received by the current process to the
// container process inside the sandbox. It returns a function that will stop
// forwarding signals.
func (c *Container) ForwardSignals(pid int32, fgProcess bool) func() {
	log.Debugf("Forwarding all signals to container %q PID %d fgProcess=%t", c.ID, pid, fgProcess)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh)
	go func() {
		for s := range sigCh {
			log.Debugf("Forwarding signal %d to container %q PID %d fgProcess=%t", s, c.ID, pid, fgProcess)
			if err := c.Sandbox.SignalProcess(c.ID, pid, s.(syscall.Signal), fgProcess); err != nil {
				log.Warningf("error forwarding signal %d to container %q: %v", s, c.ID, err)
			}
		}
		log.Debugf("Done forwarding signals to container %q PID %d fgProcess=%t", c.ID, pid, fgProcess)
	}()

	return func() {
		signal.Stop(sigCh)
		close(sigCh)
	}
}

// Checkpoint sends the checkpoint call to the container.
// The statefile will be written to f, the file at the specified image-path.
func (c *Container) Checkpoint(f *os.File) error {
	log.Debugf("Checkpoint container %q", c.ID)
	if err := c.requireStatus("checkpoint", Created, Running, Paused); err != nil {
		return err
	}
	return c.Sandbox.Checkpoint(c.ID, f)
}

// Pause suspends the container and its kernel.
// The call only succeeds if the container's status is created or running.
func (c *Container) Pause() error {
	log.Debugf("Pausing container %q", c.ID)
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if c.Status != Created && c.Status != Running {
		return fmt.Errorf("cannot pause container %q in state %v", c.ID, c.Status)
	}

	if err := c.Sandbox.Pause(c.ID); err != nil {
		return fmt.Errorf("pausing container: %v", err)
	}
	c.changeStatus(Paused)
	return c.save()
}

// Resume unpauses the container and its kernel.
// The call only succeeds if the container's status is paused.
func (c *Container) Resume() error {
	log.Debugf("Resuming container %q", c.ID)
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()

	if c.Status != Paused {
		return fmt.Errorf("cannot resume container %q in state %v", c.ID, c.Status)
	}
	if err := c.Sandbox.Resume(c.ID); err != nil {
		return fmt.Errorf("resuming container: %v", err)
	}
	c.changeStatus(Running)
	return c.save()
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
	log.Debugf("Destroy container %q", c.ID)

	// We must perform the following cleanup steps:
	// * stop the container and gofer processes,
	// * remove the container filesystem on the host, and
	// * delete the container metadata directory.
	//
	// It's possible for one or more of these steps to fail, but we should
	// do our best to perform all of the cleanups. Hence, we keep a slice
	// of errors return their concatenation.
	var errs []string

	unlock, err := maybeLockRootContainer(c.Spec, c.RootContainerDir)
	if err != nil {
		return err
	}
	defer unlock()

	// Stored for later use as stop() sets c.Sandbox to nil.
	sb := c.Sandbox

	if err := c.stop(); err != nil {
		err = fmt.Errorf("stopping container: %v", err)
		log.Warningf("%v", err)
		errs = append(errs, err.Error())
	}

	if err := os.RemoveAll(c.Root); err != nil && !os.IsNotExist(err) {
		err = fmt.Errorf("deleting container root directory %q: %v", c.Root, err)
		log.Warningf("%v", err)
		errs = append(errs, err.Error())
	}

	c.changeStatus(Stopped)

	// Adjust oom_score_adj for the sandbox. This must be done after the
	// container is stopped and the directory at c.Root is removed.
	// We must test if the sandbox is nil because Destroy should be
	// idempotent.
	if sb != nil {
		if err := adjustSandboxOOMScoreAdj(sb, c.RootContainerDir, true); err != nil {
			errs = append(errs, err.Error())
		}
	}

	// "If any poststop hook fails, the runtime MUST log a warning, but the
	// remaining hooks and lifecycle continue as if the hook had succeeded" -OCI spec.
	// Based on the OCI, "The post-stop hooks MUST be called after the container is
	// deleted but before the delete operation returns"
	// Run it here to:
	// 1) Conform to the OCI.
	// 2) Make sure it only runs once, because the root has been deleted, the container
	// can't be loaded again.
	if c.Spec.Hooks != nil {
		executeHooksBestEffort(c.Spec.Hooks.Poststop, c.State())
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf(strings.Join(errs, "\n"))
}

// save saves the container metadata to a file.
//
// Precondition: container must be locked with container.lock().
func (c *Container) save() error {
	log.Debugf("Save container %q", c.ID)
	metaFile := filepath.Join(c.Root, metadataFilename)
	meta, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("invalid container metadata: %v", err)
	}
	if err := ioutil.WriteFile(metaFile, meta, 0640); err != nil {
		return fmt.Errorf("writing container metadata: %v", err)
	}
	return nil
}

// stop stops the container (for regular containers) or the sandbox (for
// root containers), and waits for the container or sandbox and the gofer
// to stop. If any of them doesn't stop before timeout, an error is returned.
func (c *Container) stop() error {
	var cgroup *cgroup.Cgroup

	if c.Sandbox != nil {
		log.Debugf("Destroying container %q", c.ID)
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
		log.Debugf("Killing gofer for container %q, PID: %d", c.ID, c.GoferPid)
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
		if c.isSandboxRunning() {
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

func (c *Container) createGoferProcess(spec *specs.Spec, conf *boot.Config, bundleDir string) ([]*os.File, *os.File, error) {
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
	if conf.Overlay {
		args = append(args, "--panic-on-write=true")
	}

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
		return nil, nil, fmt.Errorf("Gofer: %v", err)
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

func (c *Container) isSandboxRunning() bool {
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

// lock takes a file lock on the container metadata lock file.
func (c *Container) lock() (func() error, error) {
	return lockContainerMetadata(filepath.Join(c.Root, c.ID))
}

// lockContainerMetadata takes a file lock on the metadata lock file in the
// given container root directory.
func lockContainerMetadata(containerRootDir string) (func() error, error) {
	if err := os.MkdirAll(containerRootDir, 0711); err != nil {
		return nil, fmt.Errorf("creating container root directory %q: %v", containerRootDir, err)
	}
	f := filepath.Join(containerRootDir, metadataLockFilename)
	l := flock.NewFlock(f)
	if err := l.Lock(); err != nil {
		return nil, fmt.Errorf("acquiring lock on container lock file %q: %v", f, err)
	}
	return l.Unlock, nil
}

// maybeLockRootContainer locks the sandbox root container. It is used to
// prevent races to create and delete child container sandboxes.
func maybeLockRootContainer(spec *specs.Spec, rootDir string) (func() error, error) {
	if isRoot(spec) {
		return func() error { return nil }, nil
	}

	sbid, ok := specutils.SandboxID(spec)
	if !ok {
		return nil, fmt.Errorf("no sandbox ID found when locking root container")
	}
	sb, err := Load(rootDir, sbid)
	if err != nil {
		return nil, err
	}

	unlock, err := sb.lock()
	if err != nil {
		return nil, err
	}
	return unlock, nil
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
	if c.GoferPid != 0 && c.Spec.Process.OOMScoreAdj != nil {
		if err := setOOMScoreAdj(c.GoferPid, *c.Spec.Process.OOMScoreAdj); err != nil {
			return fmt.Errorf("setting gofer oom_score_adj for container %q: %v", c.ID, err)
		}
	}

	return nil
}

// adjustSandboxOOMScoreAdj sets the oom_score_adj for the sandbox.
// oom_score_adj is set to the lowest oom_score_adj among the containers
// running in the sandbox.
//
// TODO(gvisor.dev/issue/512): This call could race with other containers being
// created at the same time and end up setting the wrong oom_score_adj to the
// sandbox.
func adjustSandboxOOMScoreAdj(s *sandbox.Sandbox, rootDir string, destroy bool) error {
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
	if len(containers) == 1 && specutils.SpecContainerType(containers[0].Spec) == specutils.ContainerTypeUnspecified {
		// This is a single-container sandbox. Set the oom_score_adj to
		// the value specified in the OCI bundle.
		if containers[0].Spec.Process.OOMScoreAdj != nil {
			scoreFound = true
			lowScore = *containers[0].Spec.Process.OOMScoreAdj
		}
	} else {
		for _, container := range containers {
			// Special multi-container support for CRI. Ignore the root
			// container when calculating oom_score_adj for the sandbox because
			// it is the infrastructure (pause) container and always has a very
			// low oom_score_adj.
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
	}

	// If the container is destroyed and remaining containers have no
	// oomScoreAdj specified then we must revert to the oom_score_adj of the
	// parent process.
	if !scoreFound && destroy {
		ppid, err := specutils.GetParentPid(s.Pid)
		if err != nil {
			return fmt.Errorf("getting parent pid of sandbox pid %d: %v", s.Pid, err)
		}
		pScore, err := specutils.GetOOMScoreAdj(ppid)
		if err != nil {
			return fmt.Errorf("getting oom_score_adj of parent %d: %v", ppid, err)
		}

		scoreFound = true
		lowScore = pScore
	}

	// Only set oom_score_adj if one of the containers has oom_score_adj set
	// in the OCI bundle. If not, we need to inherit the parent process's
	// oom_score_adj.
	// See: https://github.com/opencontainers/runtime-spec/blob/master/config.md#linux-process
	if !scoreFound {
		return nil
	}

	// Set the lowest of all containers oom_score_adj to the sandbox.
	if err := setOOMScoreAdj(s.Pid, lowScore); err != nil {
		return fmt.Errorf("setting oom_score_adj for sandbox %q: %v", s.ID, err)
	}

	return nil
}

// setOOMScoreAdj sets oom_score_adj to the given value for the given PID.
// /proc must be available and mounted read-write. scoreAdj should be between
// -1000 and 1000.
func setOOMScoreAdj(pid int, scoreAdj int) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid), os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(strconv.Itoa(scoreAdj)); err != nil {
		return err
	}
	return nil
}
