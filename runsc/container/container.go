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

// Package container creates and manipulates containers.
package container

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/control"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/runsc/boot"
	"gvisor.googlesource.com/gvisor/runsc/sandbox"
	"gvisor.googlesource.com/gvisor/runsc/specutils"
)

// metadataFilename is the name of the metadata file relative to the container
// root directory that holds sandbox metadata.
const metadataFilename = "meta.json"

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
type Container struct {
	// ID is the container ID.
	ID string `json:"id"`

	// Spec is the OCI runtime spec that configures this container.
	Spec *specs.Spec `json:"spec"`

	// BundleDir is the directory containing the container bundle.
	BundleDir string `json:"bundleDir"`

	// Root is the directory containing the container metadata file.
	Root string `json:"root"`

	// CreatedAt is the time the container was created.
	CreatedAt time.Time `json:"createdAt"`

	// Owner is the container owner.
	Owner string `json:"owner"`

	// ConsoleSocket is the path to a unix domain socket that will receive
	// the console FD. It is only used during create, so we don't need to
	// store it in the metadata.
	ConsoleSocket string `json:"-"`

	// Status is the current container Status.
	Status Status `json:"status"`

	// Sandbox is the sandbox this container is running in. It will be nil
	// if the container is not in state Running or Created.
	Sandbox *sandbox.Sandbox `json:"sandbox"`
}

// Load loads a container with the given id from a metadata file. id may be an
// abbreviation of the full container id, in which case Load loads the
// container to which id unambiguously refers to.
// Returns ErrNotExist if container doesn't exist.
func Load(rootDir, id string) (*Container, error) {
	log.Debugf("Load container %q %q", rootDir, id)
	if err := validateID(id); err != nil {
		return nil, fmt.Errorf("error validating id: %v", err)
	}

	cRoot, err := findContainerRoot(rootDir, id)
	if err != nil {
		// Preserve error so that callers can distinguish 'not found' errors.
		return nil, err
	}

	metaFile := filepath.Join(cRoot, metadataFilename)
	metaBytes, err := ioutil.ReadFile(metaFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Preserve error so that callers can distinguish 'not found' errors.
			return nil, err
		}
		return nil, fmt.Errorf("error reading container metadata file %q: %v", metaFile, err)
	}
	var c Container
	if err := json.Unmarshal(metaBytes, &c); err != nil {
		return nil, fmt.Errorf("error unmarshaling container metadata from %q: %v", metaFile, err)
	}

	// If the status is "Running" or "Created", check that the sandbox
	// process still exists, and set it to Stopped if it does not.
	//
	// This is inherently racey.
	if c.Status == Running || c.Status == Created {
		// Check if the sandbox process is still running.
		if c.Sandbox.IsRunning() {
			// TODO: Send a message into the sandbox to
			// see if this particular container is still running.
		} else {
			// Sandbox no longer exists, so this container
			// definitely does not exist.
			c.Status = Stopped
			c.Sandbox = nil
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
	// container ids. If id is ambigious (it could match more than 1
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
		return nil, fmt.Errorf("ReadDir(%s) failed: %v", rootDir, err)
	}
	var out []string
	for _, f := range fs {
		out = append(out, f.Name())
	}
	return out, nil
}

// Create creates the container in a new Sandbox process, unless the metadata
// indicates that an existing Sandbox should be used.
func Create(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, pidFile string) (*Container, error) {
	log.Debugf("Create container %q in root dir: %s", id, conf.RootDir)
	if err := validateID(id); err != nil {
		return nil, err
	}

	containerRoot := filepath.Join(conf.RootDir, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, fmt.Errorf("container with id %q already exists: %q", id, containerRoot)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("error looking for existing container in %q: %v", containerRoot, err)
	}

	c := &Container{
		ID:            id,
		Spec:          spec,
		ConsoleSocket: consoleSocket,
		BundleDir:     bundleDir,
		Root:          containerRoot,
		Status:        Creating,
		Owner:         os.Getenv("USER"),
	}

	// If the metadata annotations indicate that this container should be
	// started in an existing sandbox, we must do so. The metadata will
	// indicate the ID of the sandbox, which is the same as the ID of the
	// init container in the sandbox.
	if specutils.ShouldCreateSandbox(spec) || !conf.MultiContainer {
		log.Debugf("Creating new sandbox for container %q", id)
		// Start a new sandbox for this container. Any errors after this point
		// must destroy the container.
		s, err := sandbox.Create(id, spec, conf, bundleDir, consoleSocket)
		if err != nil {
			c.Destroy()
			return nil, err
		}
		c.Sandbox = s
	} else {
		// This is sort of confusing. For a sandbox with a root
		// container and a child container in it, runsc sees:
		// * A container struct whose sandbox ID is equal to the
		//   container ID. This is the root container that is tied to
		//   the creation of the sandbox.
		// * A container struct whose sandbox ID is equal to the above
		//   container/sandbox ID, but that has a different container
		//   ID. This is the child container.
		sbid, ok := specutils.SandboxID(spec)
		if !ok {
			return nil, fmt.Errorf("no sandbox ID found when creating container")
		}
		log.Debugf("Creating new container %q in sandbox %q", c.ID, sbid)

		// Find the sandbox associated with this ID.
		sb, err := Load(conf.RootDir, sbid)
		if err != nil {
			c.Destroy()
			return nil, err
		}
		c.Sandbox = sb.Sandbox
	}
	c.Status = Created

	// Save the metadata file.
	if err := c.save(); err != nil {
		c.Destroy()
		return nil, err
	}

	// Write the pid file. Containerd considers the create complete after
	// this file is created, so it must be the last thing we do.
	if pidFile != "" {
		if err := ioutil.WriteFile(pidFile, []byte(strconv.Itoa(c.Pid())), 0644); err != nil {
			c.Destroy()
			return nil, fmt.Errorf("error writing pid file: %v", err)
		}
	}

	return c, nil
}

// Start starts running the containerized process inside the sandbox.
func (c *Container) Start(conf *boot.Config) error {
	log.Debugf("Start container %q", c.ID)
	if c.Status != Created {
		return fmt.Errorf("cannot start container in state %s", c.Status)
	}

	// "If any prestart hook fails, the runtime MUST generate an error,
	// stop and destroy the container" -OCI spec.
	if c.Spec.Hooks != nil {
		if err := executeHooks(c.Spec.Hooks.Prestart, c.State()); err != nil {
			c.Destroy()
			return err
		}
	}

	if specutils.ShouldCreateSandbox(c.Spec) || !conf.MultiContainer {
		if err := c.Sandbox.StartRoot(c.Spec, conf); err != nil {
			c.Destroy()
			return err
		}
	} else {
		if err := c.Sandbox.Start(c.Spec, conf, c.ID); err != nil {
			c.Destroy()
			return err
		}
	}

	// "If any poststart hook fails, the runtime MUST log a warning, but
	// the remaining hooks and lifecycle continue as if the hook had
	// succeeded" -OCI spec.
	if c.Spec.Hooks != nil {
		executeHooksBestEffort(c.Spec.Hooks.Poststart, c.State())
	}

	c.Status = Running
	return c.save()
}

// Restore takes a container and replaces its kernel and file system
// to restore a container from its state file.
func (c *Container) Restore(spec *specs.Spec, conf *boot.Config, restoreFile string) error {
	log.Debugf("Restore container %q", c.ID)

	if c.Status != Created {
		return fmt.Errorf("cannot restore container in state %s", c.Status)
	}

	if err := c.Sandbox.Restore(c.ID, spec, conf, restoreFile); err != nil {
		return err
	}
	c.Status = Running
	return c.save()
}

// Run is a helper that calls Create + Start + Wait.
func Run(id string, spec *specs.Spec, conf *boot.Config, bundleDir, consoleSocket, pidFile string) (syscall.WaitStatus, error) {
	log.Debugf("Run container %q in root dir: %s", id, conf.RootDir)
	c, err := Create(id, spec, conf, bundleDir, consoleSocket, pidFile)
	if err != nil {
		return 0, fmt.Errorf("error creating container: %v", err)
	}
	if err := c.Start(conf); err != nil {
		return 0, fmt.Errorf("error starting container: %v", err)
	}
	return c.Wait()
}

// Execute runs the specified command in the container.
func (c *Container) Execute(e *control.ExecArgs) (syscall.WaitStatus, error) {
	log.Debugf("Execute in container %q, args: %+v", c.ID, e)
	if c.Status != Created && c.Status != Running {
		return 0, fmt.Errorf("cannot exec in container in state %s", c.Status)
	}
	return c.Sandbox.Execute(c.ID, e)
}

// Event returns events for the container.
func (c *Container) Event() (*boot.Event, error) {
	log.Debugf("Getting events for container %q", c.ID)
	if c.Status != Running && c.Status != Created {
		return nil, fmt.Errorf("cannot get events for container in state: %s", c.Status)
	}
	return c.Sandbox.Event(c.ID)
}

// Pid returns the Pid of the sandbox the container is running in, or -1 if the
// container is not running.
func (c *Container) Pid() int {
	if c.Status != Running && c.Status != Created && c.Status != Paused {
		return -1
	}
	return c.Sandbox.Pid
}

// Wait waits for the container to exit, and returns its WaitStatus.
func (c *Container) Wait() (syscall.WaitStatus, error) {
	log.Debugf("Wait on container %q", c.ID)
	if c.Status == Stopped {
		return 0, fmt.Errorf("container is stopped")
	}
	return c.Sandbox.Wait(c.ID)
}

// WaitRootPID waits for process 'pid' in the sandbox's PID namespace and
// returns its WaitStatus.
func (c *Container) WaitRootPID(pid int32) (syscall.WaitStatus, error) {
	log.Debugf("Wait on pid %d in sandbox %q", pid, c.Sandbox.ID)
	if c.Status == Stopped {
		return 0, fmt.Errorf("container is stopped")
	}
	return c.Sandbox.WaitPID(pid, c.Sandbox.ID)
}

// WaitPID waits for process 'pid' in the container's PID namespace and returns
// its WaitStatus.
func (c *Container) WaitPID(pid int32) (syscall.WaitStatus, error) {
	log.Debugf("Wait on pid %d in container %q", pid, c.ID)
	if c.Status == Stopped {
		return 0, fmt.Errorf("container is stopped")
	}
	return c.Sandbox.WaitPID(pid, c.ID)
}

// Signal sends the signal to the container.
func (c *Container) Signal(sig syscall.Signal) error {
	log.Debugf("Signal container %q", c.ID)
	if c.Status == Stopped {
		log.Warningf("container %q not running, not sending signal %v", c.ID, sig)
		return nil
	}
	return c.Sandbox.Signal(c.ID, sig)
}

// Checkpoint sends the checkpoint call to the container.
// The statefile will be written to f, the file at the specified image-path.
func (c *Container) Checkpoint(f *os.File) error {
	log.Debugf("Checkpoint container %q", c.ID)
	if c.Status == Stopped {
		log.Warningf("container %q not running, not checkpointing", c.ID)
		return nil
	}
	return c.Sandbox.Checkpoint(c.ID, f)
}

// Pause suspends the container and its kernel.
// The call only succeeds if the container's status is created or running.
func (c *Container) Pause() error {
	log.Debugf("Pausing container %q", c.ID)
	switch c.Status {
	case Created, Running:
		if err := c.Sandbox.Pause(c.ID); err != nil {
			return fmt.Errorf("error pausing container: %v", err)
		}
		c.Status = Paused
		return c.save()
	default:
		return fmt.Errorf("container %q not created or running, not pausing", c.ID)
	}
}

// Resume unpauses the container and its kernel.
// The call only succeeds if the container's status is paused.
func (c *Container) Resume() error {
	log.Debugf("Resuming container %q", c.ID)
	switch c.Status {
	case Paused:
		if err := c.Sandbox.Resume(c.ID); err != nil {
			return fmt.Errorf("error resuming container: %v", err)
		}
		c.Status = Running
		return c.save()
	default:
		return fmt.Errorf("container %q not paused, not resuming", c.ID)
	}
}

// State returns the metadata of the container.
func (c *Container) State() specs.State {
	return specs.State{
		Version: specs.Version,
		ID:      c.ID,
		Status:  c.Status.String(),
		Pid:     c.Pid(),
		Bundle:  c.BundleDir,
	}
}

// Processes retrieves the list of processes and associated metadata inside a
// container.
func (c *Container) Processes() ([]*control.Process, error) {
	if c.Status != Running && c.Status != Paused {
		return nil, fmt.Errorf("cannot get processes of container %q because it isn't running. It is in state %v", c.ID, c.Status)
	}
	return c.Sandbox.Processes(c.ID)
}

// Destroy frees all resources associated with the container.
func (c *Container) Destroy() error {
	log.Debugf("Destroy container %q", c.ID)

	// First stop the container.
	if c.Sandbox != nil {
		if err := c.Sandbox.Stop(c.ID); err != nil {
			return err
		}
	}

	// "If any poststop hook fails, the runtime MUST log a warning, but the
	// remaining hooks and lifecycle continue as if the hook had succeeded" -OCI spec.
	if c.Spec.Hooks != nil && (c.Status == Created || c.Status == Running) {
		executeHooksBestEffort(c.Spec.Hooks.Poststop, c.State())
	}

	if err := os.RemoveAll(c.Root); err != nil {
		log.Warningf("Failed to delete container root directory %q, err: %v", c.Root, err)
	}

	// If we are the first container in the sandbox, take the sandbox down
	// as well.
	if c.Sandbox != nil && c.Sandbox.IsRootContainer(c.ID) {
		if err := c.Sandbox.Destroy(); err != nil {
			log.Warningf("Failed to destroy sandbox %q: %v", c.Sandbox.ID, err)
		}
	}

	c.Sandbox = nil
	c.Status = Stopped

	return nil
}

// DestroyAndWait frees all resources associated with the container
// and waits for destroy to finish before returning.
func (c *Container) DestroyAndWait() error {
	sandboxPid := c.Sandbox.Pid
	goferPid := c.Sandbox.GoferPid

	if err := c.Destroy(); err != nil {
		return fmt.Errorf("error destroying container %v: %v", c, err)
	}

	if sandboxPid != 0 {
		if err := waitForDeath(sandboxPid, 5*time.Second); err != nil {
			return fmt.Errorf("error waiting for sandbox death: %v", err)
		}
	}

	if goferPid != 0 {
		if err := waitForDeath(goferPid, 5*time.Second); err != nil {
			return fmt.Errorf("error waiting for gofer death: %v", err)
		}
	}

	return nil
}

// save saves the container metadata to a file.
func (c *Container) save() error {
	log.Debugf("Save container %q", c.ID)
	if err := os.MkdirAll(c.Root, 0711); err != nil {
		return fmt.Errorf("error creating container root directory %q: %v", c.Root, err)
	}
	meta, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("error marshaling container metadata: %v", err)
	}
	metaFile := filepath.Join(c.Root, metadataFilename)
	if err := ioutil.WriteFile(metaFile, meta, 0640); err != nil {
		return fmt.Errorf("error writing container metadata: %v", err)
	}
	return nil
}

// waitForDeath ensures that process is dead before proceeding.
//
// This is racy because the kernel can potentially reuse the pid in the time
// between the process' death and the first check after the process has ended.
func waitForDeath(pid int, timeout time.Duration) error {
	backoff := 1 * time.Millisecond
	for start := time.Now(); time.Now().Sub(start) < timeout; {

		if err := syscall.Kill(pid, 0); err != nil {
			if err == syserror.ESRCH {
				// pid does not exist so process must have died
				return nil
			}
			return fmt.Errorf("error killing pid (%d): %v", pid, err)
		}
		// pid is still alive.

		// Process continues to run, backoff and retry.
		time.Sleep(backoff)
		backoff *= 2
		if backoff > 1*time.Second {
			backoff = 1 * time.Second
		}
	}
	return fmt.Errorf("timed out waiting for process (%d)", pid)
}
