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

// Package dockerutil is a collection of utility functions.
package dockerutil

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kr/pty"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

var (
	// runtime is the runtime to use for tests. This will be applied to all
	// containers. Note that the default here ("runsc") corresponds to the
	// default used by the installations. This is important, because the
	// default installer for vm_tests (in tools/installers:head, invoked
	// via tools/vm:defs.bzl) will install with this name. So without
	// changing anything, tests should have a runsc runtime available to
	// them. Otherwise installers should update the existing runtime
	// instead of installing a new one.
	runtime = flag.String("runtime", "runsc", "specify which runtime to use")

	// config is the default Docker daemon configuration path.
	config = flag.String("config_path", "/etc/docker/daemon.json", "configuration file for reading paths")
)

// EnsureSupportedDockerVersion checks if correct docker is installed.
//
// This logs directly to stderr, as it is typically called from a Main wrapper.
func EnsureSupportedDockerVersion() {
	cmd := exec.Command("docker", "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("error running %q: %v", "docker version", err)
	}
	re := regexp.MustCompile(`Version:\s+(\d+)\.(\d+)\.\d.*`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) != 3 {
		log.Fatalf("Invalid docker output: %s", out)
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	if major < 17 || (major == 17 && minor < 9) {
		log.Fatalf("Docker version 17.09.0 or greater is required, found: %02d.%02d", major, minor)
	}
}

// RuntimePath returns the binary path for the current runtime.
func RuntimePath() (string, error) {
	// Read the configuration data; the file must exist.
	configBytes, err := ioutil.ReadFile(*config)
	if err != nil {
		return "", err
	}

	// Unmarshal the configuration.
	c := make(map[string]interface{})
	if err := json.Unmarshal(configBytes, &c); err != nil {
		return "", err
	}

	// Decode the expected configuration.
	r, ok := c["runtimes"]
	if !ok {
		return "", fmt.Errorf("no runtimes declared: %v", c)
	}
	rs, ok := r.(map[string]interface{})
	if !ok {
		// The runtimes are not a map.
		return "", fmt.Errorf("unexpected format: %v", c)
	}
	r, ok = rs[*runtime]
	if !ok {
		// The expected runtime is not declared.
		return "", fmt.Errorf("runtime %q not found: %v", *runtime, c)
	}
	rs, ok = r.(map[string]interface{})
	if !ok {
		// The runtime is not a map.
		return "", fmt.Errorf("unexpected format: %v", c)
	}
	p, ok := rs["path"].(string)
	if !ok {
		// The runtime does not declare a path.
		return "", fmt.Errorf("unexpected format: %v", c)
	}
	return p, nil
}

// Save exports a container image to the given Writer.
//
// Note that the writer should be actively consuming the output, otherwise it
// is not guaranteed that the Save will make any progress and the call may
// stall indefinitely.
//
// This is called by criutil in order to import imports.
func Save(logger testutil.Logger, image string, w io.Writer) error {
	cmd := testutil.Command(logger, "docker", "save", testutil.ImageByName(image))
	cmd.Stdout = w // Send directly to the writer.
	return cmd.Run()
}

// MountMode describes if the mount should be ro or rw.
type MountMode int

const (
	// ReadOnly is what the name says.
	ReadOnly MountMode = iota
	// ReadWrite is what the name says.
	ReadWrite
)

// String returns the mount mode argument for this MountMode.
func (m MountMode) String() string {
	switch m {
	case ReadOnly:
		return "ro"
	case ReadWrite:
		return "rw"
	}
	panic(fmt.Sprintf("invalid mode: %d", m))
}

// DockerNetwork contains the name of a docker network.
type DockerNetwork struct {
	logger     testutil.Logger
	Name       string
	Subnet     *net.IPNet
	containers []*Docker
}

// NewDockerNetwork sets up the struct for a Docker network. Names of networks
// will be unique.
func NewDockerNetwork(logger testutil.Logger) *DockerNetwork {
	return &DockerNetwork{
		logger: logger,
		Name:   testutil.RandomID(logger.Name()),
	}
}

// Create calls 'docker network create'.
func (n *DockerNetwork) Create(args ...string) error {
	a := []string{"docker", "network", "create"}
	if n.Subnet != nil {
		a = append(a, fmt.Sprintf("--subnet=%s", n.Subnet))
	}
	a = append(a, args...)
	a = append(a, n.Name)
	return testutil.Command(n.logger, a...).Run()
}

// Connect calls 'docker network connect' with the arguments provided.
func (n *DockerNetwork) Connect(container *Docker, args ...string) error {
	a := []string{"docker", "network", "connect"}
	a = append(a, args...)
	a = append(a, n.Name, container.Name)
	if err := testutil.Command(n.logger, a...).Run(); err != nil {
		return err
	}
	n.containers = append(n.containers, container)
	return nil
}

// Cleanup cleans up the docker network and all the containers attached to it.
func (n *DockerNetwork) Cleanup() error {
	for _, c := range n.containers {
		// Don't propagate the error, it might be that the container
		// was already cleaned up.
		if err := c.Kill(); err != nil {
			n.logger.Logf("unable to kill container during cleanup: %s", err)
		}
	}

	if err := testutil.Command(n.logger, "docker", "network", "rm", n.Name).Run(); err != nil {
		return err
	}
	return nil
}

// Docker contains the name and the runtime of a docker container.
type Docker struct {
	logger   testutil.Logger
	Runtime  string
	Name     string
	copyErr  error
	cleanups []func()
}

// MakeDocker sets up the struct for a Docker container.
//
// Names of containers will be unique.
func MakeDocker(logger testutil.Logger) *Docker {
	// Slashes are not allowed in container names.
	name := testutil.RandomID(logger.Name())
	name = strings.ReplaceAll(name, "/", "-")

	return &Docker{
		logger:  logger,
		Name:    name,
		Runtime: *runtime,
	}
}

// CopyFiles copies in and mounts the given files. They are always ReadOnly.
func (d *Docker) CopyFiles(opts *RunOpts, targetDir string, sources ...string) {
	dir, err := ioutil.TempDir("", d.Name)
	if err != nil {
		d.copyErr = fmt.Errorf("ioutil.TempDir failed: %v", err)
		return
	}
	d.cleanups = append(d.cleanups, func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		d.copyErr = fmt.Errorf("os.Chmod(%q, 0755) failed: %v", dir, err)
		return
	}
	for _, name := range sources {
		src, err := testutil.FindFile(name)
		if err != nil {
			d.copyErr = fmt.Errorf("testutil.FindFile(%q) failed: %v", name, err)
			return
		}
		dst := path.Join(dir, path.Base(name))
		if err := testutil.Copy(src, dst); err != nil {
			d.copyErr = fmt.Errorf("testutil.Copy(%q, %q) failed: %v", src, dst, err)
			return
		}
		d.logger.Logf("copy: %s -> %s", src, dst)
	}
	opts.Mounts = append(opts.Mounts, Mount{
		Source: dir,
		Target: targetDir,
		Mode:   ReadOnly,
	})
}

// Mount describes a mount point inside the container.
type Mount struct {
	// Source is the path outside the container.
	Source string

	// Target is the path inside the container.
	Target string

	// Mode tells whether the mount inside the container should be readonly.
	Mode MountMode
}

// Link informs dockers that a given container needs to be made accessible from
// the container being configured.
type Link struct {
	// Source is the container to connect to.
	Source *Docker

	// Target is the alias for the container.
	Target string
}

// RunOpts are options for running a container.
type RunOpts struct {
	// Image is the image relative to images/. This will be mangled
	// appropriately, to ensure that only first-party images are used.
	Image string

	// Memory is the memory limit in kB.
	Memory int

	// Ports are the ports to be allocated.
	Ports []int

	// WorkDir sets the working directory.
	WorkDir string

	// ReadOnly sets the read-only flag.
	ReadOnly bool

	// Env are additional environment variables.
	Env []string

	// User is the user to use.
	User string

	// Privileged enables privileged mode.
	Privileged bool

	// CapAdd are the extra set of capabilities to add.
	CapAdd []string

	// CapDrop are the extra set of capabilities to drop.
	CapDrop []string

	// Pty indicates that a pty will be allocated. If this is non-nil, then
	// this will run after start-up with the *exec.Command and Pty file
	// passed in to the function.
	Pty func(*exec.Cmd, *os.File)

	// Foreground indicates that the container should be run in the
	// foreground. If this is true, then the output will be available as a
	// return value from the Run function.
	Foreground bool

	// Mounts is the list of directories/files to be mounted inside the container.
	Mounts []Mount

	// Links is the list of containers to be connected to the container.
	Links []Link

	// Extra are extra arguments that may be passed.
	Extra []string
}

// args returns common arguments.
//
// Note that this does not define the complete behavior.
func (d *Docker) argsFor(r *RunOpts, command string, p []string) (rv []string) {
	isExec := command == "exec"
	isRun := command == "run"

	if isRun || isExec {
		rv = append(rv, "-i")
	}
	if r.Pty != nil {
		rv = append(rv, "-t")
	}
	if r.User != "" {
		rv = append(rv, fmt.Sprintf("--user=%s", r.User))
	}
	if r.Privileged {
		rv = append(rv, "--privileged")
	}
	for _, c := range r.CapAdd {
		rv = append(rv, fmt.Sprintf("--cap-add=%s", c))
	}
	for _, c := range r.CapDrop {
		rv = append(rv, fmt.Sprintf("--cap-drop=%s", c))
	}
	for _, e := range r.Env {
		rv = append(rv, fmt.Sprintf("--env=%s", e))
	}
	if r.WorkDir != "" {
		rv = append(rv, fmt.Sprintf("--workdir=%s", r.WorkDir))
	}
	if !isExec {
		if r.Memory != 0 {
			rv = append(rv, fmt.Sprintf("--memory=%dk", r.Memory))
		}
		for _, p := range r.Ports {
			rv = append(rv, fmt.Sprintf("--publish=%d", p))
		}
		if r.ReadOnly {
			rv = append(rv, fmt.Sprintf("--read-only"))
		}
		if len(p) > 0 {
			rv = append(rv, "--entrypoint=")
		}
	}

	// Always attach the test environment & Extra.
	rv = append(rv, fmt.Sprintf("--env=RUNSC_TEST_NAME=%s", d.Name))
	rv = append(rv, r.Extra...)

	// Attach necessary bits.
	if isExec {
		rv = append(rv, d.Name)
	} else {
		for _, m := range r.Mounts {
			rv = append(rv, fmt.Sprintf("-v=%s:%s:%v", m.Source, m.Target, m.Mode))
		}
		for _, l := range r.Links {
			rv = append(rv, fmt.Sprintf("--link=%s:%s", l.Source.Name, l.Target))
		}

		if len(d.Runtime) > 0 {
			rv = append(rv, fmt.Sprintf("--runtime=%s", d.Runtime))
		}
		rv = append(rv, fmt.Sprintf("--name=%s", d.Name))
		rv = append(rv, testutil.ImageByName(r.Image))
	}

	// Attach other arguments.
	rv = append(rv, p...)
	return rv
}

// run runs a complete command.
func (d *Docker) run(r RunOpts, command string, p ...string) (string, error) {
	if d.copyErr != nil {
		return "", d.copyErr
	}
	basicArgs := []string{"docker"}
	if command == "spawn" {
		command = "run"
		basicArgs = append(basicArgs, command)
		basicArgs = append(basicArgs, "-d")
	} else {
		basicArgs = append(basicArgs, command)
	}
	customArgs := d.argsFor(&r, command, p)
	cmd := testutil.Command(d.logger, append(basicArgs, customArgs...)...)
	if r.Pty != nil {
		// If allocating a terminal, then we just ignore the output
		// from the command.
		ptmx, err := pty.Start(cmd.Cmd)
		if err != nil {
			return "", err
		}
		defer cmd.Wait() // Best effort.
		r.Pty(cmd.Cmd, ptmx)
	} else {
		// Can't support PTY or streaming.
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	return "", nil
}

// Create calls 'docker create' with the arguments provided.
func (d *Docker) Create(r RunOpts, args ...string) error {
	out, err := d.run(r, "create", args...)
	if strings.Contains(out, "Unable to find image") {
		return fmt.Errorf("unable to find image, did you remember to `make load-%s`: %w", r.Image, err)
	}
	return err
}

// Start calls 'docker start'.
func (d *Docker) Start() error {
	return testutil.Command(d.logger, "docker", "start", d.Name).Run()
}

// Stop calls 'docker stop'.
func (d *Docker) Stop() error {
	return testutil.Command(d.logger, "docker", "stop", d.Name).Run()
}

// Run calls 'docker run' with the arguments provided.
func (d *Docker) Run(r RunOpts, args ...string) (string, error) {
	return d.run(r, "run", args...)
}

// Spawn starts the container and detaches.
func (d *Docker) Spawn(r RunOpts, args ...string) error {
	_, err := d.run(r, "spawn", args...)
	return err
}

// Logs calls 'docker logs'.
func (d *Docker) Logs() (string, error) {
	// Don't capture the output; since it will swamp the logs.
	out, err := exec.Command("docker", "logs", d.Name).CombinedOutput()
	return string(out), err
}

// Exec calls 'docker exec' with the arguments provided.
func (d *Docker) Exec(r RunOpts, args ...string) (string, error) {
	return d.run(r, "exec", args...)
}

// Pause calls 'docker pause'.
func (d *Docker) Pause() error {
	return testutil.Command(d.logger, "docker", "pause", d.Name).Run()
}

// Unpause calls 'docker pause'.
func (d *Docker) Unpause() error {
	return testutil.Command(d.logger, "docker", "unpause", d.Name).Run()
}

// Checkpoint calls 'docker checkpoint'.
func (d *Docker) Checkpoint(name string) error {
	return testutil.Command(d.logger, "docker", "checkpoint", "create", d.Name, name).Run()
}

// Restore calls 'docker start --checkname [name]'.
func (d *Docker) Restore(name string) error {
	return testutil.Command(d.logger, "docker", "start", fmt.Sprintf("--checkpoint=%s", name), d.Name).Run()
}

// Kill calls 'docker kill'.
func (d *Docker) Kill() error {
	// Skip logging this command, it will likely be an error.
	out, err := exec.Command("docker", "kill", d.Name).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "is not running") {
		return err
	}
	return nil
}

// Remove calls 'docker rm'.
func (d *Docker) Remove() error {
	return testutil.Command(d.logger, "docker", "rm", d.Name).Run()
}

// CleanUp kills and deletes the container (best effort).
func (d *Docker) CleanUp() {
	// Kill the container.
	if err := d.Kill(); err != nil {
		// Just log; can't do anything here.
		d.logger.Logf("error killing container %q: %v", d.Name, err)
	}
	// Remove the image.
	if err := d.Remove(); err != nil {
		d.logger.Logf("error removing container %q: %v", d.Name, err)
	}
	// Execute all cleanups.
	for _, c := range d.cleanups {
		c()
	}
	d.cleanups = nil
}

// FindPort returns the host port that is mapped to 'sandboxPort'. This calls
// docker to allocate a free port in the host and prevent conflicts.
func (d *Docker) FindPort(sandboxPort int) (int, error) {
	format := fmt.Sprintf(`{{ (index (index .NetworkSettings.Ports "%d/tcp") 0).HostPort }}`, sandboxPort)
	out, err := testutil.Command(d.logger, "docker", "inspect", "-f", format, d.Name).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("error retrieving port: %v", err)
	}
	port, err := strconv.Atoi(strings.TrimSuffix(string(out), "\n"))
	if err != nil {
		return -1, fmt.Errorf("error parsing port %q: %v", out, err)
	}
	return port, nil
}

// FindIP returns the IP address of the container.
func (d *Docker) FindIP(ipv6 bool) (net.IP, error) {
	selector := "IPAddress"
	if ipv6 {
		selector = "GlobalIPv6Address"
	}
	format := fmt.Sprintf(`{{range .NetworkSettings.Networks}}{{.%s}}{{end}}`, selector)
	out, err := testutil.Command(d.logger, "docker", "inspect", "-f", format, d.Name).CombinedOutput()
	if err != nil {
		return net.IP{}, fmt.Errorf("error retrieving IP: %v", err)
	}
	ip := net.ParseIP(strings.TrimSpace(string(out)))
	if ip == nil {
		return net.IP{}, fmt.Errorf("invalid IP: %q", string(out))
	}
	return ip, nil
}

// A NetworkInterface is container's network interface information.
type NetworkInterface struct {
	IPv4 net.IP
	MAC  net.HardwareAddr
}

// ListNetworks returns the network interfaces of the container, keyed by
// Docker network name.
func (d *Docker) ListNetworks() (map[string]NetworkInterface, error) {
	const format = `{{json .NetworkSettings.Networks}}`
	out, err := testutil.Command(d.logger, "docker", "inspect", "-f", format, d.Name).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error network interfaces: %q: %w", string(out), err)
	}

	networks := map[string]map[string]string{}
	if err := json.Unmarshal(out, &networks); err != nil {
		return nil, fmt.Errorf("error decoding network interfaces: %w", err)
	}

	interfaces := map[string]NetworkInterface{}
	for name, iface := range networks {
		var netface NetworkInterface

		rawIP := strings.TrimSpace(iface["IPAddress"])
		if rawIP != "" {
			ip := net.ParseIP(rawIP)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP: %q", rawIP)
			}
			// Docker's IPAddress field is IPv4. The IPv6 address
			// is stored in the GlobalIPv6Address field.
			netface.IPv4 = ip
		}

		rawMAC := strings.TrimSpace(iface["MacAddress"])
		if rawMAC != "" {
			mac, err := net.ParseMAC(rawMAC)
			if err != nil {
				return nil, fmt.Errorf("invalid MAC: %q: %w", rawMAC, err)
			}
			netface.MAC = mac
		}

		interfaces[name] = netface
	}

	return interfaces, nil
}

// SandboxPid returns the PID to the sandbox process.
func (d *Docker) SandboxPid() (int, error) {
	out, err := testutil.Command(d.logger, "docker", "inspect", "-f={{.State.Pid}}", d.Name).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("error retrieving pid: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSuffix(string(out), "\n"))
	if err != nil {
		return -1, fmt.Errorf("error parsing pid %q: %v", out, err)
	}
	return pid, nil
}

// ID returns the container ID.
func (d *Docker) ID() (string, error) {
	out, err := testutil.Command(d.logger, "docker", "inspect", "-f={{.Id}}", d.Name).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error retrieving ID: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Wait waits for container to exit, up to the given timeout. Returns error if
// wait fails or timeout is hit. Returns the application return code otherwise.
// Note that the application may have failed even if err == nil, always check
// the exit code.
func (d *Docker) Wait(timeout time.Duration) (syscall.WaitStatus, error) {
	timeoutChan := time.After(timeout)
	waitChan := make(chan (syscall.WaitStatus))
	errChan := make(chan (error))

	go func() {
		out, err := testutil.Command(d.logger, "docker", "wait", d.Name).CombinedOutput()
		if err != nil {
			errChan <- fmt.Errorf("error waiting for container %q: %v", d.Name, err)
		}
		exit, err := strconv.Atoi(strings.TrimSuffix(string(out), "\n"))
		if err != nil {
			errChan <- fmt.Errorf("error parsing exit code %q: %v", out, err)
		}
		waitChan <- syscall.WaitStatus(uint32(exit))
	}()

	select {
	case ws := <-waitChan:
		return ws, nil
	case err := <-errChan:
		return syscall.WaitStatus(1), err
	case <-timeoutChan:
		return syscall.WaitStatus(1), fmt.Errorf("timeout waiting for container %q", d.Name)
	}
}

// WaitForOutput calls 'docker logs' to retrieve containers output and searches
// for the given pattern.
func (d *Docker) WaitForOutput(pattern string, timeout time.Duration) (string, error) {
	matches, err := d.WaitForOutputSubmatch(pattern, timeout)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", nil
	}
	return matches[0], nil
}

// WaitForOutputSubmatch calls 'docker logs' to retrieve containers output and
// searches for the given pattern. It returns any regexp submatches as well.
func (d *Docker) WaitForOutputSubmatch(pattern string, timeout time.Duration) ([]string, error) {
	re := regexp.MustCompile(pattern)
	var (
		lastOut string
		stopped bool
	)
	for exp := time.Now().Add(timeout); time.Now().Before(exp); {
		out, err := d.Logs()
		if err != nil {
			return nil, err
		}
		if out != lastOut {
			if lastOut == "" {
				d.logger.Logf("output (start): %s", out)
			} else if strings.HasPrefix(out, lastOut) {
				d.logger.Logf("output (contn): %s", out[len(lastOut):])
			} else {
				d.logger.Logf("output (trunc): %s", out)
			}
			lastOut = out // Save for future.
			if matches := re.FindStringSubmatch(lastOut); matches != nil {
				return matches, nil // Success!
			}
		} else if stopped {
			// The sandbox stopped and we looked at the
			// logs at least once since determining that.
			return nil, fmt.Errorf("no longer running: %v", err)
		} else if pid, err := d.SandboxPid(); pid == 0 || err != nil {
			// The sandbox may have stopped, but it's
			// possible that it has emitted the terminal
			// line between the last call to Logs and here.
			stopped = true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for output %q: %s", re.String(), lastOut)
}
