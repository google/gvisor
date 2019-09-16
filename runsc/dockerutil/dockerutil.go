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

// Package dockerutil is a collection of utility functions, primarily for
// testing.
package dockerutil

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kr/pty"
	"gvisor.dev/gvisor/runsc/testutil"
)

var (
	runtime = flag.String("runtime", "runsc", "specify which runtime to use")
	config  = flag.String("config_path", "/etc/docker/daemon.json", "configuration file for reading paths")
)

// EnsureSupportedDockerVersion checks if correct docker is installed.
func EnsureSupportedDockerVersion() {
	cmd := exec.Command("docker", "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Error running %q: %v", "docker version", err)
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

// MountArg formats the volume argument to mount in the container.
func MountArg(source, target string, mode MountMode) string {
	return fmt.Sprintf("-v=%s:%s:%v", source, target, mode)
}

// LinkArg formats the link argument.
func LinkArg(source *Docker, target string) string {
	return fmt.Sprintf("--link=%s:%s", source.Name, target)
}

// PrepareFiles creates temp directory to copy files there. The sandbox doesn't
// have access to files in the test dir.
func PrepareFiles(names ...string) (string, error) {
	dir, err := ioutil.TempDir("", "image-test")
	if err != nil {
		return "", fmt.Errorf("ioutil.TempDir failed: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		return "", fmt.Errorf("os.Chmod(%q, 0777) failed: %v", dir, err)
	}
	for _, name := range names {
		src := getLocalPath(name)
		dst := path.Join(dir, name)
		if err := testutil.Copy(src, dst); err != nil {
			return "", fmt.Errorf("testutil.Copy(%q, %q) failed: %v", src, dst, err)
		}
	}
	return dir, nil
}

func getLocalPath(file string) string {
	return path.Join(".", file)
}

// do executes docker command.
func do(args ...string) (string, error) {
	log.Printf("Running: docker %s\n", args)
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing docker %s: %v\nout: %s", args, err, out)
	}
	return string(out), nil
}

// doWithPty executes docker command with stdio attached to a pty.
func doWithPty(args ...string) (*exec.Cmd, *os.File, error) {
	log.Printf("Running with pty: docker %s\n", args)
	cmd := exec.Command("docker", args...)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("error executing docker %s with a pty: %v", args, err)
	}
	return cmd, ptmx, nil
}

// Pull pulls a docker image. This is used in tests to isolate the
// time to pull the image off the network from the time to actually
// start the container, to avoid timeouts over slow networks.
func Pull(image string) error {
	_, err := do("pull", image)
	return err
}

// Docker contains the name and the runtime of a docker container.
type Docker struct {
	Runtime string
	Name    string
}

// MakeDocker sets up the struct for a Docker container.
// Names of containers will be unique.
func MakeDocker(namePrefix string) Docker {
	return Docker{
		Name:    testutil.RandomName(namePrefix),
		Runtime: *runtime,
	}
}

// logDockerID logs a container id, which is needed to find container runsc logs.
func (d *Docker) logDockerID() {
	id, err := d.ID()
	if err != nil {
		log.Printf("%v\n", err)
	}
	log.Printf("Name: %s ID: %v\n", d.Name, id)
}

// Create calls 'docker create' with the arguments provided.
func (d *Docker) Create(args ...string) error {
	a := []string{"create", "--runtime", d.Runtime, "--name", d.Name}
	a = append(a, args...)
	_, err := do(a...)
	if err == nil {
		d.logDockerID()
	}
	return err
}

// Start calls 'docker start'.
func (d *Docker) Start() error {
	if _, err := do("start", d.Name); err != nil {
		return fmt.Errorf("error starting container %q: %v", d.Name, err)
	}
	return nil
}

// Stop calls 'docker stop'.
func (d *Docker) Stop() error {
	if _, err := do("stop", d.Name); err != nil {
		return fmt.Errorf("error stopping container %q: %v", d.Name, err)
	}
	return nil
}

// Run calls 'docker run' with the arguments provided. The container starts
// running in the background and the call returns immediately.
func (d *Docker) Run(args ...string) error {
	a := d.runArgs("-d")
	a = append(a, args...)
	_, err := do(a...)
	if err == nil {
		d.logDockerID()
	}
	return err
}

// RunWithPty is like Run but with an attached pty.
func (d *Docker) RunWithPty(args ...string) (*exec.Cmd, *os.File, error) {
	a := d.runArgs("-it")
	a = append(a, args...)
	return doWithPty(a...)
}

// RunFg calls 'docker run' with the arguments provided in the foreground. It
// blocks until the container exits and returns the output.
func (d *Docker) RunFg(args ...string) (string, error) {
	a := d.runArgs(args...)
	out, err := do(a...)
	if err == nil {
		d.logDockerID()
	}
	return string(out), err
}

func (d *Docker) runArgs(args ...string) []string {
	// Environment variable RUNSC_TEST_NAME is picked up by the runtime and added
	// to the log name, so one can easily identify the corresponding logs for
	// this test.
	rv := []string{"run", "--runtime", d.Runtime, "--name", d.Name, "-e", "RUNSC_TEST_NAME=" + d.Name}
	return append(rv, args...)
}

// Logs calls 'docker logs'.
func (d *Docker) Logs() (string, error) {
	return do("logs", d.Name)
}

// Exec calls 'docker exec' with the arguments provided.
func (d *Docker) Exec(args ...string) (string, error) {
	a := []string{"exec", d.Name}
	a = append(a, args...)
	return do(a...)
}

// ExecWithTerminal calls 'docker exec -it' with the arguments provided and
// attaches a pty to stdio.
func (d *Docker) ExecWithTerminal(args ...string) (*exec.Cmd, *os.File, error) {
	a := []string{"exec", "-it", d.Name}
	a = append(a, args...)
	return doWithPty(a...)
}

// Pause calls 'docker pause'.
func (d *Docker) Pause() error {
	if _, err := do("pause", d.Name); err != nil {
		return fmt.Errorf("error pausing container %q: %v", d.Name, err)
	}
	return nil
}

// Unpause calls 'docker pause'.
func (d *Docker) Unpause() error {
	if _, err := do("unpause", d.Name); err != nil {
		return fmt.Errorf("error unpausing container %q: %v", d.Name, err)
	}
	return nil
}

// Checkpoint calls 'docker checkpoint'.
func (d *Docker) Checkpoint(name string) error {
	if _, err := do("checkpoint", "create", d.Name, name); err != nil {
		return fmt.Errorf("error pausing container %q: %v", d.Name, err)
	}
	return nil
}

// Restore calls 'docker start --checkname [name]'.
func (d *Docker) Restore(name string) error {
	if _, err := do("start", "--checkpoint", name, d.Name); err != nil {
		return fmt.Errorf("error starting container %q: %v", d.Name, err)
	}
	return nil
}

// Remove calls 'docker rm'.
func (d *Docker) Remove() error {
	if _, err := do("rm", d.Name); err != nil {
		return fmt.Errorf("error deleting container %q: %v", d.Name, err)
	}
	return nil
}

// CleanUp kills and deletes the container (best effort).
func (d *Docker) CleanUp() {
	d.logDockerID()
	if _, err := do("kill", d.Name); err != nil {
		if strings.Contains(err.Error(), "is not running") {
			// Nothing to kill. Don't log the error in this case.
		} else {
			log.Printf("error killing container %q: %v", d.Name, err)
		}
	}
	if err := d.Remove(); err != nil {
		log.Print(err)
	}
}

// FindPort returns the host port that is mapped to 'sandboxPort'. This calls
// docker to allocate a free port in the host and prevent conflicts.
func (d *Docker) FindPort(sandboxPort int) (int, error) {
	format := fmt.Sprintf(`{{ (index (index .NetworkSettings.Ports "%d/tcp") 0).HostPort }}`, sandboxPort)
	out, err := do("inspect", "-f", format, d.Name)
	if err != nil {
		return -1, fmt.Errorf("error retrieving port: %v", err)
	}
	port, err := strconv.Atoi(strings.TrimSuffix(string(out), "\n"))
	if err != nil {
		return -1, fmt.Errorf("error parsing port %q: %v", out, err)
	}
	return port, nil
}

// SandboxPid returns the PID to the sandbox process.
func (d *Docker) SandboxPid() (int, error) {
	out, err := do("inspect", "-f={{.State.Pid}}", d.Name)
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
	out, err := do("inspect", "-f={{.Id}}", d.Name)
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
		out, err := do("wait", d.Name)
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
	var out string
	for exp := time.Now().Add(timeout); time.Now().Before(exp); {
		var err error
		out, err = d.Logs()
		if err != nil {
			return nil, err
		}
		if matches := re.FindStringSubmatch(out); matches != nil {
			// Success!
			return matches, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for output %q: %s", re.String(), out)
}
