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

package testutil

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func runtime() string {
	r := os.Getenv("RUNSC_RUNTIME")
	if r == "" {
		return "runsc-test"
	}
	return r
}

// IsPauseResumeSupported returns true if Pause/Resume is supported by runtime.
func IsPauseResumeSupported() bool {
	// Native host network stack can't be saved.
	return !strings.Contains(runtime(), "hostnet")
}

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

// MountArg formats the volume argument to mount in the container.
func MountArg(source, target string) string {
	return fmt.Sprintf("%s:%s", source, target)
}

// LinkArg formats the link argument.
func LinkArg(source *Docker, target string) string {
	return fmt.Sprintf("%s:%s", source.Name, target)
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
		if err := Copy(src, dst); err != nil {
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
	fmt.Printf("Running: docker %s\n", args)
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing docker %s: %v\nout: %s", args, err, out)
	}
	return string(out), nil
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
	suffix := fmt.Sprintf("-%06d", rand.Int())[:7]
	return Docker{Name: namePrefix + suffix, Runtime: runtime()}
}

// Create calls 'docker create' with the arguments provided.
func (d *Docker) Create(args ...string) error {
	a := []string{"create", "--runtime", d.Runtime, "--name", d.Name}
	a = append(a, args...)
	_, err := do(a...)
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

// Run calls 'docker run' with the arguments provided.
func (d *Docker) Run(args ...string) (string, error) {
	a := []string{"run", "--runtime", d.Runtime, "--name", d.Name, "-d"}
	a = append(a, args...)
	return do(a...)
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

// Remove calls 'docker rm'.
func (d *Docker) Remove() error {
	if _, err := do("rm", d.Name); err != nil {
		return fmt.Errorf("error deleting container %q: %v", d.Name, err)
	}
	return nil
}

// CleanUp kills and deletes the container.
func (d *Docker) CleanUp() error {
	if _, err := do("kill", d.Name); err != nil {
		return fmt.Errorf("error killing container %q: %v", d.Name, err)
	}
	return d.Remove()
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

// WaitForOutput calls 'docker logs' to retrieve containers output and searches
// for the given pattern.
func (d *Docker) WaitForOutput(pattern string, timeout time.Duration) error {
	re := regexp.MustCompile(pattern)
	var out string
	for exp := time.Now().Add(timeout); time.Now().Before(exp); {
		var err error
		out, err = do("logs", d.Name)
		if err != nil {
			return err
		}
		if re.MatchString(out) {
			// Success!
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for output %q: %s", re.String(), out)
}
