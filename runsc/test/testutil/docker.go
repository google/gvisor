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
	"net/http"
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
		return "", fmt.Errorf("error executing docker %s: %v", args, err)
	}
	return string(out), nil
}

// Pull pulls a docker image. This is used in tests to isolate the
// time to pull the image off the network from the time to actually
// start the container, to avoid timeouts over slow networks.
func Pull(image string) (string, error) {
	return do("pull", image)
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

// Run calls 'docker run' with the arguments provided.
func (d *Docker) Run(args ...string) (string, error) {
	a := []string{"run", "--runtime", d.Runtime, "--name", d.Name, "-d"}
	a = append(a, args...)
	return do(a...)
}

// CleanUp kills and deletes the container.
func (d *Docker) CleanUp() error {
	if _, err := do("kill", d.Name); err != nil {
		return fmt.Errorf("error killing container %q: %v", d.Name, err)
	}
	if _, err := do("rm", d.Name); err != nil {
		return fmt.Errorf("error deleting container %q: %v", d.Name, err)
	}
	return nil
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

// WaitForHTTP tries GET requests on a port until the call succeeds or a timeout.
func (d *Docker) WaitForHTTP(port int, timeout time.Duration) error {
	for exp := time.Now().Add(timeout); time.Now().Before(exp); {
		url := fmt.Sprintf("http://localhost:%d/", port)
		if _, err := http.Get(url); err == nil {
			// Success!
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for HTTP server on port %d", port)
}
