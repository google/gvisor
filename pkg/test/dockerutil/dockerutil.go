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
	"os/exec"
	"regexp"
	"strconv"

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

// Runtime returns the value of the flag runtime.
func Runtime() string {
	return *runtime
}
