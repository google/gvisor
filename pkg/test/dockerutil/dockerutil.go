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
	"time"

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

	// The following flags are for the "pprof" profiler tool.

	// pprofBaseDir allows the user to change the directory to which profiles are
	// written. By default, profiles will appear under:
	// /tmp/profile/RUNTIME/CONTAINER_NAME/*.pprof.
	pprofBaseDir = flag.String("pprof-dir", "/tmp/profile", "base directory in: BASEDIR/RUNTIME/CONTINER_NAME/FILENAME (e.g. /tmp/profile/runtime/mycontainer/cpu.pprof)")

	// duration is the max duration `runsc debug` will run and capture profiles.
	// If the container's clean up method is called prior to duration, the
	// profiling process will be killed.
	duration = flag.Duration("pprof-duration", 10*time.Second, "duration to run the profile in seconds")

	// The below flags enable each type of profile. Multiple profiles can be
	// enabled for each run.
	pprofBlock = flag.Bool("pprof-block", false, "enables block profiling with runsc debug")
	pprofCPU   = flag.Bool("pprof-cpu", false, "enables CPU profiling with runsc debug")
	pprofHeap  = flag.Bool("pprof-heap", false, "enables heap profiling with runsc debug")
	pprofMutex = flag.Bool("pprof-mutex", false, "enables mutex profiling with runsc debug")
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
	rs, err := runtimeMap()
	if err != nil {
		return "", err
	}

	p, ok := rs["path"].(string)
	if !ok {
		// The runtime does not declare a path.
		return "", fmt.Errorf("runtime does not declare a path: %v", rs)
	}
	return p, nil
}

// UsingVFS2 returns true if the 'runtime' has the vfs2 flag set.
// TODO(gvisor.dev/issue/1624): Remove.
func UsingVFS2() (bool, error) {
	rMap, err := runtimeMap()
	if err != nil {
		return false, err
	}

	list, ok := rMap["runtimeArgs"].([]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected format: %v", rMap)
	}

	for _, element := range list {
		if element == "--vfs2" {
			return true, nil
		}
	}
	return false, nil
}

// UsingFUSE returns true if the 'runtime' has the fuse flag set.
func UsingFUSE() (bool, error) {
	rMap, err := runtimeMap()
	if err != nil {
		return false, err
	}

	list, ok := rMap["runtimeArgs"].([]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected format: %v", rMap)
	}

	for _, element := range list {
		if element == "--fuse" {
			return true, nil
		}
	}
	return false, nil
}

func runtimeMap() (map[string]interface{}, error) {
	// Read the configuration data; the file must exist.
	configBytes, err := ioutil.ReadFile(*config)
	if err != nil {
		return nil, err
	}

	// Unmarshal the configuration.
	c := make(map[string]interface{})
	if err := json.Unmarshal(configBytes, &c); err != nil {
		return nil, err
	}

	// Decode the expected configuration.
	r, ok := c["runtimes"]
	if !ok {
		return nil, fmt.Errorf("no runtimes declared: %v", c)
	}
	rs, ok := r.(map[string]interface{})
	if !ok {
		// The runtimes are not a map.
		return nil, fmt.Errorf("unexpected format: %v", rs)
	}
	r, ok = rs[*runtime]
	if !ok {
		// The expected runtime is not declared.
		return nil, fmt.Errorf("runtime %q not found: %v", *runtime, rs)
	}
	rs, ok = r.(map[string]interface{})
	if !ok {
		// The runtime is not a map.
		return nil, fmt.Errorf("unexpected format: %v", r)
	}
	return rs, nil
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
