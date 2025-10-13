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
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/cgroup"
)

var (
	// runtime is the runtime to use for tests. This will be applied to all
	// containers. Note that the default here ("runsc") corresponds to the
	// default used by the installations.
	runtime = flag.String("runtime", os.Getenv("RUNTIME"), "specify which runtime to use")

	// dockerCLI is the path to the docker CLI binary.
	dockerCLI = flag.String("docker_cli", os.Getenv("DOCKER_CLI_PATH"), "path to the docker client command-line binary")

	// config is the default Docker daemon configuration path.
	config = flag.String("config_path", "/etc/docker/daemon.json", "configuration file for reading paths")

	// pgoBenchmarks is a flag that is set during PGO benchmarks.
	// This flag restricts the set of benchmark targets to run.
	pgoBenchmarks = flag.Bool("pgo-benchmarks", false, "set to true for PGO benchmarks; restricts the set of benchmark targets to run")

	// The following flags are for the "pprof" profiler tool.

	// pprofBaseDir allows the user to change the directory to which profiles are
	// written. By default, profiles will appear under:
	// /tmp/profile/RUNTIME/CONTAINER_NAME/*.pprof.
	pprofBaseDir  = flag.String("pprof-dir", "/tmp/profile", "base directory in: BASEDIR/RUNTIME/CONTINER_NAME/FILENAME (e.g. /tmp/profile/runtime/mycontainer/cpu.pprof)")
	pprofDuration = flag.Duration("pprof-duration", time.Hour, "profiling duration (automatically stopped at container exit)")

	// The below flags enable each type of profile. Multiple profiles can be
	// enabled for each run. The profile will be collected from the start.
	pprofBlock = flag.Bool("pprof-block", false, "enables block profiling with runsc debug")
	pprofCPU   = flag.Bool("pprof-cpu", false, "enables CPU profiling with runsc debug")
	pprofHeap  = flag.Bool("pprof-heap", false, "enables heap profiling with runsc debug")
	pprofMutex = flag.Bool("pprof-mutex", false, "enables mutex profiling with runsc debug")
	trace      = flag.Bool("go-trace", false, "enables collecting a go trace with runsc debug")

	// This matches the string "native.cgroupdriver=systemd" (including optional
	// whitespace), which can be found in a docker daemon configuration file's
	// exec-opts field.
	useSystemdRgx = regexp.MustCompile("\\s*(native\\.cgroupdriver)\\s*=\\s*(systemd)\\s*")
)

// dockerCLIPath returns the path to the docker CLI binary.
func dockerCLIPath() string {
	if *dockerCLI != "" {
		return *dockerCLI
	}
	return "docker"
}

// PrintDockerConfig prints the whole Docker configuration file to the log.
func PrintDockerConfig() {
	configBytes, err := os.ReadFile(*config)
	if err != nil {
		log.Fatalf("Cannot read Docker config at %v: %v", *config, err)
	}
	log.Printf("Docker config (from %v):\n--------\n%v\n--------\n", *config, string(configBytes))
}

func getDockerVersion() (int, int) {
	cmd := exec.Command(dockerCLIPath(), "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("error running %q: %v", dockerCLIPath()+" version", err)
	}
	re := regexp.MustCompile(`Version:\s+(\d+)\.(\d+)\.\d.*`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) != 3 {
		log.Fatalf("Invalid docker output: %s", out)
	}
	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	return major, minor
}

// EnsureSupportedDockerVersion checks if correct docker is installed.
//
// This logs directly to stderr, as it is typically called from a Main wrapper.
func EnsureSupportedDockerVersion() {
	major, minor := getDockerVersion()
	if major < 17 || (major == 17 && minor < 9) {
		log.Fatalf("Docker version 17.09.0 or greater is required, found: %02d.%02d", major, minor)
	}
}

// EnsureDockerExperimentalEnabled ensures that Docker has experimental features enabled.
func EnsureDockerExperimentalEnabled() {
	cmd := exec.Command(dockerCLIPath(), "version", "--format={{.Server.Experimental}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("error running %s: %v", dockerCLIPath()+" version --format='{{.Server.Experimental}}'", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		PrintDockerConfig()
		log.Fatalf("Docker is running without experimental features enabled.")
	}
}

// IsRestoreSupported returns true if the docker version supports restore.
// Docker restore broke starting v28 due to
// https://github.com/moby/moby/issues/50750.
func IsRestoreSupported() bool {
	major, _ := getDockerVersion()
	return major <= 27
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

// RuntimeArgs returns the arguments for the current runtime.
func RuntimeArgs() ([]string, error) {
	rs, err := runtimeMap()
	if err != nil {
		return nil, err
	}
	argsAny, ok := rs["runtimeArgs"]
	if !ok {
		// The runtime does not have any arguments.
		return nil, nil
	}
	argsAnySlice, ok := argsAny.([]any)
	if !ok {
		return nil, fmt.Errorf("runtime arguments should be a list of strings, got: %q (type: %T)", argsAny, argsAny)
	}
	args := make([]string, 0, len(argsAnySlice))
	for i, argAny := range argsAnySlice {
		arg, ok := argAny.(string)
		if !ok {
			return nil, fmt.Errorf("runtime arguments should be a list of strings, got: %q (index %d is %q which has unexpected type %T)", argsAny, i, argAny, argAny)
		}
		args = append(args, arg)
	}
	return args, nil
}

// IsGVisorRuntime returns whether the default container runtime used by
// `dockerutil` is gVisor-based or not.
func IsGVisorRuntime(ctx context.Context, t *testing.T) (bool, error) {
	output, err := MakeContainer(ctx, t).Run(ctx, RunOpts{Image: "basic/alpine"}, "dmesg")
	if err != nil {
		if strings.Contains(output, "dmesg: klogctl: Operation not permitted") {
			return false, nil
		}
		return false, fmt.Errorf("failed to run dmesg: %v (output: %q)", err, output)
	}
	return strings.Contains(output, "gVisor"), nil
}

// IsPGO returns true if the test is a PGO benchmark run.
func IsPGO() bool {
	return *pgoBenchmarks
}

// SkipIfPGO skips the test if it is a PGO benchmark run.
func SkipIfPGO[TB testing.TB](tb TB) {
	if *pgoBenchmarks {
		tb.Skip("Skipped as this is a PGO benchmark run.")
	}
}

// UsingSystemdCgroup returns true if the docker configuration has the
// native.cgroupdriver=systemd option set in "exec-opts", or if the
// system is using cgroupv2, in which case systemd is the default driver.
func UsingSystemdCgroup() (bool, error) {
	// Read the configuration data; the file must exist.
	configBytes, err := os.ReadFile(*config)
	if err != nil {
		return false, err
	}
	// Unmarshal the configuration.
	c := make(map[string]any)
	if err := json.Unmarshal(configBytes, &c); err != nil {
		return false, err
	}
	// Decode the expected configuration.
	e, ok := c["exec-opts"]
	if !ok {
		// No exec-opts. Default is true on cgroupv2, false otherwise.
		return cgroup.IsOnlyV2(), nil
	}
	eos, ok := e.([]any)
	if !ok {
		// The exec opts are not an array.
		return false, fmt.Errorf("unexpected format: %+v", eos)
	}
	for _, opt := range eos {
		if optStr, ok := opt.(string); ok && useSystemdRgx.MatchString(optStr) {
			return true, nil
		}
	}
	return false, nil
}

func runtimeMap() (map[string]any, error) {
	// Read the configuration data; the file must exist.
	configBytes, err := os.ReadFile(*config)
	if err != nil {
		return nil, err
	}

	// Unmarshal the configuration.
	c := make(map[string]any)
	if err := json.Unmarshal(configBytes, &c); err != nil {
		return nil, err
	}

	// Decode the expected configuration.
	r, ok := c["runtimes"]
	if !ok {
		return nil, fmt.Errorf("no runtimes declared: %v", c)
	}
	rs, ok := r.(map[string]any)
	if !ok {
		// The runtimes are not a map.
		return nil, fmt.Errorf("unexpected format: %v", rs)
	}
	r, ok = rs[*runtime]
	if !ok {
		// The expected runtime is not declared.
		return nil, fmt.Errorf("runtime %q not found: %v", *runtime, rs)
	}
	rs, ok = r.(map[string]any)
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
	cmd := testutil.Command(logger, dockerCLIPath(), "save", testutil.ImageByName(image))
	cmd.Stdout = w // Send directly to the writer.
	return cmd.Run()
}

// Runtime returns the value of the flag runtime.
func Runtime() string {
	return *runtime
}
