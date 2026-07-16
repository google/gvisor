// Copyright 2026 The gVisor Authors.
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

// This file provides end-to-end docker-in-gVisor (DinD) tests.
package image

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	yaml "gopkg.in/yaml.v3"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func dockerInGvisorCapabilities() []string {
	return []string{
		"audit_write",
		"chown",
		"dac_override",
		"fowner",
		"fsetid",
		"kill",
		"mknod",
		"net_admin",
		"net_bind_service",
		"net_raw",
		"setfcap",
		"setgid",
		"setpcap",
		"setuid",
		"sys_admin",
		"sys_chroot",
		"sys_ptrace",
	}
}

type dockerCommandOptions struct {
	hostNetwork bool
	privileged  bool
}

type dockerComposeConfig struct {
	Name     string                   `yaml:"name,omitempty"`
	Services map[string]dockerService `yaml:"services,omitempty"`
}

type dockerService struct {
	Image        string      `yaml:"image,omitempty"`
	Build        dockerBuild `yaml:"build,omitempty"`
	Privileged   bool        `yaml:"privileged,omitempty"`
	NetworkdMode string      `yaml:"network_mode,omitempty"`
}

type dockerBuild struct {
	Context string `yaml:"context,omitempty"`
	Network string `yaml:"network,omitempty"`
}

func testDockerMatrix(t *testing.T, overlay bool) {
	definitions := []struct {
		name            string
		testFunc        func(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions)
		testHostNetwork bool
		testPrivileged  bool
	}{
		{"docker_run", testDockerRun, true, true},
		{"docker_build", testDockerBuild, true, false},
		{"docker_exec", testDockerExec, false, true},
		{"docker_compose_run", testDockerComposeRun, true, true},
		{"docker_compose_build", testDockerComposeBuild, true, false},
	}
	for _, def := range definitions {
		hostNetworkOpts := []bool{false}
		if def.testHostNetwork {
			hostNetworkOpts = []bool{true, false}
		}
		privilegedOpts := []bool{false}
		if def.testPrivileged {
			privilegedOpts = []bool{true, false}
		}
		for _, hostNetwork := range hostNetworkOpts {
			for _, privileged := range privilegedOpts {
				opts := dockerCommandOptions{
					hostNetwork: hostNetwork,
					privileged:  privileged,
				}
				var nameParts []string
				nameParts = append(nameParts, def.name)
				if def.testHostNetwork {
					if hostNetwork {
						nameParts = append(nameParts, "host_network")
					} else {
						nameParts = append(nameParts, "bridge_network")
					}
				}
				if def.testPrivileged {
					if privileged {
						nameParts = append(nameParts, "privileged")
					} else {
						nameParts = append(nameParts, "non_privileged")
					}
				}
				name := strings.Join(nameParts, "_")
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()
					d := startDockerdInGvisor(ctx, t, overlay)
					defer d.CleanUp(ctx)
					if err := backoff.Retry(func() error {
						output, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "info"})
						if err != nil {
							return fmt.Errorf("docker exec failed: %v", err)
						}
						if !strings.Contains(output, "Cannot connect to the Docker daemon") {
							return nil
						}
						return fmt.Errorf("docker daemon not ready")
					}, backoff.WithMaxRetries(backoff.NewConstantBackOff(1*time.Second), 10)); err != nil {
						t.Fatalf("failed to run docker test %q: %v", name, err)
					}
					def.testFunc(ctx, t, d, opts)
				})
			}
		}
	}
}

func TestDockerWithVFS(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		t.Skip("docker doesn't work with hostinet")
	}
	testDockerMatrix(t, false)
}

func TestDockerWithOverlay(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		t.Skip("docker doesn't work with hostinet")
	}
	testDockerMatrix(t, true)
}

// The container returned by this function has to be cleaned up by the caller.
func startDockerdInGvisor(ctx context.Context, t *testing.T, overlay bool) *dockerutil.Container {
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-docker")

	// Start the container which starts dockerd.
	opts := dockerutil.RunOpts{
		Image:  "basic/docker",
		CapAdd: dockerInGvisorCapabilities(),
	}

	var args []string
	if !overlay {
		args = append(args, "--no-overlay")
	}
	if err := d.Spawn(ctx, opts, args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Wait for the docker daemon.
	cb := backoff.NewConstantBackOff(5 * time.Second)
	err := backoff.Retry(func() error {
		_, err := d.Exec(ctx, dockerutil.ExecOpts{}, "docker", "info")
		return err
	}, backoff.WithMaxRetries(cb, 10))
	if err != nil {
		t.Fatalf("docker daemon failed to start: %v", err)
	}
	return d
}

// checkDockerImage list available images and checks if the given image is
// present.
func checkDockerImage(ctx context.Context, imageName string, d *dockerutil.Container) error {
	listImages, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", "docker images")
	if err != nil {
		return fmt.Errorf("docker exec failed: %v", err)
	}
	got, err := listImages.Logs()
	if err != nil {
		return fmt.Errorf("docker logs failed: %v", err)
	}
	if !strings.Contains(got, imageName) {
		return fmt.Errorf("docker didn't get expected image: %q, got: %q", imageName, got)
	}
	return nil
}

func removeDockerImage(ctx context.Context, imageName string, d *dockerutil.Container) error {
	cmd := []string{"docker", "image", "rm", imageName}
	_, err := d.ExecProcess(
		ctx,
		dockerutil.ExecOpts{},
		"/bin/sh", "-c", strings.Join(cmd, " "))
	if err != nil {
		return fmt.Errorf("docker exec failed: %v", err)
	}
	return nil
}

func dockerInGvisorExecOutput(ctx context.Context, d *dockerutil.Container, cmd []string) (string, error) {
	execProc, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, cmd...)
	if err != nil {
		return "", fmt.Errorf("docker exec failed: %v", err)
	}
	output, err := execProc.Logs()
	if err != nil {
		return "", fmt.Errorf("docker logs failed: %v", err)
	}
	return output, nil
}

func testDockerRun(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	cmd := []string{"docker", "run", "--rm"}
	if opts.hostNetwork {
		cmd = append(cmd, "--network", "host")
	}
	if opts.privileged {
		cmd = append(cmd, "--privileged")
	}
	cmd = append(cmd, testAlpineImage, "sh", "-c", "apk add curl && apk info -d curl")

	expectedOutput := "URL retrival utility and library"
	output, err := dockerInGvisorExecOutput(ctx, d, cmd)
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if !strings.Contains(output, expectedOutput) {
		t.Fatalf("docker didn't get output expected: %q, got: %q", expectedOutput, output)
	}
}

func testDockerBuild(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	parts := []string{"echo", fmt.Sprintf("\"FROM %s\nRUN apk add git\"", testAlpineImage), "|", "docker", "build"}
	if opts.hostNetwork {
		parts = append(parts, "--network", "host")
	}
	imageName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("test_docker_build"), "/", "-"))
	parts = append(parts, "-t", imageName, "-f", "-", ".")
	cmd := strings.Join(parts, " ")
	_, err := dockerInGvisorExecOutput(ctx, d, []string{"/bin/sh", "-c", cmd})
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	defer removeDockerImage(ctx, imageName, d)
	if err := checkDockerImage(ctx, imageName, d); err != nil {
		t.Fatalf("failed to find docker image: %v", err)
	}
}

func testDockerExec(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	containerName := strings.ReplaceAll(testutil.RandomID("test_docker_exec"), "/", "-")
	// Start a container with a sleep command to ensure that the container
	// doesn't exit immediately.
	cmd := []string{"docker", "run", "--rm", "-d", "--name", containerName, testAlpineImage, "sleep", "180"}
	_, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, cmd...)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	// Kill the container at the end of the test.
	defer func() {
		_, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, []string{"docker", "kill", containerName}...)
		if err != nil {
			t.Fatalf("docker container kill failed: %v", err)
		}
	}()

	cb := backoff.NewConstantBackOff(5 * time.Second)
	err = backoff.Retry(func() error {
		inspectOutput, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "container", "inspect", containerName})
		if err != nil {
			return err
		}
		if !strings.Contains(inspectOutput, "\"Status\": \"running\"") {
			return fmt.Errorf("container %s is not running yet", containerName)
		}
		return nil
	}, backoff.WithMaxRetries(cb, 10))
	if err != nil {
		t.Fatalf("container failed to start: %v", err)
	}

	execCmd := []string{"docker", "exec"}
	if opts.privileged {
		execCmd = append(execCmd, "--privileged")
	}
	// Execute echo command in the container.
	execCmd = append(execCmd, containerName, "echo", "exec in "+containerName)

	output, err := dockerInGvisorExecOutput(ctx, d, execCmd)
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	expectedOutput := "exec in " + containerName
	if !strings.Contains(output, expectedOutput) {
		t.Fatalf("docker didn't get output expected: %q, got: %q", expectedOutput, output)
	}
}

func testDockerComposeBuild(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	dockerComposeFileName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("docker-compose-build"), "/", "-"))
	// Letters in image name must be lowercase.
	imageName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("testdockercomposebuild"), "/", "-"))
	network := ""
	if opts.hostNetwork {
		network = "host"
	} else {
		// TODO(https://gvisor.dev/issues/11937): re-enable bridge network test.
		t.Skip("Skip docker compose build test with bridge network.")
	}
	config := dockerComposeConfig{
		Name: "image_test",
		Services: map[string]dockerService{
			imageName: dockerService{
				Image: imageName,
				Build: dockerBuild{
					Context: ".",
					Network: network,
				},
			},
		},
	}
	buildConfig, err := yaml.Marshal(config)
	if err != nil {
		log.Fatalf("error marshaling to docker-compose.yml: %v", err)
	}
	dockerfileContent := fmt.Sprintf("\"FROM %s\nRUN apk add curl\"", testAlpineImage)
	cmd := []string{"echo", dockerfileContent, ">", "Dockerfile"}
	_, err = d.ExecProcess(ctx, dockerutil.ExecOpts{},
		"/bin/sh", "-c", strings.Join(cmd, " "))
	if err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}
	cmd = []string{"echo", fmt.Sprintf("\"%s\"", string(buildConfig)), ">", dockerComposeFileName}
	// Write a config file for docker compose.
	_, err = d.ExecProcess(ctx, dockerutil.ExecOpts{},
		"/bin/sh", "-c", strings.Join(cmd, " "))
	if err != nil {
		t.Fatalf("failed to write docker-compose.yml: %v", err)
	}
	_, err = d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", fmt.Sprintf("docker compose -f %s build", dockerComposeFileName))
	if err != nil {
		t.Fatalf("docker compose build failed: %v", err)
	}
	defer removeDockerImage(ctx, imageName, d)
	d.WaitForOutput(ctx, fmt.Sprintf("%s  Built", imageName), defaultWait)
	if err := checkDockerImage(ctx, imageName, d); err != nil {
		t.Fatalf("failed to find docker image: %v", err)
	}
}

func testDockerComposeRun(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	dockerComposeAppName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("docker-compose-run-test-app"), "/", "-"))
	dockerComposeFileName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("docker-compose-run"), "/", "-"))
	networkMode := ""
	// TODO(b/436936268): test bridge network driver in docker compose run.
	// The option now has no impact since the test command doesn't attempt to connect to internet.
	if opts.hostNetwork {
		networkMode = "host"
	}
	config := dockerComposeConfig{
		Name: "image_test",
		Services: map[string]dockerService{
			dockerComposeAppName: dockerService{
				Image:        testAlpineImage,
				Privileged:   opts.privileged,
				NetworkdMode: networkMode,
			},
		},
	}
	dockerComposeContent, err := yaml.Marshal(config)
	if err != nil {
		log.Fatalf("error marshaling to docker-compose.yml: %v", err)
	}
	cmd := []string{"echo", fmt.Sprintf("\"%s\"", string(dockerComposeContent)), ">", dockerComposeFileName}
	_, err = d.ExecProcess(
		ctx,
		dockerutil.ExecOpts{},
		"/bin/sh", "-c", strings.Join(cmd, " "))
	if err != nil {
		t.Fatalf("failed to write %s: %v", dockerComposeFileName, err)
	}
	execProc, err := d.ExecProcess(ctx, dockerutil.ExecOpts{},
		[]string{"docker", "compose", "-f", dockerComposeFileName, "run", "--rm", dockerComposeAppName, "sh", "-c", "echo hello gVisor"}...)
	if err != nil {
		t.Fatalf("docker compose run failed: %v", err)
	}
	output, err := execProc.Logs()
	if err != nil {
		t.Fatalf("docker logs failed: %v", err)
	}
	expectedOutput := "hello gVisor"
	if !strings.Contains(output, expectedOutput) {
		t.Fatalf("docker didn't get output expected: %q, got: %q", expectedOutput, output)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
