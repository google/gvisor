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

// Package image provides end-to-end image tests for runsc.

// Each test calls docker commands to start up a container, and tests that it
// is behaving properly, like connecting to a port or looking at the output.
// The container is killed and deleted at the end.
//
// Setup instruction in test/README.md.
package image

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	yaml "gopkg.in/yaml.v3"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

var testAlpineImage = func() string {
	switch runtime.GOARCH {
	case "amd64":
		return "gcr.io/gvisor-presubmit/basic/alpine_x86_64:latest"
	case "arm64":
		return "gcr.io/gvisor-presubmit/basic/alpine_aarch64:latest"
	default:
		panic(fmt.Sprintf("unsupported architecture: %s", runtime.GOARCH))
	}
}()

// defaultWait defines how long to wait for progress.
//
// See BUILD: This is at least a "large" test, so allow up to 1 minute for any
// given "wait" step. Note that all tests are run in parallel, which may cause
// individual slow-downs (but a huge speed-up in aggregate).
const defaultWait = time.Minute

func TestHelloWorld(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Run the basic container.
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "echo", "Hello world!")
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check the output.
	if !strings.Contains(out, "Hello world!") {
		t.Fatalf("docker didn't say hello: got %s", out)
	}
}

func TestRust(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Run the basic container.
	out, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/rust",
	})
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Check the output.
	if !strings.Contains(out, "Hello, World!") {
		t.Fatalf("Container didn't say Hello, World!: got %s", out)
	}
}

func runHTTPRequest(ip string, port int) error {
	url := fmt.Sprintf("http://%s:%d/not-found", ip, port)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error reaching http server: %v", err)
	}
	if want := http.StatusNotFound; resp.StatusCode != want {
		return fmt.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}

	url = fmt.Sprintf("http://%s:%d/latin10k.txt", ip, port)
	resp, err = http.Get(url)
	if err != nil {
		return fmt.Errorf("Error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		return fmt.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Error reading http response: %v", err)
	}
	defer resp.Body.Close()

	// READALL is the last word in the file. Ensures everything was read.
	if want := "READALL"; strings.HasSuffix(string(body), want) {
		return fmt.Errorf("response doesn't contain %q, resp: %q", want, body)
	}
	return nil
}

func testHTTPServer(t *testing.T, ip string, port int) {
	const requests = 10
	ch := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func() {
			start := time.Now()
			err := runHTTPRequest(ip, port)
			log.Printf("Response time %v: %v", time.Since(start).String(), err)
			ch <- err
		}()
	}

	for i := 0; i < requests; i++ {
		err := <-ch
		if err != nil {
			t.Errorf("testHTTPServer(%s, %d) failed: %v", ip, port, err)
		}
	}
}

func TestHttpd(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 80
	opts := dockerutil.RunOpts{
		Image: "basic/httpd",
	}
	d.CopyFiles(&opts, "/usr/local/apache2/htdocs", "test/image/latin10k.txt")
	if err := d.Spawn(ctx, opts); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, ip.String(), port)
}

func TestNginx(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the container.
	port := 80
	opts := dockerutil.RunOpts{
		Image: "basic/nginx",
	}
	d.CopyFiles(&opts, "/usr/share/nginx/html", "test/image/latin10k.txt")
	if err := d.Spawn(ctx, opts); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Errorf("WaitForHTTP() timeout: %v", err)
	}

	testHTTPServer(t, ip.String(), port)
}

func TestMysql(t *testing.T) {
	ctx := context.Background()
	server := dockerutil.MakeContainer(ctx, t)
	defer server.CleanUp(ctx)

	// Start the container.
	if err := server.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/mysql",
		Env: []string{
			"MYSQL_ROOT_PASSWORD=foobar123",
			"MYSQL_ROOT_HOST=%", // Allow anyone to connect to the server.
		},
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Wait until it's up and running.
	if _, err := server.WaitForOutput(ctx, "port: 3306  MySQL Community Server", defaultWait); err != nil {
		t.Fatalf("WaitForOutput() timeout: %v", err)
	}

	// Generate the client and copy in the SQL payload.
	client := dockerutil.MakeContainer(ctx, t)
	defer client.CleanUp(ctx)

	// Tell mysql client to connect to the server and execute the file in
	// verbose mode to verify the output.
	opts := dockerutil.RunOpts{
		Image: "basic/mysql",
		Links: []string{server.MakeLink("mysql")},
	}
	client.CopyFiles(&opts, "/sql", "test/image/mysql.sql")
	if _, err := client.Run(ctx, opts, "mysql", "-hmysql", "-uroot", "-pfoobar123", "-v", "-e", "source /sql/mysql.sql"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Ensure file executed to the end and shutdown mysql.
	if _, err := server.WaitForOutput(ctx, "mysqld: Shutdown complete", defaultWait); err != nil {
		t.Fatalf("WaitForOutput() timeout: %v", err)
	}
}

func TestTomcat(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start the server.
	port := 8080
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/tomcat",
	}); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, defaultWait); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v", err)
	}

	// Ensure that content is being served.
	url := fmt.Sprintf("http://%s:%d", ip.String(), port)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("Error reaching http server: %v", err)
	}
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("Wrong response code, got: %d, want: %d", resp.StatusCode, want)
	}
}

func dockerLogs(ctx context.Context, d *dockerutil.Container) string {
	logs, err := d.Logs(ctx)
	if err != nil {
		return fmt.Sprintf("Failed to get docker logs: %v", err)
	}
	return fmt.Sprintf("\n%s", logs)
}

func TestRuby(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Execute the ruby workload.
	port := 8080
	opts := dockerutil.RunOpts{
		Image: "image-test/ruby",
	}

	if err := d.Spawn(ctx, opts); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Find container IP address.
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		t.Fatalf("docker.FindIP failed: %v", err)
	}

	// Wait until it's up and running.
	if err := testutil.WaitForHTTP(ip.String(), port, time.Minute); err != nil {
		t.Fatalf("WaitForHTTP() timeout: %v, docker logs: %v", err, dockerLogs(ctx, d))
	}

	// Ensure that content is being served.
	url := fmt.Sprintf("http://%s:%d", ip.String(), port)
	resp, err := http.Get(url)
	if err != nil {
		t.Errorf("error reaching http server: %v, docker logs: %v", err, dockerLogs(ctx, d))
	}
	if want := http.StatusOK; resp.StatusCode != want {
		t.Errorf("wrong response code, got: %d, want: %d, docker logs: %v", resp.StatusCode, want, dockerLogs(ctx, d))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("error reading body: %v, docker logs: %v", err, dockerLogs(ctx, d))
	}
	if got, want := string(body), "Hello World"; !strings.Contains(got, want) {
		t.Errorf("invalid body content, got: %q, want: %q, docker logs: %v", got, want, dockerLogs(ctx, d))
	}
}

func TestStdio(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	wantStdout := "hello stdout"
	wantStderr := "bonjour stderr"
	cmd := fmt.Sprintf("echo %q; echo %q 1>&2;", wantStdout, wantStderr)
	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "/bin/sh", "-c", cmd); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	for _, want := range []string{wantStdout, wantStderr} {
		if _, err := d.WaitForOutput(ctx, want, defaultWait); err != nil {
			t.Fatalf("docker didn't get output %q : %v", want, err)
		}
	}
}

func TestTcpdump(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		t.Skip("docker doesn't work with hostinet")
	}
	ctx := context.Background()
	// The "-docker" runtime comes with the net_raw capabilities enabled which are
	// required for tcpdump.
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-docker")
	defer d.CleanUp(ctx)

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image: "basic/tcpdump",
	}, "sleep", "infinity"); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Stick to `lo` to avoid catching packets from the host. The "port 9999"
	// does not actually do anything because we do not yet support installing
	// a filter bpf program.
	cmd := "tcpdump -c 2 -i lo port 9999"
	tcpdumpProc, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	cmd = "python3 sender.py"
	senderProc, err := d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	if status, err := senderProc.WaitExitStatus(ctx); err != nil || status != 0 {
		t.Fatalf("docker exec failed: %v, status: %d", err, status)
	}
	if status, err := tcpdumpProc.WaitExitStatus(ctx); err != nil || status != 0 {
		t.Fatalf("docker exec failed: %v, status: %d", err, status)
	}
	expectedOutputStr1 := "IP localhost.9999 > localhost.9999: UDP, length 4"
	logs, err := tcpdumpProc.Logs()
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	if !strings.Contains(logs, expectedOutputStr1) {
		t.Fatalf("docker didn't get output: %q, got: %q", expectedOutputStr1, logs)
	}
	expectedOutputStr2 := "IP localhost.9999 > localhost.9999: UDP, length 8"
	if !strings.Contains(logs, expectedOutputStr2) {
		t.Fatalf("docker didn't get output: %q, got: %q", expectedOutputStr2, logs)
	}

	// Check that `any` also works to guard against b/411198401.
	cmd = "tcpdump -c 2 -i any port 9999"
	tcpdumpProc, err = d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	cmd = "python3 sender.py"
	senderProc, err = d.ExecProcess(ctx, dockerutil.ExecOpts{}, "/bin/sh", "-c", cmd)
	if err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}

	// We make no assertions about the output because we might catch host packets
	// too: we only rely on tcpdump's exit status.
	if status, err := tcpdumpProc.WaitExitStatus(ctx); err != nil || status != 0 {
		t.Fatalf("docker exec failed: %v, status: %d", err, status)
	}
	if status, err := senderProc.WaitExitStatus(ctx); err != nil || status != 0 {
		t.Fatalf("docker exec failed: %v, status: %d", err, status)
	}
}

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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	d := startDockerdInGvisor(ctx, t, overlay)
	defer d.CleanUp(ctx)

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
	t.Parallel()
	testDockerMatrix(t, false)
}

func TestDockerWithOverlay(t *testing.T) {
	if testutil.IsRunningWithHostNet() {
		t.Skip("docker doesn't work with hostinet")
	}
	t.Parallel()
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
	cb := backoff.NewConstantBackOff(1 * time.Second)
	if err := backoff.Retry(func() error {
		_, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "info"})
		return err
	}, backoff.WithMaxRetries(cb, 30)); err != nil {
		t.Fatalf("docker daemon failed to start: %v", err)
	}
	return d
}

// checkDockerImage list available images and checks if the given image is
// present.
func checkDockerImage(ctx context.Context, imageName string, d *dockerutil.Container) error {
	_, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "image", "inspect", imageName})
	if err != nil {
		return fmt.Errorf("docker image inspect %q failed: %v", imageName, err)
	}
	return nil
}

func removeDockerImage(ctx context.Context, imageName string, d *dockerutil.Container) error {
	_, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "image", "rm", imageName})
	return err
}

func writeFileInContainer(ctx context.Context, d *dockerutil.Container, filePath, content string) error {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	cmd := []string{"/bin/sh", "-c", `echo "$1" | base64 -d > "$2"`, "--", encoded, filePath}
	_, err := dockerInGvisorExecOutput(ctx, d, cmd)
	return err
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
	status, err := execProc.ExitCode(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get exit code: %v", err)
	}
	if status != 0 {
		return output, fmt.Errorf("command %v failed with status %d, output: %q", cmd, status, output)
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
	tmpDir, err := d.Exec(ctx, dockerutil.ExecOpts{}, "mktemp", "-d")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	tmpDir = strings.TrimSpace(tmpDir)
	defer func() {
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "rm", "-rf", tmpDir); err != nil {
			t.Logf("failed to cleanup temp dir %s: %v", tmpDir, err)
		}
	}()

	dockerfilePath := path.Join(tmpDir, "Dockerfile")
	dockerfileContent := fmt.Sprintf("FROM %s\nRUN apk add git\n", testAlpineImage)
	if err := writeFileInContainer(ctx, d, dockerfilePath, dockerfileContent); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}

	imageName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("test_docker_build"), "/", "-"))
	cmd := []string{"docker", "build"}
	if opts.hostNetwork {
		cmd = append(cmd, "--network", "host")
	}
	cmd = append(cmd, "-t", imageName, tmpDir)
	if _, err := dockerInGvisorExecOutput(ctx, d, cmd); err != nil {
		t.Fatalf("docker exec failed: %v", err)
	}
	defer func() {
		if err := removeDockerImage(ctx, imageName, d); err != nil {
			t.Logf("failed to remove docker image %s: %v", imageName, err)
		}
	}()
	if err := checkDockerImage(ctx, imageName, d); err != nil {
		t.Fatalf("failed to find docker image: %v", err)
	}
}

func testDockerExec(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	containerName := strings.ReplaceAll(testutil.RandomID("test_docker_exec"), "/", "-")
	// Start a container with a sleep command to ensure that the container
	// doesn't exit immediately.
	cmd := []string{"docker", "run", "--rm", "-d", "--name", containerName, testAlpineImage, "sleep", "180"}
	if _, err := dockerInGvisorExecOutput(ctx, d, cmd); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	// Kill the container at the end of the test.
	defer func() {
		if _, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "kill", containerName}); err != nil {
			t.Logf("docker container kill failed: %v", err)
		}
	}()

	cb := backoff.NewConstantBackOff(500 * time.Millisecond)
	err := backoff.Retry(func() error {
		inspectOutput, err := dockerInGvisorExecOutput(ctx, d, []string{"docker", "container", "inspect", containerName})
		if err != nil {
			return err
		}
		if !strings.Contains(inspectOutput, "\"Status\": \"running\"") {
			return fmt.Errorf("container %s is not running yet", containerName)
		}
		return nil
	}, backoff.WithMaxRetries(cb, 20))
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
	tmpDir, err := d.Exec(ctx, dockerutil.ExecOpts{}, "mktemp", "-d")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	tmpDir = strings.TrimSpace(tmpDir)
	defer func() {
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "rm", "-rf", tmpDir); err != nil {
			t.Logf("failed to cleanup temp dir %s: %v", tmpDir, err)
		}
	}()

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
		t.Fatalf("error marshaling to docker-compose.yml: %v", err)
	}
	dockerfileContent := fmt.Sprintf("FROM %s\nRUN apk add curl\n", testAlpineImage)
	dockerfilePath := path.Join(tmpDir, "Dockerfile")
	dockerComposePath := path.Join(tmpDir, "docker-compose.yml")

	if err := writeFileInContainer(ctx, d, dockerfilePath, dockerfileContent); err != nil {
		t.Fatalf("failed to write Dockerfile: %v", err)
	}
	if err := writeFileInContainer(ctx, d, dockerComposePath, string(buildConfig)); err != nil {
		t.Fatalf("failed to write docker-compose.yml: %v", err)
	}

	cmd := []string{"docker", "compose", "-f", dockerComposePath, "build"}
	if _, err := dockerInGvisorExecOutput(ctx, d, cmd); err != nil {
		t.Fatalf("docker compose build failed: %v", err)
	}
	defer func() {
		if err := removeDockerImage(ctx, imageName, d); err != nil {
			t.Logf("failed to remove docker image %s: %v", imageName, err)
		}
	}()

	if err := checkDockerImage(ctx, imageName, d); err != nil {
		t.Fatalf("failed to find docker image: %v", err)
	}
}

func testDockerComposeRun(ctx context.Context, t *testing.T, d *dockerutil.Container, opts dockerCommandOptions) {
	tmpDir, err := d.Exec(ctx, dockerutil.ExecOpts{}, "mktemp", "-d")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	tmpDir = strings.TrimSpace(tmpDir)
	defer func() {
		if _, err := d.Exec(ctx, dockerutil.ExecOpts{}, "rm", "-rf", tmpDir); err != nil {
			t.Logf("failed to cleanup temp dir %s: %v", tmpDir, err)
		}
	}()

	dockerComposeAppName := strings.ToLower(strings.ReplaceAll(testutil.RandomID("docker-compose-run-test-app"), "/", "-"))
	dockerComposeFilePath := path.Join(tmpDir, "docker-compose.yml")
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
		t.Fatalf("error marshaling to docker-compose.yml: %v", err)
	}

	if err := writeFileInContainer(ctx, d, dockerComposeFilePath, string(dockerComposeContent)); err != nil {
		t.Fatalf("failed to write %s: %v", dockerComposeFilePath, err)
	}

	cmd := []string{"docker", "compose", "-f", dockerComposeFilePath, "run", "--rm", dockerComposeAppName, "sh", "-c", "echo hello gVisor"}
	output, err := dockerInGvisorExecOutput(ctx, d, cmd)
	if err != nil {
		t.Fatalf("docker compose run failed: %v", err)
	}
	expectedOutput := "hello gVisor"
	if !strings.Contains(output, expectedOutput) {
		t.Fatalf("docker didn't get output expected: %q, got: %q", expectedOutput, output)
	}
}

func TestPIDFDSelftests(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	runOpts := dockerutil.RunOpts{
		Image:      "basic/pidfd-tests",
		Privileged: true,
	}
	out, err := d.Run(ctx, runOpts)
	if err != nil {
		t.Fatalf("docker run failed; output: %v, err: %v", out, err)
	} else {
		t.Logf("docker run succeeded; output: %v", out)
	}
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}
