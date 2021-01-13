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

// Package criutil contains utility functions for interacting with the
// Container Runtime Interface (CRI), principally via the crictl command line
// tool. This requires critools to be installed on the local system.
package criutil

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Crictl contains information required to run the crictl utility.
type Crictl struct {
	logger   testutil.Logger
	endpoint string
	cleanup  []func()
}

// ResolvePath attempts to find binary paths. It may set the path to invalid,
// which will cause the execution to fail with a sensible error.
func ResolvePath(executable string) string {
	runtime, err := dockerutil.RuntimePath()
	if err == nil {
		// Check first the directory of the runtime itself.
		if dir := path.Dir(runtime); dir != "" && dir != "." {
			guess := path.Join(dir, executable)
			if fi, err := os.Stat(guess); err == nil && (fi.Mode()&0111) != 0 {
				return guess
			}
		}
	}

	// Favor /usr/local/bin, if it exists.
	localBin := fmt.Sprintf("/usr/local/bin/%s", executable)
	if _, err := os.Stat(localBin); err == nil {
		return localBin
	}

	// Try to find via the path.
	guess, _ := exec.LookPath(executable)
	if err == nil {
		return guess
	}

	// Return a bare path; this generates a suitable error.
	return executable
}

// NewCrictl returns a Crictl configured with a timeout and an endpoint over
// which it will talk to containerd.
func NewCrictl(logger testutil.Logger, endpoint string) *Crictl {
	// Attempt to find the executable, but don't bother propagating the
	// error at this point. The first command executed will return with a
	// binary not found error.
	return &Crictl{
		logger:   logger,
		endpoint: endpoint,
	}
}

// CleanUp executes cleanup functions.
func (cc *Crictl) CleanUp() {
	for _, c := range cc.cleanup {
		c()
	}
	cc.cleanup = nil
}

// RunPod creates a sandbox. It corresponds to `crictl runp`.
func (cc *Crictl) RunPod(runtime, sbSpecFile string) (string, error) {
	podID, err := cc.run("runp", "--runtime", runtime, sbSpecFile)
	if err != nil {
		return "", fmt.Errorf("runp failed: %v", err)
	}
	// Strip the trailing newline from crictl output.
	return strings.TrimSpace(podID), nil
}

// Create creates a container within a sandbox. It corresponds to `crictl
// create`.
func (cc *Crictl) Create(podID, contSpecFile, sbSpecFile string) (string, error) {
	// In version 1.16.0, crictl annoying starting attempting to pull the
	// container, even if it was already available locally. We therefore
	// need to parse the version and add an appropriate --no-pull argument
	// since the image has already been loaded locally.
	out, err := cc.run("-v")
	if err != nil {
		return "", err
	}
	r := regexp.MustCompile("crictl version ([0-9]+)\\.([0-9]+)\\.([0-9+])")
	vs := r.FindStringSubmatch(out)
	if len(vs) != 4 {
		return "", fmt.Errorf("crictl -v had unexpected output: %s", out)
	}
	major, err := strconv.ParseUint(vs[1], 10, 64)
	if err != nil {
		return "", fmt.Errorf("crictl had invalid version: %v (%s)", err, out)
	}
	minor, err := strconv.ParseUint(vs[2], 10, 64)
	if err != nil {
		return "", fmt.Errorf("crictl had invalid version: %v (%s)", err, out)
	}

	args := []string{"create"}
	if (major == 1 && minor >= 16) || major > 1 {
		args = append(args, "--no-pull")
	}
	args = append(args, podID)
	args = append(args, contSpecFile)
	args = append(args, sbSpecFile)

	podID, err = cc.run(args...)
	if err != nil {
		time.Sleep(10 * time.Minute) // XXX
		return "", fmt.Errorf("create failed: %v", err)
	}

	// Strip the trailing newline from crictl output.
	return strings.TrimSpace(podID), nil
}

// Start starts a container. It corresponds to `crictl start`.
func (cc *Crictl) Start(contID string) (string, error) {
	output, err := cc.run("start", contID)
	if err != nil {
		return "", fmt.Errorf("start failed: %v", err)
	}
	return output, nil
}

// Stop stops a container. It corresponds to `crictl stop`.
func (cc *Crictl) Stop(contID string) error {
	_, err := cc.run("stop", contID)
	return err
}

// Exec execs a program inside a container. It corresponds to `crictl exec`.
func (cc *Crictl) Exec(contID string, args ...string) (string, error) {
	a := []string{"exec", contID}
	a = append(a, args...)
	output, err := cc.run(a...)
	if err != nil {
		return "", fmt.Errorf("exec failed: %v", err)
	}
	return output, nil
}

// Logs retrieves the container logs. It corresponds to `crictl logs`.
func (cc *Crictl) Logs(contID string, args ...string) (string, error) {
	a := []string{"logs", contID}
	a = append(a, args...)
	output, err := cc.run(a...)
	if err != nil {
		return "", fmt.Errorf("logs failed: %v", err)
	}
	return output, nil
}

// Rm removes a container. It corresponds to `crictl rm`.
func (cc *Crictl) Rm(contID string) error {
	_, err := cc.run("rm", contID)
	return err
}

// StopPod stops a pod. It corresponds to `crictl stopp`.
func (cc *Crictl) StopPod(podID string) error {
	_, err := cc.run("stopp", podID)
	return err
}

// containsConfig is a minimal copy of
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/apis/cri/runtime/v1alpha2/api.proto
// It only contains fields needed for testing.
type containerConfig struct {
	Status containerStatus
}

type containerStatus struct {
	Network containerNetwork
}

type containerNetwork struct {
	IP string
}

// PodIP returns a pod's IP address.
func (cc *Crictl) PodIP(podID string) (string, error) {
	output, err := cc.run("inspectp", podID)
	if err != nil {
		return "", err
	}
	conf := &containerConfig{}
	if err := json.Unmarshal([]byte(output), conf); err != nil {
		return "", fmt.Errorf("failed to unmarshal JSON: %v, %s", err, output)
	}
	if conf.Status.Network.IP == "" {
		return "", fmt.Errorf("no IP found in config: %s", output)
	}
	return conf.Status.Network.IP, nil
}

// RmPod removes a container. It corresponds to `crictl rmp`.
func (cc *Crictl) RmPod(podID string) error {
	_, err := cc.run("rmp", podID)
	return err
}

// Import imports the given container from the local Docker instance.
func (cc *Crictl) Import(image string) error {
	// Note that we provide a 10 minute timeout after connect because we may
	// be pushing a lot of bytes in order to import the image. The connect
	// timeout stays the same and is inherited from the Crictl instance.
	cmd := testutil.Command(cc.logger,
		ResolvePath("ctr"),
		fmt.Sprintf("--connect-timeout=%s", 30*time.Second),
		fmt.Sprintf("--address=%s", cc.endpoint),
		"-n", "k8s.io", "images", "import", "-")
	cmd.Stderr = os.Stderr // Pass through errors.

	// Create a pipe and start the program.
	w, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	// Save the image on the other end.
	if err := dockerutil.Save(cc.logger, image, w); err != nil {
		cmd.Wait()
		return err
	}

	// Close our pipe reference & see if it was loaded.
	if err := w.Close(); err != nil {
		return w.Close()
	}

	return cmd.Wait()
}

// StartContainer pulls the given image ands starts the container in the
// sandbox with the given podID.
//
// Note that the image will always be imported from the local docker daemon.
func (cc *Crictl) StartContainer(podID, image, sbSpec, contSpec string) (string, error) {
	if err := cc.Import(image); err != nil {
		return "", err
	}

	// Write the specs to files that can be read by crictl.
	sbSpecFile, cleanup, err := testutil.WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		return "", fmt.Errorf("failed to write sandbox spec: %v", err)
	}
	cc.cleanup = append(cc.cleanup, cleanup)
	contSpecFile, cleanup, err := testutil.WriteTmpFile("contSpec", contSpec)
	if err != nil {
		return "", fmt.Errorf("failed to write container spec: %v", err)
	}
	cc.cleanup = append(cc.cleanup, cleanup)

	return cc.startContainer(podID, image, sbSpecFile, contSpecFile)
}

func (cc *Crictl) startContainer(podID, image, sbSpecFile, contSpecFile string) (string, error) {
	contID, err := cc.Create(podID, contSpecFile, sbSpecFile)
	if err != nil {
		return "", fmt.Errorf("failed to create container in pod %q: %v", podID, err)
	}

	if _, err := cc.Start(contID); err != nil {
		return "", fmt.Errorf("failed to start container %q in pod %q: %v", contID, podID, err)
	}

	return contID, nil
}

// StopContainer stops and deletes the container with the given container ID.
func (cc *Crictl) StopContainer(contID string) error {
	if err := cc.Stop(contID); err != nil {
		return fmt.Errorf("failed to stop container %q: %v", contID, err)
	}

	if err := cc.Rm(contID); err != nil {
		return fmt.Errorf("failed to remove container %q: %v", contID, err)
	}

	return nil
}

// StartPodAndContainer starts a sandbox and container in that sandbox. It
// returns the pod ID and container ID.
func (cc *Crictl) StartPodAndContainer(runtime, image, sbSpec, contSpec string) (string, string, error) {
	if err := cc.Import(image); err != nil {
		return "", "", err
	}

	// Write the specs to files that can be read by crictl.
	sbSpecFile, cleanup, err := testutil.WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to write sandbox spec: %v", err)
	}
	cc.cleanup = append(cc.cleanup, cleanup)
	contSpecFile, cleanup, err := testutil.WriteTmpFile("contSpec", contSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to write container spec: %v", err)
	}
	cc.cleanup = append(cc.cleanup, cleanup)

	podID, err := cc.RunPod(runtime, sbSpecFile)
	if err != nil {
		return "", "", err
	}

	contID, err := cc.startContainer(podID, image, sbSpecFile, contSpecFile)

	return podID, contID, err
}

// StopPodAndContainer stops a container and pod.
func (cc *Crictl) StopPodAndContainer(podID, contID string) error {
	if err := cc.StopContainer(contID); err != nil {
		return fmt.Errorf("failed to stop container %q in pod %q: %v", contID, podID, err)
	}

	if err := cc.StopPod(podID); err != nil {
		return fmt.Errorf("failed to stop pod %q: %v", podID, err)
	}

	if err := cc.RmPod(podID); err != nil {
		return fmt.Errorf("failed to remove pod %q: %v", podID, err)
	}

	return nil
}

// run runs crictl with the given args.
func (cc *Crictl) run(args ...string) (string, error) {
	defaultArgs := []string{
		ResolvePath("crictl"),
		"--image-endpoint", fmt.Sprintf("unix://%s", cc.endpoint),
		"--runtime-endpoint", fmt.Sprintf("unix://%s", cc.endpoint),
	}
	fullArgs := append(defaultArgs, args...)
	out, err := testutil.Command(cc.logger, fullArgs...).CombinedOutput()
	return string(out), err
}
