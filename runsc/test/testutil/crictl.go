// Copyright 2018 Google LLC
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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const endpointPrefix = "unix://"

// Crictl contains information required to run the crictl utility.
type Crictl struct {
	executable      string
	timeout         time.Duration
	imageEndpoint   string
	runtimeEndpoint string
}

// NewCrictl returns a Crictl configured with a timeout and an endpoint over
// which it will talk to containerd.
func NewCrictl(timeout time.Duration, endpoint string) *Crictl {
	// Bazel doesn't pass PATH through, assume the location of crictl
	// unless specified by environment variable.
	executable := os.Getenv("CRICTL_PATH")
	if executable == "" {
		executable = "/usr/local/bin/crictl"
	}
	return &Crictl{
		executable:      executable,
		timeout:         timeout,
		imageEndpoint:   endpointPrefix + endpoint,
		runtimeEndpoint: endpointPrefix + endpoint,
	}
}

// Pull pulls an container image. It corresponds to `crictl pull`.
func (cc *Crictl) Pull(imageName string) error {
	_, err := cc.run("pull", imageName)
	return err
}

// RunPod creates a sandbox. It corresponds to `crictl runp`.
func (cc *Crictl) RunPod(sbSpecFile string) (string, error) {
	podID, err := cc.run("runp", sbSpecFile)
	if err != nil {
		return "", fmt.Errorf("runp failed: %v", err)
	}
	// Strip the trailing newline from crictl output.
	return strings.TrimSpace(podID), nil
}

// Create creates a container within a sandbox. It corresponds to `crictl
// create`.
func (cc *Crictl) Create(podID, contSpecFile, sbSpecFile string) (string, error) {
	podID, err := cc.run("create", podID, contSpecFile, sbSpecFile)
	if err != nil {
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

// StartPodAndContainer pulls an image, then starts a sandbox and container in
// that sandbox. It returns the pod ID and container ID.
func (cc *Crictl) StartPodAndContainer(image, sbSpec, contSpec string) (string, string, error) {
	if err := cc.Pull(image); err != nil {
		return "", "", fmt.Errorf("failed to pull %s: %v", image, err)
	}

	// Write the specs to files that can be read by crictl.
	sbSpecFile, err := WriteTmpFile("sbSpec", sbSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to write sandbox spec: %v", err)
	}
	contSpecFile, err := WriteTmpFile("contSpec", contSpec)
	if err != nil {
		return "", "", fmt.Errorf("failed to write container spec: %v", err)
	}

	podID, err := cc.RunPod(sbSpecFile)
	if err != nil {
		return "", "", err
	}

	contID, err := cc.Create(podID, contSpecFile, sbSpecFile)
	if err != nil {
		return "", "", fmt.Errorf("failed to create container in pod %q: %v", podID, err)
	}

	if _, err := cc.Start(contID); err != nil {
		return "", "", fmt.Errorf("failed to start container %q in pod %q: %v", contID, podID, err)
	}

	return podID, contID, nil
}

// StopPodAndContainer stops a container and pod.
func (cc *Crictl) StopPodAndContainer(podID, contID string) error {
	if err := cc.Stop(contID); err != nil {
		return fmt.Errorf("failed to stop container %q in pod %q: %v", contID, podID, err)
	}

	if err := cc.Rm(contID); err != nil {
		return fmt.Errorf("failed to remove container %q in pod %q: %v", contID, podID, err)
	}

	if err := cc.StopPod(podID); err != nil {
		return fmt.Errorf("failed to stop pod %q: %v", podID, err)
	}

	if err := cc.RmPod(podID); err != nil {
		return fmt.Errorf("failed to remove pod %q: %v", podID, err)
	}

	return nil
}

// run runs crictl with the given args and returns an error if it takes longer
// than cc.Timeout to run.
func (cc *Crictl) run(args ...string) (string, error) {
	defaultArgs := []string{
		"--image-endpoint", cc.imageEndpoint,
		"--runtime-endpoint", cc.runtimeEndpoint,
	}
	cmd := exec.Command(cc.executable, append(defaultArgs, args...)...)

	// Run the command with a timeout.
	done := make(chan string)
	errCh := make(chan error)
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			errCh <- fmt.Errorf("error: \"%v\", output: %s", err, string(output))
		}
		done <- string(output)
	}()
	select {
	case output := <-done:
		return output, nil
	case err := <-errCh:
		return "", err
	case <-time.After(cc.timeout):
		if err := KillCommand(cmd); err != nil {
			return "", fmt.Errorf("timed out, then couldn't kill process %+v: %v", cmd, err)
		}
		return "", fmt.Errorf("timed out: %+v", cmd)
	}
}
