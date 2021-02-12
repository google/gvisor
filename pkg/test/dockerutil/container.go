// Copyright 2020 The gVisor Authors.
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

package dockerutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Container represents a Docker Container allowing
// user to configure and control as one would with the 'docker'
// client. Container is backed by the offical golang docker API.
// See: https://pkg.go.dev/github.com/docker/docker.
type Container struct {
	Name    string
	runtime string

	logger   testutil.Logger
	client   *client.Client
	id       string
	mounts   []mount.Mount
	links    []string
	copyErr  error
	cleanups []func()

	// profile is the profiling hook associated with this container.
	profile *profile
}

// RunOpts are options for running a container.
type RunOpts struct {
	// Image is the image relative to images/. This will be mangled
	// appropriately, to ensure that only first-party images are used.
	Image string

	// Memory is the memory limit in bytes.
	Memory int

	// Cpus in which to allow execution. ("0", "1", "0-2").
	CpusetCpus string

	// Ports are the ports to be allocated.
	Ports []int

	// WorkDir sets the working directory.
	WorkDir string

	// ReadOnly sets the read-only flag.
	ReadOnly bool

	// Env are additional environment variables.
	Env []string

	// User is the user to use.
	User string

	// Privileged enables privileged mode.
	Privileged bool

	// CapAdd are the extra set of capabilities to add.
	CapAdd []string

	// CapDrop are the extra set of capabilities to drop.
	CapDrop []string

	// Mounts is the list of directories/files to be mounted inside the container.
	Mounts []mount.Mount

	// Links is the list of containers to be connected to the container.
	Links []string
}

func makeContainer(ctx context.Context, logger testutil.Logger, runtime string) *Container {
	// Slashes are not allowed in container names.
	name := testutil.RandomID(logger.Name())
	name = strings.ReplaceAll(name, "/", "-")
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil
	}
	client.NegotiateAPIVersion(ctx)
	return &Container{
		logger:  logger,
		Name:    name,
		runtime: runtime,
		client:  client,
	}
}

// MakeContainer constructs a suitable Container object.
//
// The runtime used is determined by the runtime flag.
//
// Containers will check flags for profiling requests.
func MakeContainer(ctx context.Context, logger testutil.Logger) *Container {
	return makeContainer(ctx, logger, *runtime)
}

// MakeNativeContainer constructs a suitable Container object.
//
// The runtime used will be the system default.
//
// Native containers aren't profiled.
func MakeNativeContainer(ctx context.Context, logger testutil.Logger) *Container {
	return makeContainer(ctx, logger, "" /*runtime*/)
}

// Spawn is analogous to 'docker run -d'.
func (c *Container) Spawn(ctx context.Context, r RunOpts, args ...string) error {
	if err := c.create(ctx, r.Image, c.config(r, args), c.hostConfig(r), nil); err != nil {
		return err
	}
	return c.Start(ctx)
}

// SpawnProcess is analogous to 'docker run -it'. It returns a process
// which represents the root process.
func (c *Container) SpawnProcess(ctx context.Context, r RunOpts, args ...string) (Process, error) {
	config, hostconf, netconf := c.ConfigsFrom(r, args...)
	config.Tty = true
	config.OpenStdin = true

	if err := c.CreateFrom(ctx, r.Image, config, hostconf, netconf); err != nil {
		return Process{}, err
	}

	// Open a connection to the container for parsing logs and for TTY.
	stream, err := c.client.ContainerAttach(ctx, c.id,
		types.ContainerAttachOptions{
			Stream: true,
			Stdin:  true,
			Stdout: true,
			Stderr: true,
		})
	if err != nil {
		return Process{}, fmt.Errorf("connect failed container id %s: %v", c.id, err)
	}

	c.cleanups = append(c.cleanups, func() { stream.Close() })

	if err := c.Start(ctx); err != nil {
		return Process{}, err
	}

	return Process{container: c, conn: stream}, nil
}

// Run is analogous to 'docker run'.
func (c *Container) Run(ctx context.Context, r RunOpts, args ...string) (string, error) {
	if err := c.create(ctx, r.Image, c.config(r, args), c.hostConfig(r), nil); err != nil {
		return "", err
	}

	if err := c.Start(ctx); err != nil {
		return "", err
	}

	if err := c.Wait(ctx); err != nil {
		return "", err
	}

	return c.Logs(ctx)
}

// ConfigsFrom returns container configs from RunOpts and args. The caller should call 'CreateFrom'
// and Start.
func (c *Container) ConfigsFrom(r RunOpts, args ...string) (*container.Config, *container.HostConfig, *network.NetworkingConfig) {
	return c.config(r, args), c.hostConfig(r), &network.NetworkingConfig{}
}

// MakeLink formats a link to add to a RunOpts.
func (c *Container) MakeLink(target string) string {
	return fmt.Sprintf("%s:%s", c.Name, target)
}

// CreateFrom creates a container from the given configs.
func (c *Container) CreateFrom(ctx context.Context, profileImage string, conf *container.Config, hostconf *container.HostConfig, netconf *network.NetworkingConfig) error {
	return c.create(ctx, profileImage, conf, hostconf, netconf)
}

// Create is analogous to 'docker create'.
func (c *Container) Create(ctx context.Context, r RunOpts, args ...string) error {
	return c.create(ctx, r.Image, c.config(r, args), c.hostConfig(r), nil)
}

func (c *Container) create(ctx context.Context, profileImage string, conf *container.Config, hostconf *container.HostConfig, netconf *network.NetworkingConfig) error {
	if c.runtime != "" && c.runtime != "runc" {
		// Use the image name as provided here; which normally represents the
		// unmodified "basic/alpine" image name. This should be easy to grok.
		c.profileInit(profileImage)
	}
	cont, err := c.client.ContainerCreate(ctx, conf, hostconf, nil, c.Name)
	if err != nil {
		return err
	}
	c.id = cont.ID
	return nil
}

func (c *Container) config(r RunOpts, args []string) *container.Config {
	ports := nat.PortSet{}
	for _, p := range r.Ports {
		port := nat.Port(fmt.Sprintf("%d", p))
		ports[port] = struct{}{}
	}
	env := append(r.Env, fmt.Sprintf("RUNSC_TEST_NAME=%s", c.Name))

	return &container.Config{
		Image:        testutil.ImageByName(r.Image),
		Cmd:          args,
		ExposedPorts: ports,
		Env:          env,
		WorkingDir:   r.WorkDir,
		User:         r.User,
	}
}

func (c *Container) hostConfig(r RunOpts) *container.HostConfig {
	c.mounts = append(c.mounts, r.Mounts...)

	return &container.HostConfig{
		Runtime:         c.runtime,
		Mounts:          c.mounts,
		PublishAllPorts: true,
		Links:           r.Links,
		CapAdd:          r.CapAdd,
		CapDrop:         r.CapDrop,
		Privileged:      r.Privileged,
		ReadonlyRootfs:  r.ReadOnly,
		Resources: container.Resources{
			Memory:     int64(r.Memory), // In bytes.
			CpusetCpus: r.CpusetCpus,
		},
	}
}

// Start is analogous to 'docker start'.
func (c *Container) Start(ctx context.Context) error {
	if err := c.client.ContainerStart(ctx, c.id, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("ContainerStart failed: %v", err)
	}

	if c.profile != nil {
		if err := c.profile.Start(c); err != nil {
			c.logger.Logf("profile.Start failed: %v", err)
		}
	}

	return nil
}

// Stop is analogous to 'docker stop'.
func (c *Container) Stop(ctx context.Context) error {
	return c.client.ContainerStop(ctx, c.id, nil)
}

// Pause is analogous to'docker pause'.
func (c *Container) Pause(ctx context.Context) error {
	return c.client.ContainerPause(ctx, c.id)
}

// Unpause is analogous to 'docker unpause'.
func (c *Container) Unpause(ctx context.Context) error {
	return c.client.ContainerUnpause(ctx, c.id)
}

// Checkpoint is analogous to 'docker checkpoint'.
func (c *Container) Checkpoint(ctx context.Context, name string) error {
	return c.client.CheckpointCreate(ctx, c.Name, types.CheckpointCreateOptions{CheckpointID: name, Exit: true})
}

// Restore is analogous to 'docker start --checkname [name]'.
func (c *Container) Restore(ctx context.Context, name string) error {
	return c.client.ContainerStart(ctx, c.id, types.ContainerStartOptions{CheckpointID: name})
}

// Logs is analogous 'docker logs'.
func (c *Container) Logs(ctx context.Context) (string, error) {
	var out bytes.Buffer
	err := c.logs(ctx, &out, &out)
	return out.String(), err
}

func (c *Container) logs(ctx context.Context, stdout, stderr *bytes.Buffer) error {
	opts := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
	writer, err := c.client.ContainerLogs(ctx, c.id, opts)
	if err != nil {
		return err
	}
	defer writer.Close()
	_, err = stdcopy.StdCopy(stdout, stderr, writer)

	return err
}

// ID returns the container id.
func (c *Container) ID() string {
	return c.id
}

// SandboxPid returns the container's pid.
func (c *Container) SandboxPid(ctx context.Context) (int, error) {
	resp, err := c.client.ContainerInspect(ctx, c.id)
	if err != nil {
		return -1, err
	}
	return resp.ContainerJSONBase.State.Pid, nil
}

// ErrNoIP indicates that no IP address is available.
var ErrNoIP = errors.New("no IP available")

// FindIP returns the IP address of the container.
func (c *Container) FindIP(ctx context.Context, ipv6 bool) (net.IP, error) {
	resp, err := c.client.ContainerInspect(ctx, c.id)
	if err != nil {
		return nil, err
	}

	var ip net.IP
	if ipv6 {
		ip = net.ParseIP(resp.NetworkSettings.DefaultNetworkSettings.GlobalIPv6Address)
	} else {
		ip = net.ParseIP(resp.NetworkSettings.DefaultNetworkSettings.IPAddress)
	}
	if ip == nil {
		return net.IP{}, ErrNoIP
	}
	return ip, nil
}

// FindPort returns the host port that is mapped to 'sandboxPort'.
func (c *Container) FindPort(ctx context.Context, sandboxPort int) (int, error) {
	desc, err := c.client.ContainerInspect(ctx, c.id)
	if err != nil {
		return -1, fmt.Errorf("error retrieving port: %v", err)
	}

	format := fmt.Sprintf("%d/tcp", sandboxPort)
	ports, ok := desc.NetworkSettings.Ports[nat.Port(format)]
	if !ok {
		return -1, fmt.Errorf("error retrieving port: %v", err)

	}

	port, err := strconv.Atoi(ports[0].HostPort)
	if err != nil {
		return -1, fmt.Errorf("error parsing port %q: %v", port, err)
	}
	return port, nil
}

// CopyFiles copies in and mounts the given files. They are always ReadOnly.
func (c *Container) CopyFiles(opts *RunOpts, target string, sources ...string) {
	dir, err := ioutil.TempDir("", c.Name)
	if err != nil {
		c.copyErr = fmt.Errorf("ioutil.TempDir failed: %v", err)
		return
	}
	c.cleanups = append(c.cleanups, func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		c.copyErr = fmt.Errorf("os.Chmod(%q, 0755) failed: %v", dir, err)
		return
	}
	for _, name := range sources {
		src := name
		if !filepath.IsAbs(src) {
			src, err = testutil.FindFile(name)
			if err != nil {
				c.copyErr = fmt.Errorf("testutil.FindFile(%q) failed: %w", name, err)
				return
			}
		}
		dst := path.Join(dir, path.Base(name))
		if err := testutil.Copy(src, dst); err != nil {
			c.copyErr = fmt.Errorf("testutil.Copy(%q, %q) failed: %v", src, dst, err)
			return
		}
		c.logger.Logf("copy: %s -> %s", src, dst)
	}
	opts.Mounts = append(opts.Mounts, mount.Mount{
		Type:     mount.TypeBind,
		Source:   dir,
		Target:   target,
		ReadOnly: false,
	})
}

// Status inspects the container returns its status.
func (c *Container) Status(ctx context.Context) (types.ContainerState, error) {
	resp, err := c.client.ContainerInspect(ctx, c.id)
	if err != nil {
		return types.ContainerState{}, err
	}
	return *resp.State, err
}

// Wait waits for the container to exit.
func (c *Container) Wait(ctx context.Context) error {
	defer c.stopProfiling()
	statusChan, errChan := c.client.ContainerWait(ctx, c.id, container.WaitConditionNotRunning)
	select {
	case err := <-errChan:
		return err
	case <-statusChan:
		return nil
	}
}

// WaitTimeout waits for the container to exit with a timeout.
func (c *Container) WaitTimeout(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	statusChan, errChan := c.client.ContainerWait(ctx, c.id, container.WaitConditionNotRunning)
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("container %s timed out after %v seconds", c.Name, timeout.Seconds())
		}
		return nil
	case err := <-errChan:
		return err
	case <-statusChan:
		return nil
	}
}

// WaitForOutput searches container logs for pattern and returns or timesout.
func (c *Container) WaitForOutput(ctx context.Context, pattern string, timeout time.Duration) (string, error) {
	matches, err := c.WaitForOutputSubmatch(ctx, pattern, timeout)
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("didn't find pattern %s logs", pattern)
	}
	return matches[0], nil
}

// WaitForOutputSubmatch searches container logs for the given
// pattern or times out. It returns any regexp submatches as well.
func (c *Container) WaitForOutputSubmatch(ctx context.Context, pattern string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	re := regexp.MustCompile(pattern)
	for {
		logs, err := c.Logs(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get logs: %v logs: %s", err, logs)
		}
		if matches := re.FindStringSubmatch(logs); matches != nil {
			return matches, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stopProfiling stops profiling.
func (c *Container) stopProfiling() {
	if c.profile != nil {
		if err := c.profile.Stop(c); err != nil {
			// This most likely means that the runtime for the container
			// was too short to connect and actually get a profile.
			c.logger.Logf("warning: profile.Stop failed: %v", err)
		}
	}
}

// Kill kills the container.
func (c *Container) Kill(ctx context.Context) error {
	defer c.stopProfiling()
	return c.client.ContainerKill(ctx, c.id, "")
}

// Remove is analogous to 'docker rm'.
func (c *Container) Remove(ctx context.Context) error {
	// Remove the image.
	remove := types.ContainerRemoveOptions{
		RemoveVolumes: c.mounts != nil,
		RemoveLinks:   c.links != nil,
		Force:         true,
	}
	return c.client.ContainerRemove(ctx, c.Name, remove)
}

// CleanUp kills and deletes the container (best effort).
func (c *Container) CleanUp(ctx context.Context) {
	// Execute all cleanups. We execute cleanups here to close any
	// open connections to the container before closing. Open connections
	// can cause Kill and Remove to hang.
	for _, c := range c.cleanups {
		c()
	}
	c.cleanups = nil

	// Kill the container.
	if err := c.Kill(ctx); err != nil && !strings.Contains(err.Error(), "is not running") {
		// Just log; can't do anything here.
		c.logger.Logf("error killing container %q: %v", c.Name, err)
	}

	// Remove the image.
	if err := c.Remove(ctx); err != nil {
		c.logger.Logf("error removing container %q: %v", c.Name, err)
	}

	// Forget all mounts.
	c.mounts = nil
}
