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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/checkpoint"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Container represents a Docker Container allowing
// user to configure and control as one would with the 'docker'
// client. Container is backed by the official golang docker API.
// See: https://pkg.go.dev/github.com/docker/docker.
type Container struct {
	Name     string
	runtime  string
	logger   testutil.Logger
	client   *client.Client
	id       string
	mounts   []mount.Mount
	links    []string
	copyErr  error
	cleanups []func()

	// profile is the profiling hook associated with this container.
	profile *profile

	// sniffGPUOpts, if set, sets the rules for GPU sniffing for this container.
	sniffGPUOpts *SniffGPUOpts
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

	// WorkDir sets the working directory.
	WorkDir string

	// ReadOnly sets the read-only flag.
	ReadOnly bool

	// Env are additional environment variables.
	Env []string

	// User is the user to use.
	User string

	// Optional argv to override the ENTRYPOINT specified in the image.
	Entrypoint []string

	// Privileged enables privileged mode.
	Privileged bool

	// Sets network mode for the container. See container.NetworkMode for types. Several options will
	// not work w/ gVisor. For example, you can't set the "sandbox" network option for gVisor using
	// this handle.
	NetworkMode string

	// CapAdd are the extra set of capabilities to add.
	CapAdd []string

	// CapDrop are the extra set of capabilities to drop.
	CapDrop []string

	// Mounts is the list of directories/files to be mounted inside the container.
	Mounts []mount.Mount

	// "--tmpfs" has features unsupported by "--mount", especially nosuid,
	// see https://docs.docker.com/engine/storage/tmpfs/
	Tmpfs map[string]string

	// Links is the list of containers to be connected to the container.
	Links []string

	// DeviceRequests are device requests on the container itself.
	DeviceRequests []container.DeviceRequest

	Devices []container.DeviceMapping

	// SecurityOpts are security options to set on the container.
	SecurityOpts []string

	// sniffGPUOpts, if set, sets the rules for GPU sniffing during this test.
	// Must be set via `RunOpts.SniffGPU`.
	sniffGPUOpts *SniffGPUOpts
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

// MakeContainerWithRuntime is like MakeContainer, but allows for a runtime
// to be specified by suffix.
func MakeContainerWithRuntime(ctx context.Context, logger testutil.Logger, suffix string) *Container {
	return makeContainer(ctx, logger, *runtime+suffix)
}

// MakeNativeContainer constructs a suitable Container object.
//
// The runtime used will be the system default.
//
// Native containers aren't profiled.
func MakeNativeContainer(ctx context.Context, logger testutil.Logger) *Container {
	unsandboxedRuntime := "runc"
	if override, found := os.LookupEnv("UNSANDBOXED_RUNTIME"); found {
		unsandboxedRuntime = override
	}
	return makeContainer(ctx, logger, unsandboxedRuntime)
}

// Spawn is analogous to 'docker run -d'.
func (c *Container) Spawn(ctx context.Context, r RunOpts, args ...string) error {
	cfg, err := c.config(ctx, r, args)
	if err != nil {
		return fmt.Errorf("container config: %w", err)
	}
	if err := c.create(ctx, r.Image, cfg, c.hostConfig(r), nil); err != nil {
		return err
	}
	return c.Start(ctx)
}

// SpawnProcess is analogous to 'docker run -it'. It returns a process
// which represents the root process.
func (c *Container) SpawnProcess(ctx context.Context, r RunOpts, args ...string) (Process, error) {
	config, hostconf, netconf, err := c.ConfigsFrom(ctx, r, args...)
	if err != nil {
		return Process{}, fmt.Errorf("container config: %w", err)
	}
	config.Tty = true
	config.OpenStdin = true

	if err := c.CreateFrom(ctx, r.Image, config, hostconf, netconf); err != nil {
		return Process{}, err
	}

	// Open a connection to the container for parsing logs and for TTY.
	stream, err := c.client.ContainerAttach(ctx, c.id,
		container.AttachOptions{
			Stream: true,
			Stdin:  true,
			Stdout: true,
			Stderr: true,
		})
	if err != nil {
		return Process{}, fmt.Errorf("connect failed container id %s: %v", c.id, err)
	}

	c.cleanups = append(c.cleanups, func() { stream.Close() })
	c.sniffGPUOpts = r.sniffGPUOpts

	if err := c.Start(ctx); err != nil {
		return Process{}, err
	}

	return Process{container: c, conn: stream}, nil
}

// Run is analogous to 'docker run'.
func (c *Container) Run(ctx context.Context, r RunOpts, args ...string) (string, error) {
	cfg, err := c.config(ctx, r, args)
	if err != nil {
		return "", fmt.Errorf("container config: %w", err)
	}
	if err := c.create(ctx, r.Image, cfg, c.hostConfig(r), nil); err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	if err := c.Start(ctx); err != nil {
		logs, _ := c.Logs(ctx)
		return logs, fmt.Errorf("failed to start container: %w", err)
	}

	if err := c.Wait(ctx); err != nil {
		logs, _ := c.Logs(ctx)
		return logs, fmt.Errorf("container failed: %w", err)
	}

	logs, err := c.Logs(ctx)
	if err != nil {
		return logs, fmt.Errorf("failed to get logs: %w", err)
	}
	return logs, nil
}

// ConfigsFrom returns container configs from RunOpts and args. The caller should call 'CreateFrom'
// and Start.
func (c *Container) ConfigsFrom(ctx context.Context, r RunOpts, args ...string) (*container.Config, *container.HostConfig, *network.NetworkingConfig, error) {
	cfg, err := c.config(ctx, r, args)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("container config: %w", err)
	}
	return cfg, c.hostConfig(r), &network.NetworkingConfig{}, nil
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
	cfg, err := c.config(ctx, r, args)
	if err != nil {
		return fmt.Errorf("container config: %w", err)
	}
	return c.create(ctx, r.Image, cfg, c.hostConfig(r), nil)
}

func (c *Container) create(ctx context.Context, profileImage string, conf *container.Config, hostconf *container.HostConfig, netconf *network.NetworkingConfig) error {
	if c.runtime != "" && c.runtime != "runc" {
		// Use the image name as provided here; which normally represents the
		// unmodified "basic/alpine" image name. This should be easy to grok.
		c.profileInit(profileImage)
	}
	if hostconf == nil || hostconf.LogConfig.Type == "" {
		// If logging config is not explicitly specified, set it to a fairly
		// generous default. This makes large volumes of log more reliably
		// captured, which is useful for profiling metrics.
		if hostconf == nil {
			hostconf = &container.HostConfig{}
		}
		hostconf.LogConfig.Type = "local"
		hostconf.LogConfig.Config = map[string]string{
			"mode":     "blocking",
			"max-size": "1g",
			"max-file": "10",
			"compress": "false",
		}
	}
	cont, err := c.client.ContainerCreate(ctx, conf, hostconf, nil, nil, c.Name)
	if err != nil {
		return err
	}
	c.id = cont.ID
	return nil
}

func (c *Container) config(ctx context.Context, r RunOpts, args []string) (*container.Config, error) {
	env := append(r.Env, fmt.Sprintf("RUNSC_TEST_NAME=%s", c.Name))

	image := testutil.ImageByName(r.Image)
	entrypoint := r.Entrypoint
	if r.sniffGPUOpts != nil {
		c.cleanups = append(c.cleanups, func() {
			r.sniffGPUOpts.cleanup()
		})
		if len(entrypoint) == 0 || len(args) == 0 {
			// Need to look up the image's default entrypoint/args so we can prepend to them.
			// If we don't, then we will end up overwriting them.
			imageInfo, _, err := c.client.ImageInspectWithRaw(ctx, image)
			if err != nil {
				return nil, fmt.Errorf("cannot inspect image %q: %w", image, err)
			}
			if len(entrypoint) == 0 {
				entrypoint = []string(imageInfo.Config.Entrypoint)
			}
			if len(args) == 0 {
				args = []string(imageInfo.Config.Cmd)
			}
		}
		if len(entrypoint) != 0 {
			entrypoint = r.sniffGPUOpts.prepend(entrypoint)
		} else {
			args = r.sniffGPUOpts.prepend(args)
		}
	}

	return &container.Config{
		Image:      image,
		Cmd:        args,
		Entrypoint: entrypoint,
		Env:        env,
		WorkingDir: r.WorkDir,
		User:       r.User,
	}, nil
}

func (c *Container) hostConfig(r RunOpts) *container.HostConfig {
	c.mounts = append(c.mounts, r.Mounts...)

	return &container.HostConfig{
		Runtime:         c.runtime,
		Mounts:          c.mounts,
		Tmpfs:           r.Tmpfs,
		PublishAllPorts: true,
		Links:           r.Links,
		CapAdd:          r.CapAdd,
		CapDrop:         r.CapDrop,
		Privileged:      r.Privileged,
		SecurityOpt:     r.SecurityOpts,
		ReadonlyRootfs:  r.ReadOnly,
		NetworkMode:     container.NetworkMode(r.NetworkMode),
		Resources: container.Resources{
			Memory:         int64(r.Memory), // In bytes.
			CpusetCpus:     r.CpusetCpus,
			DeviceRequests: r.DeviceRequests,
			Devices:        r.Devices,
		},
	}
}

// Start is analogous to 'docker start'.
func (c *Container) Start(ctx context.Context) error {
	if err := c.client.ContainerStart(ctx, c.id, container.StartOptions{}); err != nil {
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
	return c.client.ContainerStop(ctx, c.id, container.StopOptions{})
}

// Pause is analogous to 'docker pause'.
func (c *Container) Pause(ctx context.Context) error {
	return c.client.ContainerPause(ctx, c.id)
}

// Unpause is analogous to 'docker unpause'.
func (c *Container) Unpause(ctx context.Context) error {
	return c.client.ContainerUnpause(ctx, c.id)
}

// Checkpoint is analogous to 'docker checkpoint'.
func (c *Container) Checkpoint(ctx context.Context, name string) error {
	return c.client.CheckpointCreate(ctx, c.Name, checkpoint.CreateOptions{CheckpointID: name, Exit: true})
}

// Restore is analogous to 'docker start --checkpoint [name]'.
func (c *Container) Restore(ctx context.Context, name string) error {
	return c.client.ContainerStart(ctx, c.id, container.StartOptions{CheckpointID: name})
}

// RestoreInTest is the same as Restore, except that it handles known issues
// while testing.
func (c *Container) RestoreInTest(ctx context.Context, t *testing.T, name string) {
	// TODO(b/143498576): Remove sleep after github.com/moby/moby/issues/38963 is fixed.
	time.Sleep(2 * time.Second)
	if err := c.Restore(ctx, name); err != nil {
		if regexp.MustCompile("failed to upload checkpoint to containerd: commit failed: content sha256:.*: already exists").MatchString(err.Error()) ||
			regexp.MustCompile("failed to create task for container: content digest .*: not found: unknown").MatchString(err.Error()) {
			t.Skip("Skipping restore due to known issue: https://github.com/moby/moby/issues/42900")
		}
		t.Fatalf("docker restore failed: %v", err)
	}
}

// CheckpointResume is analogous to 'docker checkpoint'.
func (c *Container) CheckpointResume(ctx context.Context, name string) error {
	return c.client.CheckpointCreate(ctx, c.Name, checkpoint.CreateOptions{CheckpointID: name, Exit: false})
}

// Logs is analogous 'docker logs'.
func (c *Container) Logs(ctx context.Context) (string, error) {
	var out bytes.Buffer
	err := c.logs(ctx, &out, &out)
	return out.String(), err
}

// OutputStreams gets the container's stdout and stderr streams separately.
func (c *Container) OutputStreams(ctx context.Context) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := c.logs(ctx, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func (c *Container) logs(ctx context.Context, stdout, stderr *bytes.Buffer) error {
	opts := container.LogsOptions{ShowStdout: true, ShowStderr: true}
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

// RootDirectory returns an educated guess about the container's root directory.
func (c *Container) RootDirectory() (string, error) {
	// The root directory of this container's runtime.
	rootDir := fmt.Sprintf("/var/run/docker/runtime-%s/moby", c.runtime)
	_, err := os.Stat(rootDir)
	if err == nil {
		return rootDir, nil
	}
	// In docker v20+, due to https://github.com/moby/moby/issues/42345 the
	// rootDir seems to always be the following.
	const defaultDir = "/var/run/docker/runtime-runc/moby"
	_, derr := os.Stat(defaultDir)
	if derr == nil {
		return defaultDir, nil
	}

	return "", fmt.Errorf("cannot stat %q: %v or %q: %v", rootDir, err, defaultDir, derr)
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
	dir, err := os.MkdirTemp("", c.Name)
	if err != nil {
		c.copyErr = fmt.Errorf("os.MkdirTemp failed: %v", err)
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

// Stats returns a snapshot of container stats similar to `docker stats`.
func (c *Container) Stats(ctx context.Context) (*container.StatsResponse, error) {
	responseBody, err := c.client.ContainerStats(ctx, c.id, false /*stream*/)
	if err != nil {
		return nil, fmt.Errorf("ContainerStats failed: %v", err)
	}
	defer responseBody.Body.Close()
	var v container.StatsResponse
	if err := json.NewDecoder(responseBody.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("failed to decode container stats: %v", err)
	}
	return &v, nil
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
	case res := <-statusChan:
		if res.StatusCode != 0 {
			var msg string
			if res.Error != nil {
				msg = res.Error.Message
			}
			return fmt.Errorf("container returned non-zero status: %d, msg: %q", res.StatusCode, msg)
		}
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
	remove := container.RemoveOptions{
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

// ContainerPool represents a pool of reusable containers.
// Callers may request a container from the pool, and must release it back
// when they are done with it.
//
// This is useful for large tests which can `exec` individual test cases
// inside the same set of reusable containers, to avoid the cost of creating
// and destroying containers for each test.
//
// It also supports reserving the whole pool ("exclusive"), which locks out
// all other callers from getting any other container from the pool.
// This is useful for tests where running in parallel may induce unexpected
// errors which running serially would not cause. This allows the test to
// first try to run in parallel, and then re-run failing tests exclusively
// to make sure their failure is not due to parallel execution.
type ContainerPool struct {
	// numContainers is the total number of containers in the pool, whether
	// reserved or not.
	numContainers int

	// containersCh is the main container queue channel.
	// It is buffered with as many items as there are total containers in the
	// pool (i.e. `numContainers`).
	containersCh chan *Container

	// exclusiveLockCh is a lock-like channel for exclusive locking.
	// It is buffered with a single element seeded in it.
	// Whichever goroutine claims this element now holds the exclusive lock.
	exclusiveLockCh chan struct{}

	// containersExclusiveCh is an alternative container queue channel.
	// It is preferentially written to over containerCh, but is unbuffered.
	// A goroutine may only listen on this channel if they hold the exclusive
	// lock.
	// This allows exclusive locking to get released containers preferentially
	// over non-exclusive waiters, to avoid needless starvation.
	containersExclusiveCh chan *Container

	// shutdownCh is always empty, and is closed when the pool is shutting down.
	shutdownCh chan struct{}

	// mu protects the fields below.
	mu sync.Mutex

	// statuses maps container name to their current status.
	statuses map[*Container]containerPoolStatus

	// firstReservation is the time of the first container reservation event.
	firstReservation time.Time

	// productive is the duration containers have cumulatively spent in reserved
	// state.
	productive time.Duration
}

// containerPoolStatus represents the status of a container in the pool.
type containerPoolStatus struct {
	when      time.Time
	state     containerPoolState
	userLabel string
}

// containerPoolState is the state of a container in the pool.
type containerPoolState int

// Set of containerPoolState used by ContainerPool.
const (
	stateNeverUsed containerPoolState = iota
	stateIdle
	stateReserved
	stateReservedExclusive
	stateShutdown
	stateHeldForExclusive
)

// IsProductive returns true if the container is in a state where it is
// actively being used.
func (cps containerPoolState) IsProductive() bool {
	return cps == stateReserved || cps == stateReservedExclusive
}

// String returns a human-friendly representation of the container state in
// the pool.
func (cps containerPoolState) String() string {
	switch cps {
	case stateNeverUsed:
		return "never used"
	case stateIdle:
		return "idle"
	case stateReserved:
		return "reserved"
	case stateReservedExclusive:
		return "reserved in exclusive mode"
	case stateHeldForExclusive:
		return "held back to allow another container to be exclusively-reserved"
	case stateShutdown:
		return "shutdown"
	default:
		return fmt.Sprintf("unknownstate(%d)", cps)
	}
}

// NewContainerPool returns a new ContainerPool holding the given set of
// containers.
func NewContainerPool(containers []*Container) *ContainerPool {
	if len(containers) == 0 {
		panic("cannot create an empty pool")
	}
	containersCh := make(chan *Container, len(containers))
	for _, c := range containers {
		containersCh <- c
	}
	exclusiveCh := make(chan struct{}, 1)
	exclusiveCh <- struct{}{}
	statuses := make(map[*Container]containerPoolStatus)
	poolStarted := time.Now()
	for _, c := range containers {
		statuses[c] = containerPoolStatus{
			when:  poolStarted,
			state: stateNeverUsed,
		}
	}
	return &ContainerPool{
		containersCh:          containersCh,
		exclusiveLockCh:       exclusiveCh,
		containersExclusiveCh: make(chan *Container),
		shutdownCh:            make(chan struct{}),
		numContainers:         len(containers),
		statuses:              statuses,
	}
}

// releaseFn returns a function to release a container back to the pool.
func (cp *ContainerPool) releaseFn(c *Container) func() {
	return func() {
		cp.setContainerState(c, stateIdle)
		// Preferentially release to the exclusive channel.
		select {
		case cp.containersExclusiveCh <- c:
			return
		default:
			// Otherwise, release to either channel.
			select {
			case cp.containersExclusiveCh <- c:
			case cp.containersCh <- c:
			}
		}
	}
}

// Get returns a free container and a function to release it back to the pool.
func (cp *ContainerPool) Get(ctx context.Context) (*Container, func(), error) {
	select {
	case c := <-cp.containersCh:
		cp.setContainerState(c, stateReserved)
		return c, cp.releaseFn(c), nil
	case <-cp.shutdownCh:
		return nil, func() {}, errors.New("pool's closed")
	case <-ctx.Done():
		return nil, func() {}, ctx.Err()
	}
}

// GetExclusive ensures all pooled containers are in the pool, reserves all
// of them, and returns one of them, along with a function to release them all
// back to the pool.
func (cp *ContainerPool) GetExclusive(ctx context.Context) (*Container, func(), error) {
	select {
	case <-cp.exclusiveLockCh:
		// Proceed.
	case <-cp.shutdownCh:
		return nil, func() {}, errors.New("pool's closed")
	case <-ctx.Done():
		return nil, func() {}, ctx.Err()
	}
	var reserved *Container
	releaseFuncs := make([]func(), 0, cp.numContainers)
	releaseAll := func() {
		for i := len(releaseFuncs) - 1; i >= 0; i-- {
			releaseFuncs[i]()
		}
		cp.exclusiveLockCh <- struct{}{}
	}
	for i := 0; i < cp.numContainers; i++ {
		var got *Container
		select {
		case c := <-cp.containersExclusiveCh:
			got = c
		case c := <-cp.containersCh:
			got = c
		case <-cp.shutdownCh:
			releaseAll()
			return nil, func() {}, errors.New("pool's closed")
		case <-ctx.Done():
			releaseAll()
			return nil, func() {}, ctx.Err()
		}
		cp.setContainerState(got, stateHeldForExclusive)
		releaseFuncs = append(releaseFuncs, cp.releaseFn(got))
		if reserved == nil {
			reserved = got
		}
	}
	cp.setContainerState(reserved, stateReservedExclusive)
	return reserved, releaseAll, nil
}

// CleanUp waits for all containers to be back into the pool, and cleans up
// each container as soon as it gets back in the pool.
func (cp *ContainerPool) CleanUp(ctx context.Context) {
	close(cp.shutdownCh)
	for i := 0; i < cp.numContainers; i++ {
		c := <-cp.containersCh
		cp.setContainerState(c, stateShutdown)
		c.CleanUp(ctx)
	}
}

// setContainerState sets the state of the given container.
func (cp *ContainerPool) setContainerState(c *Container, state containerPoolState) {
	isProductive := state.IsProductive()
	when := time.Now()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if isProductive && cp.firstReservation.IsZero() {
		cp.firstReservation = when
	}
	status := cp.statuses[c]
	wasProductive := status.state.IsProductive()
	if wasProductive && !isProductive {
		cp.productive += when.Sub(status.when)
	}
	status.when = when
	status.state = state
	status.userLabel = "" // Clear any existing user label.
	cp.statuses[c] = status
}

// Utilization returns the utilization of the pool.
// This is the ratio of the cumulative duration containers have been in a
// productive state (reserved) divided by the maximum potential productive
// container-duration since the first container was reserved.
func (cp *ContainerPool) Utilization() float64 {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.getUtilizationLocked(time.Now())
}

// getUtilizationLocked actually computes the utilization of the pool.
// Preconditions: cp.mu is held.
func (cp *ContainerPool) getUtilizationLocked(now time.Time) float64 {
	if cp.firstReservation.IsZero() {
		return 0
	}
	maxUtilization := now.Sub(cp.firstReservation) * time.Duration(len(cp.statuses))
	actualUtilization := cp.productive
	for container := range cp.statuses {
		if status := cp.statuses[container]; status.state.IsProductive() {
			actualUtilization += now.Sub(status.when)
		}
	}
	return float64(actualUtilization.Nanoseconds()) / float64(maxUtilization.Nanoseconds())
}

// SetContainerLabel sets the label for a container.
// This is printed in `cp.String`, and wiped every time the container changes
// state. It is useful for the ContainerPool user to track what each container
// is doing.
func (cp *ContainerPool) SetContainerLabel(c *Container, label string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	status := cp.statuses[c]
	status.userLabel = label
	cp.statuses[c] = status
}

// String returns a string representation of the pool.
// It includes the state of each container, and their user-set label.
func (cp *ContainerPool) String() string {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.firstReservation.IsZero() {
		return "ContainerPool[never used]"
	}
	now := time.Now()
	containers := make([]*Container, 0, len(cp.statuses))
	for c := range cp.statuses {
		containers = append(containers, c)
	}
	sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
	containersInUse := 0
	for _, container := range containers {
		if status := cp.statuses[container]; status.state.IsProductive() {
			containersInUse++
		}
	}
	utilizationPct := 100.0 * cp.getUtilizationLocked(now)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ContainerPool[%d/%d containers in use, utilization=%.1f%%]: ", containersInUse, len(containers), utilizationPct))
	for i, container := range containers {
		if i > 0 {
			sb.WriteString(", ")
		}
		status := cp.statuses[container]
		sb.WriteString("#")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString("[")
		sb.WriteString(status.state.String())
		sb.WriteString("]")
		if status.userLabel != "" {
			sb.WriteString(": ")
			sb.WriteString(status.userLabel)
		}
	}
	return sb.String()
}
