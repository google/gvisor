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

// Package ding benchmarks Docker-in-gVisor (DinG) workloads.
package ding

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
	"gvisor.dev/gvisor/test/benchmarks/tools"
	"gvisor.dev/gvisor/test/moby/mobyutil"
)

const (
	// iperf server listen port.
	iperfPort = 5001
	// Published port on DING forwarded to a sub-container's iperfPort.
	pubPort      = 5002
	setupTimeout = 2 * time.Minute
	runTimeout   = 2 * time.Minute
)

// node represents Host, DING, or DINGSubContainer.
type node struct {
	ip      string
	runCmd  func(ctx context.Context, cmd ...string) (string, error)
	cleanUp func(ctx context.Context)
}

// dingNode represents a gVisor DING container running dockerd.
type dingNode struct {
	*node
	topo *topology
}

// topology represents the topology of the nodes.
type topology struct {
	machine harness.Machine
	logger  testutil.Logger
	nodes   []*node
}

// cleanUp tears down all nodes in reverse creation order.
func (t *topology) cleanUp(ctx context.Context) {
	for i := len(t.nodes) - 1; i >= 0; i-- {
		if t.nodes[i].cleanUp != nil {
			t.nodes[i].cleanUp(ctx)
		}
	}
}

// newHost starts a runc container on the host running an iperf server
// and adds it to the topology.
func (t *topology) newHost(ctx context.Context) (*node, error) {
	c := t.machine.GetNativeContainer(ctx, t.logger)
	if err := c.Spawn(ctx, dockerutil.RunOpts{Image: "moby"}, "iperf", "-s", "-p", strconv.Itoa(iperfPort)); err != nil {
		c.CleanUp(ctx)
		return nil, fmt.Errorf("failed to spawn host container: %w", err)
	}
	if out, err := c.WaitForOutput(ctx, fmt.Sprintf("Server listening on TCP port %d", iperfPort), 10*time.Second); err != nil {
		c.CleanUp(ctx)
		return nil, fmt.Errorf("failed to wait for host iperf server: %w (%s)", err, out)
	}
	ip, err := c.FindIP(ctx, false)
	if err != nil {
		c.CleanUp(ctx)
		return nil, fmt.Errorf("failed to find host container IP: %w", err)
	}
	n := &node{
		ip: ip.String(),
		runCmd: func(ctx context.Context, cmd ...string) (string, error) {
			return c.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
		},
		cleanUp: c.CleanUp,
	}
	t.nodes = append(t.nodes, n)
	return n, nil
}

// newDING starts a gVisor DING container running dockerd and an iperf server,
// loads the busybox image and adds it to the topology.
func (t *topology) newDING(ctx context.Context) (*dingNode, error) {
	d, err := mobyutil.StartContainer(ctx, t.logger, t.machine)
	if err != nil {
		return nil, err
	}
	ip, err := d.FindIP(ctx, false)
	if err != nil {
		d.CleanUp(ctx)
		return nil, fmt.Errorf("failed to find DING container IP: %w", err)
	}
	// Load the pre-bundled busybox image into DING's dockerd daemon.
	if out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "docker", "load", "-i", "/docker-images/busybox.tar"); err != nil {
		d.CleanUp(ctx)
		return nil, fmt.Errorf("docker load failed: %w (%s)", err, out)
	}
	// Start a background iperf server on DING itself.
	if out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "iperf", "-s", "-D", "-p", strconv.Itoa(iperfPort)); err != nil {
		d.CleanUp(ctx)
		return nil, fmt.Errorf("failed to start DING iperf server: %w (%s)", err, out)
	}
	n := &node{
		ip: ip.String(),
		runCmd: func(ctx context.Context, cmd ...string) (string, error) {
			return d.Exec(ctx, dockerutil.ExecOpts{}, cmd...)
		},
		cleanUp: d.CleanUp,
	}
	t.nodes = append(t.nodes, n)
	return &dingNode{
		node: n,
		topo: t,
	}, nil
}

// dockerInspect runs `docker inspect -f <format> <target>` inside a DING node.
func (d *dingNode) dockerInspect(ctx context.Context, format, target string) (string, error) {
	out, err := d.runCmd(ctx, "docker", "inspect", "-f", format, target)
	if err != nil {
		return "", fmt.Errorf("docker inspect %s failed: %w (%s)", target, err, out)
	}
	val := strings.TrimSpace(out)
	if val == "" {
		return "", fmt.Errorf("empty docker inspect result for %s (format %q)", target, format)
	}
	return val, nil
}

// createNetwork creates a Docker bridge network inside DING and returns its
// assigned gateway IP.
func (d *dingNode) createNetwork(ctx context.Context, netName string) (string, error) {
	if out, err := d.runCmd(ctx, "docker", "network", "create", netName); err != nil {
		return "", fmt.Errorf("docker network create %s failed: %w (%s)", netName, err, out)
	}
	return d.dockerInspect(ctx, "{{(index .IPAM.Config 0).Gateway}}", netName)
}

// newSubContainer starts a DINGSubContainer running an iperf server
// and adds it to the topology.
func (d *dingNode) newSubContainer(ctx context.Context, name, netName, portMap string) (*node, error) {
	// `docker run` arguments:
	// - `-d --name <name> --network <net>`: run detached on the target bridge.
	// - `-v /usr/bin/iperf`, `-v /usr/lib`, `-v /lib`: busybox:latest does not
	//   include iperf, so bind-mount DING's iperf binary and shared libraries
	//   read-only into the sub-container.
	args := []string{
		"docker", "run", "-d",
		"--name", name,
		"--network", netName,
		"-v", "/usr/bin/iperf:/usr/bin/iperf:ro",
		"-v", "/usr/lib:/usr/lib:ro",
		"-v", "/lib:/lib:ro",
	}
	if portMap != "" {
		args = append(args, "--publish", portMap)
	}
	args = append(args, "busybox:latest", "iperf", "-s", "--port", strconv.Itoa(iperfPort))
	if out, err := d.runCmd(ctx, args...); err != nil {
		return nil, fmt.Errorf("docker run %s failed: %w (%s)", name, err, out)
	}
	wantLog := fmt.Sprintf("Server listening on TCP port %d", iperfPort)
	pollCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := testutil.PollContext(pollCtx, func() error {
		out, err := d.runCmd(pollCtx, "docker", "logs", name)
		if err != nil {
			return err
		}
		if !strings.Contains(out, wantLog) {
			return fmt.Errorf("iperf server not ready yet (logs=%q)", out)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("waiting for %s iperf server: %w", name, err)
	}
	ip, err := d.dockerInspect(ctx, "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		return nil, err
	}
	n := &node{
		ip: ip,
		runCmd: func(ctx context.Context, cmd ...string) (string, error) {
			execArgs := append([]string{"docker", "exec", name}, cmd...)
			return d.runCmd(ctx, execArgs...)
		},
	}
	d.topo.nodes = append(d.topo.nodes, n)
	return n, nil
}

// BenchmarkDockerNetwork benchmarks IPv4 TCP throughput across Host, DING, and
// DINGSubContainer network topologies using iperf.
func BenchmarkDockerNetwork(b *testing.B) {
	dockerutil.SkipIfPGO(b)
	ctx := context.Background()

	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	for _, tc := range []struct {
		name  string
		port  int
		setup func(ctx context.Context, t *topology) (client *node, targetIP string, err error)
	}{
		{
			// DING -> DING.
			name: "DINGLoopback",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				return ding.node, "127.0.0.1", nil
			},
		},
		{
			// Host -> DING.
			name: "HostToDING",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				host, err := t.newHost(ctx)
				if err != nil {
					return nil, "", err
				}
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				return host, ding.ip, nil
			},
		},
		{
			// DING -> Host.
			name: "DINGToHost",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				host, err := t.newHost(ctx)
				if err != nil {
					return nil, "", err
				}
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				return ding.node, host.ip, nil
			},
		},
		{
			// DING -> DING.
			name: "DINGToDING",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding1, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				ding2, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				return ding1.node, ding2.ip, nil
			},
		},
		{
			// Host -> DINGSubContainer.
			name: "HostToDINGSubContainer",
			port: pubPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				host, err := t.newHost(ctx)
				if err != nil {
					return nil, "", err
				}
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				if _, err := ding.createNetwork(ctx, "net1"); err != nil {
					return nil, "", err
				}
				portMap := fmt.Sprintf("%d:%d", pubPort, iperfPort)
				if _, err := ding.newSubContainer(ctx, "c1", "net1", portMap); err != nil {
					return nil, "", err
				}
				return host, ding.ip, nil
			},
		},
		{
			// DINGSubContainer -> Host.
			name: "DINGSubContainerToHost",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				host, err := t.newHost(ctx)
				if err != nil {
					return nil, "", err
				}
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				if _, err := ding.createNetwork(ctx, "net1"); err != nil {
					return nil, "", err
				}
				c1, err := ding.newSubContainer(ctx, "c1", "net1", "")
				if err != nil {
					return nil, "", err
				}
				return c1, host.ip, nil
			},
		},
		{
			// DING -> DINGSubContainer over bridge net1.
			name: "DINGToDINGSubContainer",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				if _, err := ding.createNetwork(ctx, "net1"); err != nil {
					return nil, "", err
				}
				c1, err := ding.newSubContainer(ctx, "c1", "net1", "")
				if err != nil {
					return nil, "", err
				}
				return ding.node, c1.ip, nil
			},
		},
		{
			// DINGSubContainer c1 -> DING over net1 bridge.
			name: "DINGSubContainerToDING",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				gwIP, err := ding.createNetwork(ctx, "net1")
				if err != nil {
					return nil, "", err
				}
				c1, err := ding.newSubContainer(ctx, "c1", "net1", "")
				if err != nil {
					return nil, "", err
				}
				return c1, gwIP, nil
			},
		},
		{
			// DINGSubContainer c2 -> DINGSubContainer c1 on the same bridge (net1).
			name: "DINGSubContainerSameBridge",
			port: iperfPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				if _, err := ding.createNetwork(ctx, "net1"); err != nil {
					return nil, "", err
				}
				c1, err := ding.newSubContainer(ctx, "c1", "net1", "")
				if err != nil {
					return nil, "", err
				}
				c2, err := ding.newSubContainer(ctx, "c2", "net1", "")
				if err != nil {
					return nil, "", err
				}
				return c2, c1.ip, nil
			},
		},
		{
			// DINGSubContainer c1 (bridge net1) -> DING (bridge net2).
			name: "DINGSubContainerDifferentBridge",
			port: pubPort,
			setup: func(ctx context.Context, t *topology) (*node, string, error) {
				ding, err := t.newDING(ctx)
				if err != nil {
					return nil, "", err
				}
				gwIP, err := ding.createNetwork(ctx, "net1")
				if err != nil {
					return nil, "", err
				}
				if _, err := ding.createNetwork(ctx, "net2"); err != nil {
					return nil, "", err
				}
				c1, err := ding.newSubContainer(ctx, "c1", "net1", "")
				if err != nil {
					return nil, "", err
				}
				portMap := fmt.Sprintf("%d:%d", pubPort, iperfPort)
				if _, err := ding.newSubContainer(ctx, "c2", "net2", portMap); err != nil {
					return nil, "", err
				}
				return c1, gwIP, nil
			},
		},
	} {
		name, err := tools.ParametersToName(
			tools.Parameter{Name: "topology", Value: tc.name},
		)
		if err != nil {
			b.Fatalf("failed to parse parameters: %v", err)
		}

		b.Run(name, func(b *testing.B) {
			topo := &topology{machine: machine, logger: b}
			defer topo.cleanUp(ctx)

			setupCtx, cancelSetup := context.WithTimeout(ctx, setupTimeout)
			defer cancelSetup()
			client, targetIP, err := tc.setup(setupCtx, topo)
			if err != nil {
				b.Fatalf("failed to set up topology: %v", err)
			}
			iperf := tools.Iperf{
				Num: b.N, // KB.
			}
			cmd := iperf.MakeCmd(targetIP, tc.port)

			runCtx, cancelRun := context.WithTimeout(ctx, runTimeout)
			defer cancelRun()
			b.ResetTimer()
			out, err := client.runCmd(runCtx, cmd...)
			if err != nil {
				b.Fatalf("failed to run iperf: %v (%s)", err, out)
			}
			b.StopTimer()
			iperf.Report(b, out)
		})
	}
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
