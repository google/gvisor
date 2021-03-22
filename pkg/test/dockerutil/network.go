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
	"context"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// Network is a docker network.
type Network struct {
	client     *client.Client
	id         string
	logger     testutil.Logger
	Name       string
	containers []*Container
	Subnet     *net.IPNet
}

// NewNetwork sets up the struct for a Docker network. Names of networks
// will be unique.
func NewNetwork(ctx context.Context, logger testutil.Logger) *Network {
	client, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		logger.Logf("create client failed with: %v", err)
		return nil
	}
	client.NegotiateAPIVersion(ctx)

	return &Network{
		logger: logger,
		Name:   testutil.RandomID(logger.Name()),
		client: client,
	}
}

func (n *Network) networkCreate() types.NetworkCreate {

	var subnet string
	if n.Subnet != nil {
		subnet = n.Subnet.String()
	}

	ipam := network.IPAM{
		Config: []network.IPAMConfig{{
			Subnet: subnet,
		}},
	}

	return types.NetworkCreate{
		CheckDuplicate: true,
		IPAM:           &ipam,
	}
}

// Create is analogous to 'docker network create'.
func (n *Network) Create(ctx context.Context) error {

	opts := n.networkCreate()
	resp, err := n.client.NetworkCreate(ctx, n.Name, opts)
	if err != nil {
		return err
	}
	n.id = resp.ID
	return nil
}

// Connect is analogous to 'docker network connect' with the arguments provided.
func (n *Network) Connect(ctx context.Context, container *Container, ipv4, ipv6 string) error {
	settings := network.EndpointSettings{
		IPAMConfig: &network.EndpointIPAMConfig{
			IPv4Address: ipv4,
			IPv6Address: ipv6,
		},
	}
	err := n.client.NetworkConnect(ctx, n.id, container.id, &settings)
	if err == nil {
		n.containers = append(n.containers, container)
	}
	return err
}

// Inspect returns this network's info.
func (n *Network) Inspect(ctx context.Context) (types.NetworkResource, error) {
	return n.client.NetworkInspect(ctx, n.id, types.NetworkInspectOptions{Verbose: true})
}

// Cleanup cleans up the docker network.
func (n *Network) Cleanup(ctx context.Context) error {
	n.containers = nil

	return n.client.NetworkRemove(ctx, n.id)
}
