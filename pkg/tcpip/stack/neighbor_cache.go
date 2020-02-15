// Copyright 2019 The gVisor Authors.
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

package stack

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// NeighborCache is the per-interface cache for mapping IP addresses to link
// addresses. It contains the state machine for running Neighbor Unreachability
// Detection, as well as the configuration for each NIC.
type NeighborCache interface {
	// Config returns the NUD configuration for the interface.
	Config() NUDConfigurations

	// UpdateConfig changes the NUD configuration for nicID.
	//
	// If config contains invalid NUD configuration values, it will be fixed to
	// use default values for the erroneous values.
	UpdateConfig(config NUDConfigurations)
}

// neighborCache is a fixed-sized cache mapping IP addresses to link addresses.
// Entries are stored in a ring buffer, oldest entry replaced first.
type neighborCache struct {
	NeighborCache

	// configs holds the per-interface Neighbor Unreachability Detection
	// configurations.
	configs struct {
		mu  sync.RWMutex
		nud *NUDConfigurations
	}
}

func newNeighborCache(config NUDConfigurations) *neighborCache {
	n := &neighborCache{}
	n.UpdateConfig(config)
	return n
}

// Config implements NeighborCache.Config.
func (n *neighborCache) Config() NUDConfigurations {
	n.configs.mu.RLock()
	defer n.configs.mu.RUnlock()
	return *n.configs.nud
}

// UpdateConfig implements NeighborCache.UpdateConfig.
func (n *neighborCache) UpdateConfig(config NUDConfigurations) {
	config.validate()
	n.configs.mu.RLock()
	if n.configs.nud == nil {
		n.configs.nud = new(NUDConfigurations)
	}
	*n.configs.nud = config
	n.configs.mu.RUnlock()
}
