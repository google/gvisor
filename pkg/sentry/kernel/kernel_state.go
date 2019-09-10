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

package kernel

import (
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// saveCleanupEndpoints is invoked by stateify.
func (k *Kernel) saveCleanupEndpoints() []stack.TransportEndpoint {
	if k.networkStack == nil {
		return nil
	}
	return k.networkStack.CleanupEndpoints()
}

// loadCleanupEndpoints is invoked by stateify.
func (k *Kernel) loadCleanupEndpoints(es []stack.TransportEndpoint) {
	if k.networkStack == nil {
		return
	}
	k.networkStack.RestoreCleanupEndpoints(es)
}

// saveRegisteredEndpoints is invoked by stateify.
func (k *Kernel) saveRegisteredEndpoints() []stack.TransportEndpoint {
	if k.networkStack == nil {
		return nil
	}
	return k.networkStack.RegisteredEndpoints()
}

// loadRegisteredEndpoints is invoked by stateify.
func (*Kernel) loadRegisteredEndpoints([]stack.TransportEndpoint) {}

// saveDeviceRegistry is invoked by stateify.
func (*Kernel) saveDeviceRegistry() *device.Registry {
	return device.SimpleDevices
}

// loadDeviceRegistry is invoked by stateify.
func (*Kernel) loadDeviceRegistry(r *device.Registry) {
	device.SimpleDevices.LoadFrom(r)
}
