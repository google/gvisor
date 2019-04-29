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
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

// saveDanglingEndpoints is invoked by stateify.
func (k *Kernel) saveDanglingEndpoints() []tcpip.Endpoint {
	return tcpip.GetDanglingEndpoints()
}

// loadDanglingEndpoints is invoked by stateify.
func (k *Kernel) loadDanglingEndpoints(es []tcpip.Endpoint) {
	for _, e := range es {
		tcpip.AddDanglingEndpoint(e)
	}
}

// saveDeviceRegistry is invoked by stateify.
func (k *Kernel) saveDeviceRegistry() *device.Registry {
	return device.SimpleDevices
}

// loadDeviceRegistry is invoked by stateify.
func (k *Kernel) loadDeviceRegistry(r *device.Registry) {
	device.SimpleDevices.LoadFrom(r)
}
