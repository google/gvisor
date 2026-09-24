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

// Package genericproxy implements a no-op rdmaproxy.Driver plug-in for an explicit
// allow-list of host RDMA drivers.
//
// To make this driver available, Init() must be called.
package genericproxy

import (
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// genericDriver is the no-op rdmaproxy.Driver implementation. A single
// instance is registered under rdmaproxy.GenericDriverName; rdmaproxy's
// LookupDriver returns it for allow-listed host driver names that have no
// vendor-specific plug-in of their own.
type genericDriver struct{}

// Name implements rdmaproxy.Driver.Name.
func (d genericDriver) Name() string { return rdmaproxy.GenericDriverName }

// PrepareCreateDMA implements rdmaproxy.Driver.PrepareCreateDMA. It is a
// no-op: the UHW payload is forwarded verbatim and no pages are mirrored.
func (genericDriver) PrepareCreateDMA(t *kernel.Task, uhwIn []byte) (*rdmaproxy.PinnedDMABufs, error) {
	return nil, nil
}

// Schemas implements rdmaproxy.Driver.Schemas. No driver-namespace methods
// are modeled; driver-private ioctl methods are rejected by the core.
func (genericDriver) Schemas() map[uint32]*rdmaproxy.MethodSchema {
	return nil
}

// Init registers the no-op plug-in once under rdmaproxy.GenericDriverName.
func Init() { rdmaproxy.RegisterDriver(genericDriver{}) }
