// Copyright 2024 The gVisor Authors.
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

package rdmaproxy

import (
	"sync"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Driver is the per-vendor plug-in interface for mirroring the DMA buffers a
// CQ or QP CREATE references through its driver-private (UHW) payload.
//
// The vendor-neutral core routes every standard UVERBS object/method from the
// schema, but the work-queue and doorbell buffer pointers embedded in the
// driver-private data are vendor-specific (mlx5_ib_create_cq / mlx5_ib_create_qp,
// efa_ibv_create_qp, ...). The core hands the copied-in UHW_IN payload to the
// matching driver during CQ/QP CREATE.
//
// Implementations live in vendor-specific subpackages, e.g.
// pkg/sentry/devices/rdmaproxy/cxproxy for ConnectX (mlx5).
type Driver interface {
	// Name returns the driver name as it appears in the host's
	// /sys/class/infiniband/<ibdev>/device/uevent DRIVER= field (e.g.
	// "mlx5_core"). This is the string passed to Register and used to look
	// up the driver at registration time.
	Name() string

	// PrepareCreateDMA mirrors the DMA buffers referenced by the vendor
	// driver-private payload of a CQ or QP CREATE and rewrites the embedded
	// app addresses in uhwIn IN PLACE to the corresponding sentry-side
	// mappings. uhwIn is the sentry-side copy of the UHW_IN attribute the
	// core already copied in from the guest; the host kernel will forward it
	// to the vendor driver verbatim. The CQ and QP driver-private structs
	// share the buf/doorbell prefix this needs, so CREATE type is not passed.
	//
	// It returns a handle tracking the mirrored pages, stored by the core
	// against the resulting CQ/QP handle and released on teardown, or nil if
	// the payload referenced no buffers. A non-nil error aborts the ioctl.
	PrepareCreateDMA(t *kernel.Task, uhwIn []byte) (*PinnedDMABufs, error)

	// Schemas returns the driver-namespace (object, method) pairs this driver
	// models (IDs >= UVERBS_ID_DRIVER_NS), keyed by SchemaKey, which the core
	// merges into its allowlist.
	Schemas() map[uint32]*MethodSchema
}

// driverRegistry holds Drivers registered by per-vendor packages keyed by
// Driver.Name() (which must match the host PCI driver name).
type driverRegistry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

var registryOnce sync.Once
var registry *driverRegistry

// driverReg returns the process-wide driver registry.
func driverReg() *driverRegistry {
	registryOnce.Do(func() {
		registry = &driverRegistry{drivers: make(map[string]Driver)}
	})
	return registry
}

// RegisterDriver makes drv available for lookup by drv.Name(). Duplicate
// registrations under the same name overwrite the previous entry (last writer
// wins) so tests can stub a driver.
func RegisterDriver(drv Driver) {
	reg := driverReg()
	name := drv.Name()
	reg.mu.Lock()
	reg.drivers[name] = drv
	reg.mu.Unlock()
	log.Infof("rdmaproxy: registered driver name=%s", name)
}

// LookupDriver returns the driver registered under name, or nil if none.
func LookupDriver(name string) Driver {
	reg := driverReg()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	return reg.drivers[name]
}

// rangeDrivers calls f for each registered driver.
func rangeDrivers(f func(Driver)) {
	reg := driverReg()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	for _, drv := range reg.drivers {
		f(drv)
	}
}

// RegisteredDrivers returns the names of all registered drivers.
func RegisteredDrivers() []string {
	reg := driverReg()
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	names := make([]string, 0, len(reg.drivers))
	for name := range reg.drivers {
		names = append(names, name)
	}
	return names
}
