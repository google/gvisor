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

// Driver is the per-vendor plug-in interface for handling RDMA driver-private
// uverbs attributes. The vendor-neutral RDMA core can route every standard
// UVERBS object/method, but the driver-private input attrs that carry CQ/QP
// DMA buffer pointers are vendor-specific (mlx5_ib_create_cq, bnxt_re_qp_req,
// efa_ibv_create_qp, ...). Drivers register themselves at init() time and the
// core dispatches CQ/QP CREATE classification + DMA buffer mirroring through
// this interface.
//
// Implementations live in vendor-specific subpackages, e.g.
// pkg/sentry/devices/rdmaproxy/cxproxy for ConnectX (mlx5).
type Driver interface {
	// Name returns the driver name as it appears in the host's
	// /sys/class/infiniband/<ibdev>/device/uevent DRIVER= field. This is
	// the same string passed to Register and used to look up the driver
	// at registration time.
	Name() string

	// HasDriverCreateAttr returns true if the parsed UVERBS ioctl buffer
	// contains the driver-private input attribute that signals a CQ/QP
	// CREATE op. The core uses this to distinguish CREATE from
	// DESTROY/MODIFY because modern UVERBS method IDs for these ops are
	// not stable across kernel versions.
	HasDriverCreateAttr(buf []byte, numAttrs int) bool

	// PrepareCQQPCreate mirrors the DMA buffers (work queue + doorbell
	// pages) referenced by the driver-private input attribute and
	// rewrites the embedded sandbox addresses to the corresponding
	// sentry-side mappings. Returns a handle that the caller stores
	// against the new CQ/QP IDR handle on success and releases on
	// teardown.
	//
	// The action argument is one of ActionCQCreate or ActionQPCreate.
	// rewrites is the slice of attribute rewrites already performed by
	// the core; the driver finds its own attribute by ID inside this
	// slice.
	PrepareCQQPCreate(t *kernel.Task, buf []byte, numAttrs int,
		rewrites []AttrRewrite, action IoctlAction) (*PinnedDMABufs, error)
}

// driverRegistry holds Drivers registered by per-vendor packages at init()
// time. Registration is keyed by Driver.Name(), which must match the host
// PCI driver name plumbed into Register.
type driverRegistry struct {
	mu      sync.RWMutex
	drivers map[string]Driver
}

var registry = &driverRegistry{drivers: make(map[string]Driver)}

// RegisterDriver makes drv available for lookup by drv.Name(). Intended to
// be called from a per-vendor package init(); duplicate registrations under
// the same name overwrite the previous entry (last writer wins) so tests can
// stub a driver out without running afoul of init-order constraints.
func RegisterDriver(drv Driver) {
	if drv == nil {
		return
	}
	name := drv.Name()
	registry.mu.Lock()
	registry.drivers[name] = drv
	registry.mu.Unlock()
	log.Infof("rdmaproxy: registered driver name=%s", name)
}

// LookupDriver returns the driver registered under name, or nil if no such
// driver was registered. An empty name always returns nil (the caller is
// responsible for handling the no-driver case explicitly; see Register).
func LookupDriver(name string) Driver {
	if name == "" {
		return nil
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.drivers[name]
}
