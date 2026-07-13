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

package rdmaproxy

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sync"
)

// registeredDevs records the in-sandbox device numbers of registered RDMA
// devices so that the NETLINK_RDMA protocol can report them in
// RDMA_NLDEV_ATTR_CHARDEV. rdma-core verifies that the reported dev_t
// matches st_rdev of the opened device node (rdma-core
// util/open_cdev.c:open_cdev_internal), so these must be the numbers the
// device files are registered with, not the host's.
var registeredDevs struct {
	mu sync.RWMutex
	// uverbsMinors maps uverbs device numbers (the N in
	// /dev/infiniband/uverbsN) to registered device minors.
	uverbsMinors map[uint32]uint32
	rdmaCMMinor  uint32
	rdmaCMSet    bool
}

func recordUverbsDevice(deviceNum, minor uint32) {
	registeredDevs.mu.Lock()
	defer registeredDevs.mu.Unlock()
	if registeredDevs.uverbsMinors == nil {
		registeredDevs.uverbsMinors = make(map[uint32]uint32)
	}
	registeredDevs.uverbsMinors[deviceNum] = minor
}

func recordRDMACMDevice(minor uint32) {
	registeredDevs.mu.Lock()
	defer registeredDevs.mu.Unlock()
	registeredDevs.rdmaCMMinor = minor
	registeredDevs.rdmaCMSet = true
}

// UverbsDev returns the registered device number of
// /dev/infiniband/uverbs<deviceNum>.
func UverbsDev(deviceNum uint32) (major, minor uint32, ok bool) {
	registeredDevs.mu.RLock()
	defer registeredDevs.mu.RUnlock()
	minor, ok = registeredDevs.uverbsMinors[deviceNum]
	return rdmaDevMajor, minor, ok
}

// RDMACMDev returns the registered device number of /dev/infiniband/rdma_cm.
func RDMACMDev() (major, minor uint32, ok bool) {
	registeredDevs.mu.RLock()
	defer registeredDevs.mu.RUnlock()
	return linux.MISC_MAJOR, registeredDevs.rdmaCMMinor, registeredDevs.rdmaCMSet
}
