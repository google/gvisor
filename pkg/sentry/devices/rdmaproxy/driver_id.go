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
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// driverIDByModule maps PCI driver module names to RDMA driver IDs.
var driverIDByModule = map[string]uint32{
	"mlx5_core": linux.RDMA_DRIVER_MLX5,
	"mlx4_core": linux.RDMA_DRIVER_MLX4,
	"irdma":     linux.RDMA_DRIVER_IRDMA,
	"ice":       linux.RDMA_DRIVER_IRDMA,
	"i40e":      linux.RDMA_DRIVER_I40IW,
	"idpf":      linux.RDMA_DRIVER_IRDMA,
	"efa":       linux.RDMA_DRIVER_EFA,
	"bnxt_en":   linux.RDMA_DRIVER_BNXT_RE,
	"hns3":      linux.RDMA_DRIVER_HNS,
	"qede":      linux.RDMA_DRIVER_QEDR,
	"erdma":     linux.RDMA_DRIVER_ERDMA,
	"mana":      linux.RDMA_DRIVER_MANA,
}

// driverIDByIBDevPrefix maps ibdev name prefixes (the kernel driver's
// device naming convention) to RDMA driver IDs.
var driverIDByIBDevPrefix = []struct {
	prefix string
	id     uint32
}{
	{"mlx5_", linux.RDMA_DRIVER_MLX5},
	{"mlx4_", linux.RDMA_DRIVER_MLX4},
	{"irdma", linux.RDMA_DRIVER_IRDMA},
	{"rocep", linux.RDMA_DRIVER_IRDMA}, // irdma RoCE naming
	{"iwp", linux.RDMA_DRIVER_IRDMA},   // irdma iWARP naming
	{"efa_", linux.RDMA_DRIVER_EFA},
	{"bnxt_re", linux.RDMA_DRIVER_BNXT_RE},
	{"hns_", linux.RDMA_DRIVER_HNS},
	{"rxe", linux.RDMA_DRIVER_RXE},
	{"siw", linux.RDMA_DRIVER_SIW},
	{"erdma", linux.RDMA_DRIVER_ERDMA},
	{"mana_", linux.RDMA_DRIVER_MANA},
	{"qedr", linux.RDMA_DRIVER_QEDR},
}

// DriverID infers the RDMA driver ID (enum rdma_driver_id, reported to
// userspace in RDMA_NLDEV_ATTR_UVERBS_DRIVER_ID) for a device from its PCI
// driver module name and ibdev name. Reporting the correct ID lets
// libibverbs bind the provider library directly; on ok == false the
// returned RDMA_DRIVER_UNKNOWN makes rdma-core fall back to PCI ID
// matching.
func DriverID(ibdevName, pciDriver string) (id uint32, ok bool) {
	if id, ok := driverIDByModule[pciDriver]; ok {
		return id, true
	}
	for _, e := range driverIDByIBDevPrefix {
		if strings.HasPrefix(ibdevName, e.prefix) {
			return e.id, true
		}
	}
	return linux.RDMA_DRIVER_UNKNOWN, false
}
