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

// Package efaproxy implements the rdmaproxy.Driver plug-in for AWS Elastic
// Fabric Adapter (EFA) devices bound to the host `efa` kernel driver.
//
// To make this driver available, Init() must be called.
package efaproxy

import (
	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// driverName matches the DRIVER= field of
// /sys/class/infiniband/<ibdev>/device/uevent for EFA adapters. runsc looks
// this up via rdmaproxy.LookupDriver and attaches the resulting driver to the
// corresponding uverbs device.
const driverName = "efa"

// efaDriver is the rdmaproxy.Driver implementation for EFA adapters.
type efaDriver struct{}

// Name implements rdmaproxy.Driver.Name.
func (efaDriver) Name() string { return driverName }

// PrepareCreateDMA implements rdmaproxy.Driver.PrepareCreateDMA. EFA CQ/QP
// CREATE command structs (efa_ibv_create_cq / efa_ibv_create_qp) carry no
// userspace buffer pointers. The host kernel allocates the work-queue and
// doorbell memory and hands it back through mmap keys in the CREATE *response*
// (q_mmap_key, rq_mmap_key, sq_db_mmap_key, ...); userspace then mmap()s the
// uverbs FD at those offsets, which the rdmaproxy core already forwards to the
// host FD verbatim. There is thus no app memory to mirror or rewrite at CREATE
// time, so PrepareCreateDMA is a no-op.
func (efaDriver) PrepareCreateDMA(t *kernel.Task, uhwIn []byte) (*rdmaproxy.PinnedDMABufs, error) {
	return nil, nil
}

// Schemas implements rdmaproxy.Driver.Schemas. EFA extends the standard MR
// object with a query method returning the interconnect IDs a source MR must
// advertise for RDMA read/write; libfabric's EFA provider issues it during
// endpoint setup. All attributes are handles or fixed scalars, so no address
// translation is needed.
func (efaDriver) Schemas() map[uint32]*rdmaproxy.MethodSchema {
	return map[uint32]*rdmaproxy.MethodSchema{
		rdmaproxy.SchemaKey(ib.UVERBS_OBJECT_MR, ib.EFA_IB_METHOD_MR_QUERY): {
			Attrs: map[uint16]rdmaproxy.AttrType{
				ib.EFA_IB_ATTR_QUERY_MR_HANDLE:               rdmaproxy.AttrIdr,
				ib.EFA_IB_ATTR_QUERY_MR_RESP_IC_ID_VALIDITY:  rdmaproxy.AttrPtrOut,
				ib.EFA_IB_ATTR_QUERY_MR_RESP_RECV_IC_ID:      rdmaproxy.AttrPtrOut,
				ib.EFA_IB_ATTR_QUERY_MR_RESP_RDMA_READ_IC_ID: rdmaproxy.AttrPtrOut,
				ib.EFA_IB_ATTR_QUERY_MR_RESP_RDMA_RECV_IC_ID: rdmaproxy.AttrPtrOut,
			},
		},
	}
}

// Init registers the EFA driver plug-in with the rdmaproxy core.
func Init() { rdmaproxy.RegisterDriver(efaDriver{}) }
