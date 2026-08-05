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

// Package cxproxy implements the rdmaproxy.Driver plug-in for Mellanox/NVIDIA
// ConnectX adapters (mlx5_core / mlx5_ib). It mirrors the CQ/QP work-queue and
// doorbell DMA buffers referenced by the mlx5 driver-private UHW payload.
//
// To make this driver available, Init() must be called.
package cxproxy

import (
	"gvisor.dev/gvisor/pkg/abi/ib"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// driverName matches the DRIVER= field of
// /sys/class/infiniband/<ibdev>/device/uevent for ConnectX adapters bound to
// the upstream mlx5 stack. runsc looks this up via rdmaproxy.LookupDriver and
// attaches the resulting driver to the corresponding uverbs device.
const driverName = "mlx5_core"

// cxDriver is the rdmaproxy.Driver implementation for ConnectX adapters.
type cxDriver struct{}

// Name implements rdmaproxy.Driver.Name.
func (cxDriver) Name() string { return driverName }

// PrepareCreateDMA implements rdmaproxy.Driver.PrepareCreateDMA. It mirrors the
// work-queue buffer (buf_addr) and doorbell page (db_addr) referenced by the
// mlx5 driver-private payload, rewriting both fields to their sentry-side
// mappings before the ioctl is forwarded to the host kernel.
//
// mlx5 supplies no explicit buffer length in the payload, so the work-queue
// buffer is mirrored from buf_addr to the end of its VMA (the buffer is a
// single mlx5-allocated mapping); rdmaproxy caps the pinned length. The
// doorbell is a small record within one page, so a single page is mirrored.
func (cxDriver) PrepareCreateDMA(t *kernel.Task, uhwIn []byte) (*rdmaproxy.PinnedDMABufs, error) {
	var prefix ib.Mlx5CreatePrefix
	if len(uhwIn) < prefix.SizeBytes() {
		return nil, nil
	}
	prefix.UnmarshalBytes(uhwIn)

	var bufs rdmaproxy.PinnedDMABufs
	var cu cleanup.Cleanup
	defer cu.Clean()

	if prefix.BufAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(prefix.BufAddr))
		if err != nil {
			return nil, err
		}
		length := uint64(vmaRange.End) - prefix.BufAddr
		mp, sentryVA, err := rdmaproxy.MirrorAppPages(t, prefix.BufAddr, length)
		if err != nil {
			return nil, err
		}
		bufs.Buf = mp
		cu.Add(func() { mp.Release(t) })
		prefix.BufAddr = uint64(sentryVA)
	}

	if prefix.DBAddr != 0 {
		mp, sentryVA, err := rdmaproxy.MirrorAppPages(t, prefix.DBAddr, hostarch.PageSize)
		if err != nil {
			return nil, err
		}
		bufs.DB = mp
		cu.Add(func() { mp.Release(t) })
		prefix.DBAddr = uint64(sentryVA)
	}

	cu.Release()
	prefix.MarshalBytes(uhwIn)
	return &bufs, nil
}

// Schemas implements rdmaproxy.Driver.Schemas. It models the mlx5 UAR (User
// Access Region — the CQ/QP doorbell page) object: alloc returns an mmap
// offset that the app maps through the uverbs FD via the generic passthrough,
// so no address translation is needed here.
func (cxDriver) Schemas() map[uint32]*rdmaproxy.MethodSchema {
	return map[uint32]*rdmaproxy.MethodSchema{
		rdmaproxy.SchemaKey(ib.MLX5_IB_OBJECT_UAR, ib.MLX5_IB_METHOD_UAR_OBJ_ALLOC): {
			Attrs: map[uint16]rdmaproxy.AttrType{
				ib.MLX5_IB_ATTR_UAR_OBJ_ALLOC_HANDLE:      rdmaproxy.AttrIdr,
				ib.MLX5_IB_ATTR_UAR_OBJ_ALLOC_TYPE:        rdmaproxy.AttrPtrIn,
				ib.MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_OFFSET: rdmaproxy.AttrPtrOut,
				ib.MLX5_IB_ATTR_UAR_OBJ_ALLOC_MMAP_LENGTH: rdmaproxy.AttrPtrOut,
				ib.MLX5_IB_ATTR_UAR_OBJ_ALLOC_PAGE_ID:     rdmaproxy.AttrPtrOut,
			},
		},
		rdmaproxy.SchemaKey(ib.MLX5_IB_OBJECT_UAR, ib.MLX5_IB_METHOD_UAR_OBJ_DESTROY): {
			Attrs: map[uint16]rdmaproxy.AttrType{
				ib.MLX5_IB_ATTR_UAR_OBJ_DESTROY_HANDLE: rdmaproxy.AttrIdr,
			},
		},
	}
}

// Init registers the ConnectX (mlx5) driver plug-in with the rdmaproxy core.
func Init() { rdmaproxy.RegisterDriver(cxDriver{}) }
