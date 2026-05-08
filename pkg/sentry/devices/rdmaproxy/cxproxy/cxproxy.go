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
// ConnectX adapters (mlx5_core / mlx5_ib). It exposes the driver-private
// uverbs attribute layout that mlx5 uses to carry CQ/QP DMA buffer pointers
// and registers itself with the rdmaproxy core at init() time.
//
// To make this driver available, the runsc binary must include this package
// in its import graph (typically via an anonymous import alongside the
// rdmaproxy core import).
package cxproxy

import (
	"encoding/binary"
	"fmt"

	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// driverName matches the value reported by the host's
// /sys/class/infiniband/<ibdev>/device/uevent DRIVER= field for ConnectX
// adapters bound to the upstream mlx5 stack. The runsc boot path looks up
// this name through rdmaproxy.LookupDriver and attaches the resulting
// rdmaproxy.Driver to the corresponding uverbs device.
const driverName = "mlx5_core"

// mlx5 driver attribute IDs (assigned by drivers/infiniband/hw/mlx5/main.c
// via the UVERBS_ID_DRIVER_NS_WITH_NS_IDX macros). Other vendors use
// different ranges and would register their own rdmaproxy.Driver.
const (
	mlx5DriverAttrIn  = 0x1000 // input driver-private attribute
	mlx5DriverAttrOut = 0x1001 // output driver-private attribute (unused here)
)

// Field offsets inside the mlx5 driver-private input attribute payload, which
// corresponds to struct mlx5_ib_create_cq / struct mlx5_ib_create_qp from the
// upstream kernel. Both structs share the same prefix layout for buf_addr +
// db_addr, which is all this proxy needs.
const (
	driverAttrBufAddr = 0  // __aligned_u64 buf_addr
	driverAttrDBAddr  = 8  // __aligned_u64 db_addr
	driverAttrMinLen  = 16 // minimum payload size to read both fields
)

// cxDriver is the rdmaproxy.Driver implementation for ConnectX adapters.
type cxDriver struct{}

// Name implements rdmaproxy.Driver.Name.
func (cxDriver) Name() string { return driverName }

// HasDriverCreateAttr implements rdmaproxy.Driver.HasDriverCreateAttr by
// scanning for the mlx5 driver-private input attribute, which is present on
// CQ/QP CREATE ioctls and absent on DESTROY/MODIFY.
func (cxDriver) HasDriverCreateAttr(buf []byte, numAttrs int) bool {
	return rdmaproxy.HasAttrID(buf, numAttrs, mlx5DriverAttrIn)
}

// PrepareCQQPCreate implements rdmaproxy.Driver.PrepareCQQPCreate. It mirrors
// the work-queue and doorbell DMA buffers referenced by buf_addr / db_addr
// inside the mlx5 driver-private input attribute, then rewrites those fields
// to point at the corresponding sentry-side mappings before the ioctl is
// forwarded to the host kernel.
//
// The action argument is one of rdmaproxy.ActionCQCreate or
// rdmaproxy.ActionQPCreate. Both share the same buf_addr/db_addr prefix in
// the mlx5 driver-private struct, so the action only matters for logging.
func (cxDriver) PrepareCQQPCreate(t *kernel.Task, buf []byte, numAttrs int,
	rewrites []rdmaproxy.AttrRewrite, action rdmaproxy.IoctlAction,
) (*rdmaproxy.PinnedDMABufs, error) {
	drv := rdmaproxy.FindRewrite(buf, numAttrs, rewrites, mlx5DriverAttrIn)
	if drv == nil {
		return nil, nil
	}
	if len(drv.Sentry) < driverAttrMinLen {
		return nil, nil
	}

	bufAddr := binary.LittleEndian.Uint64(drv.Sentry[driverAttrBufAddr : driverAttrBufAddr+8])
	dbAddr := binary.LittleEndian.Uint64(drv.Sentry[driverAttrDBAddr : driverAttrDBAddr+8])

	var bufs rdmaproxy.PinnedDMABufs
	var cu cleanup.Cleanup
	defer cu.Clean()

	if bufAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(bufAddr))
		if err != nil {
			return nil, fmt.Errorf("FindVMARange(buf %#x): %w", bufAddr, err)
		}
		length := uint64(vmaRange.End) - bufAddr
		mp, sentryVA, err := rdmaproxy.MirrorSandboxPages(t, bufAddr, length)
		if err != nil {
			return nil, fmt.Errorf("MirrorSandboxPages buf: %w", err)
		}
		bufs.Buf = mp
		cu.Add(func() { mp.Release(t) })
		binary.LittleEndian.PutUint64(drv.Sentry[driverAttrBufAddr:driverAttrBufAddr+8], uint64(sentryVA))
	}

	if dbAddr != 0 {
		vmaRange, err := t.MemoryManager().FindVMARange(hostarch.Addr(dbAddr))
		if err != nil {
			return nil, fmt.Errorf("FindVMARange(db %#x): %w", dbAddr, err)
		}
		length := uint64(vmaRange.End) - dbAddr
		mp, sentryVA, err := rdmaproxy.MirrorSandboxPages(t, dbAddr, length)
		if err != nil {
			return nil, fmt.Errorf("MirrorSandboxPages db: %w", err)
		}
		bufs.DB = mp
		cu.Add(func() { mp.Release(t) })
		binary.LittleEndian.PutUint64(drv.Sentry[driverAttrDBAddr:driverAttrDBAddr+8], uint64(sentryVA))
	}

	cu.Release()
	_ = action // currently unused; reserved for future per-action behavior.
	return &bufs, nil
}

func init() { rdmaproxy.RegisterDriver(cxDriver{}) }
