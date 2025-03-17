// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vfio

import (
	"gvisor.dev/gvisor/pkg/context"
)

// NOTE: TPU save/restore does not work as expected without tight coordination
// with the application. TPU device state is not saved, all memory mappings
// are marked as invalid, and TPU/VFIO related file descriptors are stubbed out.
// Accessing any TPU memory mappings after restore will result in SIGBUS.
// Issuing any TPU IOCTL command will be a no-op. Reading and writing to TPU
// FDs will be a no-op.
//
// It is up to the application to release all TPU resources before saving and
// reinitialize them after restoring.

func (fd *tpuFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}

func (fd *vfioFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}

func (fd *pciDeviceFD) beforeSave() {
	fd.Release(context.Background())
	fd.hostFD = -1
}
