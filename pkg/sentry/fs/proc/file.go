// Copyright 2018 Google Inc.
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

package proc

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type file struct {
	fs.InodeOperations

	// nodeType is the file type of this file.
	nodeType fs.InodeType

	// t is the associated kernel task that owns this file.
	t *kernel.Task
}

func newFile(node fs.InodeOperations, msrc *fs.MountSource, nodeType fs.InodeType, t *kernel.Task) *fs.Inode {
	iops := &file{node, nodeType, t}
	sattr := fs.StableAttr{
		DeviceID:  device.ProcDevice.DeviceID(),
		InodeID:   device.ProcDevice.NextIno(),
		BlockSize: usermem.PageSize,
		Type:      nodeType,
	}
	return fs.NewInode(iops, msrc, sattr)
}

// UnstableAttr returns all attributes of this file.
func (f *file) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, err := f.InodeOperations.UnstableAttr(ctx, inode)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	if f.t != nil {
		uattr.Owner = fs.FileOwnerFromContext(f.t)
	}
	return uattr, nil
}
