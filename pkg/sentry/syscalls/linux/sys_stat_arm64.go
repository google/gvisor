// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// LINT.IfChange

func statFromAttrs(t *kernel.Task, sattr fs.StableAttr, uattr fs.UnstableAttr) linux.Stat {
	return linux.Stat{
		Dev:     sattr.DeviceID,
		Ino:     sattr.InodeID,
		Nlink:   uint32(uattr.Links),
		Mode:    sattr.Type.LinuxType() | uint32(uattr.Perms.LinuxMode()),
		UID:     uint32(uattr.Owner.UID.In(t.UserNamespace()).OrOverflow()),
		GID:     uint32(uattr.Owner.GID.In(t.UserNamespace()).OrOverflow()),
		Rdev:    uint64(linux.MakeDeviceID(sattr.DeviceFileMajor, sattr.DeviceFileMinor)),
		Size:    uattr.Size,
		Blksize: int32(sattr.BlockSize),
		Blocks:  uattr.Usage / 512,
		ATime:   uattr.AccessTime.Timespec(),
		MTime:   uattr.ModificationTime.Timespec(),
		CTime:   uattr.StatusChangeTime.Timespec(),
	}
}

// LINT.ThenChange(vfs2/stat_arm64.go)
