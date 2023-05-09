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
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// This takes both input and output as pointer arguments to avoid copying large
// structs.
func convertStatxToUserStat(t *kernel.Task, statx *linux.Statx, stat *linux.Stat) {
	// Linux just copies fields from struct kstat without regard to struct
	// kstat::result_mask (fs/stat.c:cp_new_stat()), so we do too.
	userns := t.UserNamespace()
	*stat = linux.Stat{
		Dev:     uint64(linux.MakeDeviceID(uint16(statx.DevMajor), statx.DevMinor)),
		Ino:     statx.Ino,
		Nlink:   uint32(statx.Nlink),
		Mode:    uint32(statx.Mode),
		UID:     uint32(auth.KUID(statx.UID).In(userns).OrOverflow()),
		GID:     uint32(auth.KGID(statx.GID).In(userns).OrOverflow()),
		Rdev:    uint64(linux.MakeDeviceID(uint16(statx.RdevMajor), statx.RdevMinor)),
		Size:    int64(statx.Size),
		Blksize: int32(statx.Blksize),
		Blocks:  int64(statx.Blocks),
		ATime:   timespecFromStatxTimestamp(statx.Atime),
		MTime:   timespecFromStatxTimestamp(statx.Mtime),
		CTime:   timespecFromStatxTimestamp(statx.Ctime),
	}
}
