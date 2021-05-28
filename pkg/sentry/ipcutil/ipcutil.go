// Copyright 2021 The gVisor Authors.
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

// Package ipcutil defines a set of utilities common to sysvipc mechanisms.
package ipcutil

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// CheckOwnership verifies whether an IPC object may be accessed using creds as
// an owner. See ipc/util.c:ipcctl_obtain_check() in Linux.
func CheckOwnership(ns *auth.UserNamespace, owner, creator fs.FileOwner, creds *auth.Credentials) bool {
	if owner.UID == creds.EffectiveKUID || creator.UID == creds.EffectiveKUID {
		return true
	}

	// Tasks with CAP_SYS_ADMIN may bypass ownership checks. Strangely, Linux
	// doesn't use CAP_IPC_OWNER for this despite CAP_IPC_OWNER being documented
	// for use to "override IPC ownership checks".
	return creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, ns)
}

// CheckPermissions verifies whether an IPC object is accessible using creds for
// access described by req. See ipc/util.c:ipcperms() in Linux.
func CheckPermissions(ns *auth.UserNamespace, owner fs.FileOwner, perms fs.FilePermissions, creds *auth.Credentials, req fs.PermMask) bool {
	p := perms.Other
	if owner.UID == creds.EffectiveKUID {
		p = perms.User
	} else if creds.InGroup(owner.GID) {
		p = perms.Group
	}

	if p.SupersetOf(req) {
		return true
	}
	return creds.HasCapabilityIn(linux.CAP_IPC_OWNER, ns)
}
