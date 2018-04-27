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

package fs

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
)

// contextID is the kernel package's type for context.Context.Value keys.
type contextID int

const (
	// CtxRoot is a Context.Value key for a Dirent.
	CtxRoot contextID = iota
)

// ContextCanAccessFile determines whether `file` can be accessed in the requested way
// (for reading, writing, or execution) using the caller's credentials and user
// namespace, as does Linux's fs/namei.c:generic_permission.
func ContextCanAccessFile(ctx context.Context, inode *Inode, reqPerms PermMask) bool {
	creds := auth.CredentialsFromContext(ctx)
	uattr, err := inode.UnstableAttr(ctx)
	if err != nil {
		return false
	}

	p := uattr.Perms.Other
	// Are we owner or in group?
	if uattr.Owner.UID == creds.EffectiveKUID {
		p = uattr.Perms.User
	} else if creds.InGroup(uattr.Owner.GID) {
		p = uattr.Perms.Group
	}

	// Are permissions satisfied without capability checks?
	if p.SupersetOf(reqPerms) {
		return true
	}

	if IsDir(inode.StableAttr) {
		// CAP_DAC_OVERRIDE can override any perms on directories.
		if inode.CheckCapability(ctx, linux.CAP_DAC_OVERRIDE) {
			return true
		}

		// CAP_DAC_READ_SEARCH can normally only override Read perms,
		// but for directories it can also override execution.
		if !reqPerms.Write && inode.CheckCapability(ctx, linux.CAP_DAC_READ_SEARCH) {
			return true
		}
	}

	// CAP_DAC_OVERRIDE can always override Read/Write.
	// Can override executable only when at least one execute bit is set.
	if !reqPerms.Execute || uattr.Perms.AnyExecute() {
		if inode.CheckCapability(ctx, linux.CAP_DAC_OVERRIDE) {
			return true
		}
	}

	// Read perms can be overridden by CAP_DAC_READ_SEARCH.
	if reqPerms.OnlyRead() && inode.CheckCapability(ctx, linux.CAP_DAC_READ_SEARCH) {
		return true
	}
	return false
}

// FileOwnerFromContext returns a FileOwner using the effective user and group
// IDs used by ctx.
func FileOwnerFromContext(ctx context.Context) FileOwner {
	creds := auth.CredentialsFromContext(ctx)
	return FileOwner{creds.EffectiveKUID, creds.EffectiveKGID}
}

// RootFromContext returns the root of the virtual filesystem observed by ctx,
// or nil if ctx is not associated with a virtual filesystem. If
// RootFromContext returns a non-nil fs.Dirent, a reference is taken on it.
func RootFromContext(ctx context.Context) *Dirent {
	if v := ctx.Value(CtxRoot); v != nil {
		return v.(*Dirent)
	}
	return nil
}
