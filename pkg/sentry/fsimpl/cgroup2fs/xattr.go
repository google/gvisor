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

package cgroup2fs

import (
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

var _ kernfs.InodeWithXattrs = (*cgroup)(nil)

func cgroup2XattrAllowed(name string) bool {
	return strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) ||
		strings.HasPrefix(name, linux.XATTR_SECURITY_PREFIX) ||
		strings.HasPrefix(name, linux.XATTR_USER_PREFIX)
}

// GetXattr implements kernfs.InodeWithXattrs.GetXattr.
func (c *cgroup) GetXattr(ctx context.Context, opts vfs.GetXattrOptions) (string, error) {
	if !cgroup2XattrAllowed(opts.Name) {
		return "", linuxerr.EOPNOTSUPP
	}
	creds := auth.CredentialsFromContext(ctx)
	return c.xattrs.GetXattr(creds, c.Mode(), c.UID(), &opts)
}

// SetXattr implements kernfs.InodeWithXattrs.SetXattr.
func (c *cgroup) SetXattr(ctx context.Context, opts vfs.SetXattrOptions) error {
	if !cgroup2XattrAllowed(opts.Name) {
		return linuxerr.EOPNOTSUPP
	}
	creds := auth.CredentialsFromContext(ctx)
	return c.xattrs.SetXattr(creds, c.Mode(), c.UID(), c.GID(), &opts)
}

// ListXattr implements kernfs.InodeWithXattrs.ListXattr.
func (c *cgroup) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	creds := auth.CredentialsFromContext(ctx)
	return c.xattrs.ListXattr(creds, size)
}

// RemoveXattr implements kernfs.InodeWithXattrs.RemoveXattr.
func (c *cgroup) RemoveXattr(ctx context.Context, name string) error {
	if !cgroup2XattrAllowed(name) {
		return linuxerr.EOPNOTSUPP
	}
	creds := auth.CredentialsFromContext(ctx)
	return c.xattrs.RemoveXattr(creds, c.Mode(), c.UID(), name)
}
