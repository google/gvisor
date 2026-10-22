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

package erofs

import (
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// listXattr returns the names of the inode's xattrs that creds can see.
func (i *inode) listXattr(creds *auth.Credentials) ([]string, error) {
	names, err := i.ListXattrs()
	if err != nil {
		return nil, err
	}
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	n := 0
	for _, name := range names {
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names[n] = name
		n++
	}
	return names[:n], nil
}

// getXattr returns the value of an xattr that creds can read.
func (i *inode) getXattr(creds *auth.Credentials, opts vfs.GetXattrOptions) (string, error) {
	if vfs.XattrReadNeedsFilePermission(opts.Name) {
		if err := i.checkPermissions(creds, vfs.MayRead); err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(opts.Name, linux.XATTR_SYSTEM_PREFIX) {
		return vfs.ACLGetXattr(creds, &opts, linux.FileMode(i.Mode()), nil, nil)
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayRead, linux.FileMode(i.Mode()), auth.KUID(i.UID()), opts.Name); err != nil {
		return "", err
	}
	value, err := i.Xattr(opts.Name)
	if err != nil {
		return "", err
	}
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		value, err = auth.FixupVfsCapDataOnGet(creds, value)
		if err != nil {
			return "", err
		}
	}
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", linuxerr.ERANGE
	}
	return value, nil
}
