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

// Package memxattr provides a default, in-memory extended attribute
// implementation.
package memxattr

import (
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// SimpleExtendedAttributes implements extended attributes using a map of
// names to values.
//
// SimpleExtendedAttributes calls vfs.CheckXattrPermissions, so callers are not
// required to do so.
//
// +stateify savable
type SimpleExtendedAttributes struct {
	// mu protects the below fields.
	mu     sync.RWMutex `state:"nosave"`
	xattrs map[string]string
}

// GetXattr returns the value at 'name'.
func (x *SimpleExtendedAttributes) GetXattr(creds *auth.Credentials, mode linux.FileMode, kuid auth.KUID, opts *vfs.GetXattrOptions) (string, error) {
	if err := vfs.CheckXattrPermissions(creds, vfs.MayRead, mode, kuid, opts.Name); err != nil {
		return "", err
	}

	x.mu.RLock()
	value, ok := x.xattrs[opts.Name]
	x.mu.RUnlock()
	if !ok {
		return "", linuxerr.ENODATA
	}
	// Check that the size of the buffer provided in getxattr(2) is large enough
	// to contain the value.
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", syserror.ERANGE
	}
	return value, nil
}

// SetXattr sets 'value' at 'name'.
func (x *SimpleExtendedAttributes) SetXattr(creds *auth.Credentials, mode linux.FileMode, kuid auth.KUID, opts *vfs.SetXattrOptions) error {
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, kuid, opts.Name); err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	if x.xattrs == nil {
		if opts.Flags&linux.XATTR_REPLACE != 0 {
			return linuxerr.ENODATA
		}
		x.xattrs = make(map[string]string)
	}

	_, ok := x.xattrs[opts.Name]
	if ok && opts.Flags&linux.XATTR_CREATE != 0 {
		return syserror.EEXIST
	}
	if !ok && opts.Flags&linux.XATTR_REPLACE != 0 {
		return linuxerr.ENODATA
	}

	x.xattrs[opts.Name] = opts.Value
	return nil
}

// ListXattr returns all names in xattrs.
func (x *SimpleExtendedAttributes) ListXattr(creds *auth.Credentials, size uint64) ([]string, error) {
	// Keep track of the size of the buffer needed in listxattr(2) for the list.
	listSize := 0
	x.mu.RLock()
	names := make([]string, 0, len(x.xattrs))
	haveCap := creds.HasCapability(linux.CAP_SYS_ADMIN)
	for n := range x.xattrs {
		// Hide extended attributes in the "trusted" namespace from
		// non-privileged users. This is consistent with Linux's
		// fs/xattr.c:simple_xattr_list().
		if !haveCap && strings.HasPrefix(n, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, n)
		// Add one byte per null terminator.
		listSize += len(n) + 1
	}
	x.mu.RUnlock()
	if size != 0 && uint64(listSize) > size {
		return nil, syserror.ERANGE
	}
	return names, nil
}

// RemoveXattr removes the xattr at 'name'.
func (x *SimpleExtendedAttributes) RemoveXattr(creds *auth.Credentials, mode linux.FileMode, kuid auth.KUID, name string) error {
	if err := vfs.CheckXattrPermissions(creds, vfs.MayWrite, mode, kuid, name); err != nil {
		return err
	}

	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.xattrs[name]; !ok {
		return linuxerr.ENODATA
	}
	delete(x.xattrs, name)
	return nil
}
