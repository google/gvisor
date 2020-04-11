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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// SimpleExtendedAttributes implements extended attributes using a map of
// names to values.
//
// +stateify savable
type SimpleExtendedAttributes struct {
	// mu protects the below fields.
	mu     sync.RWMutex `state:"nosave"`
	xattrs map[string]string
}

// Getxattr returns the value at 'name'.
func (x *SimpleExtendedAttributes) Getxattr(opts *vfs.GetxattrOptions) (string, error) {
	x.mu.RLock()
	value, ok := x.xattrs[opts.Name]
	x.mu.RUnlock()
	if !ok {
		return "", syserror.ENODATA
	}
	// Check that the size of the buffer provided in getxattr(2) is large enough
	// to contain the value.
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", syserror.ERANGE
	}
	return value, nil
}

// Setxattr sets 'value' at 'name'.
func (x *SimpleExtendedAttributes) Setxattr(opts *vfs.SetxattrOptions) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.xattrs == nil {
		if opts.Flags&linux.XATTR_REPLACE != 0 {
			return syserror.ENODATA
		}
		x.xattrs = make(map[string]string)
	}

	_, ok := x.xattrs[opts.Name]
	if ok && opts.Flags&linux.XATTR_CREATE != 0 {
		return syserror.EEXIST
	}
	if !ok && opts.Flags&linux.XATTR_REPLACE != 0 {
		return syserror.ENODATA
	}

	x.xattrs[opts.Name] = opts.Value
	return nil
}

// Listxattr returns all names in xattrs.
func (x *SimpleExtendedAttributes) Listxattr(size uint64) ([]string, error) {
	// Keep track of the size of the buffer needed in listxattr(2) for the list.
	listSize := 0
	x.mu.RLock()
	names := make([]string, 0, len(x.xattrs))
	for n := range x.xattrs {
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

// Removexattr removes the xattr at 'name'.
func (x *SimpleExtendedAttributes) Removexattr(name string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if _, ok := x.xattrs[name]; !ok {
		return syserror.ENODATA
	}
	delete(x.xattrs, name)
	return nil
}
