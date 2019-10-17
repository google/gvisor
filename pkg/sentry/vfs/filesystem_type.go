// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// A FilesystemType constructs filesystems.
//
// FilesystemType is analogous to Linux's struct file_system_type.
type FilesystemType interface {
	// NewFilesystem returns a Filesystem configured by the given options,
	// along with its mount root. A reference is taken on the returned
	// Filesystem and Dentry.
	NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts NewFilesystemOptions) (*Filesystem, *Dentry, error)
}

// NewFilesystemOptions contains options to FilesystemType.NewFilesystem.
type NewFilesystemOptions struct {
	// Data is the string passed as the 5th argument to mount(2), which is
	// usually a comma-separated list of filesystem-specific mount options.
	Data string

	// InternalData holds opaque FilesystemType-specific data. There is
	// intentionally no way for applications to specify InternalData; if it is
	// not nil, the call to NewFilesystem originates from within the sentry.
	InternalData interface{}
}

// RegisterFilesystemType registers the given FilesystemType in vfs with the
// given name.
func (vfs *VirtualFilesystem) RegisterFilesystemType(name string, fsType FilesystemType) error {
	vfs.fsTypesMu.Lock()
	defer vfs.fsTypesMu.Unlock()
	if existing, ok := vfs.fsTypes[name]; ok {
		return fmt.Errorf("name %q is already registered to filesystem type %T", name, existing)
	}
	vfs.fsTypes[name] = fsType
	return nil
}

// MustRegisterFilesystemType is equivalent to RegisterFilesystemType but
// panics on failure.
func (vfs *VirtualFilesystem) MustRegisterFilesystemType(name string, fsType FilesystemType) {
	if err := vfs.RegisterFilesystemType(name, fsType); err != nil {
		panic(fmt.Sprintf("failed to register filesystem type %T: %v", fsType, err))
	}
}

func (vfs *VirtualFilesystem) getFilesystemType(name string) FilesystemType {
	vfs.fsTypesMu.RLock()
	defer vfs.fsTypesMu.RUnlock()
	return vfs.fsTypes[name]
}
