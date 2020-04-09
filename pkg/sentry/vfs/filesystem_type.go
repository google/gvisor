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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// A FilesystemType constructs filesystems.
//
// FilesystemType is analogous to Linux's struct file_system_type.
type FilesystemType interface {
	// GetFilesystem returns a Filesystem configured by the given options,
	// along with its mount root. A reference is taken on the returned
	// Filesystem and Dentry.
	GetFilesystem(ctx context.Context, vfsObj *VirtualFilesystem, creds *auth.Credentials, source string, opts GetFilesystemOptions) (*Filesystem, *Dentry, error)

	// Name returns the name of this FilesystemType.
	Name() string
}

// GetFilesystemOptions contains options to FilesystemType.GetFilesystem.
type GetFilesystemOptions struct {
	// Data is the string passed as the 5th argument to mount(2), which is
	// usually a comma-separated list of filesystem-specific mount options.
	Data string

	// InternalData holds opaque FilesystemType-specific data. There is
	// intentionally no way for applications to specify InternalData; if it is
	// not nil, the call to GetFilesystem originates from within the sentry.
	InternalData interface{}
}

// +stateify savable
type registeredFilesystemType struct {
	fsType FilesystemType
	opts   RegisterFilesystemTypeOptions
}

// RegisterFilesystemTypeOptions contains options to
// VirtualFilesystem.RegisterFilesystem().
type RegisterFilesystemTypeOptions struct {
	// If AllowUserMount is true, allow calls to VirtualFilesystem.MountAt()
	// for which MountOptions.InternalMount == false to use this filesystem
	// type.
	AllowUserMount bool

	// If AllowUserList is true, make this filesystem type visible in
	// /proc/filesystems.
	AllowUserList bool

	// If RequiresDevice is true, indicate that mounting this filesystem
	// requires a block device as the mount source in /proc/filesystems.
	RequiresDevice bool
}

// RegisterFilesystemType registers the given FilesystemType in vfs with the
// given name.
func (vfs *VirtualFilesystem) RegisterFilesystemType(name string, fsType FilesystemType, opts *RegisterFilesystemTypeOptions) error {
	vfs.fsTypesMu.Lock()
	defer vfs.fsTypesMu.Unlock()
	if existing, ok := vfs.fsTypes[name]; ok {
		return fmt.Errorf("name %q is already registered to filesystem type %T", name, existing.fsType)
	}
	vfs.fsTypes[name] = &registeredFilesystemType{
		fsType: fsType,
		opts:   *opts,
	}
	return nil
}

// MustRegisterFilesystemType is equivalent to RegisterFilesystemType but
// panics on failure.
func (vfs *VirtualFilesystem) MustRegisterFilesystemType(name string, fsType FilesystemType, opts *RegisterFilesystemTypeOptions) {
	if err := vfs.RegisterFilesystemType(name, fsType, opts); err != nil {
		panic(fmt.Sprintf("failed to register filesystem type %T: %v", fsType, err))
	}
}

func (vfs *VirtualFilesystem) getFilesystemType(name string) *registeredFilesystemType {
	vfs.fsTypesMu.RLock()
	defer vfs.fsTypesMu.RUnlock()
	return vfs.fsTypes[name]
}

// GenerateProcFilesystems emits the contents of /proc/filesystems for vfs to
// buf.
func (vfs *VirtualFilesystem) GenerateProcFilesystems(buf *bytes.Buffer) {
	vfs.fsTypesMu.RLock()
	defer vfs.fsTypesMu.RUnlock()
	for name, rft := range vfs.fsTypes {
		if !rft.opts.AllowUserList {
			continue
		}
		var nodev string
		if !rft.opts.RequiresDevice {
			nodev = "nodev"
		}
		fmt.Fprintf(buf, "%s\t%s\n", nodev, name)
	}
}
