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

// Package landlock implements file descriptors for Landlock rulesets.
package landlock

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// RulesetFD represents a Landlock ruleset file descriptor.
//
// +stateify savable
type RulesetFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// handledAccessFS is the set of filesystem access rights handled by this
	// ruleset.
	//
	// Immutable after ruleset creation.
	handledAccessFS uint64
}

// NewRulesetFD returns a new Landlock ruleset file descriptor.
func NewRulesetFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, fileFlags uint32, handledAccessFS uint64) (*vfs.FileDescription, error) {
	creds := auth.CredentialsFromContext(ctx)
	fd := &RulesetFD{
		handledAccessFS: handledAccessFS,
	}

	vd := vfsObj.NewAnonVirtualDentry("[landlock-ruleset]")
	defer vd.DecRef(ctx)

	err := fd.vfsfd.Init(fd, fileFlags, creds, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	})
	if err != nil {
		return nil, err
	}

	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *RulesetFD) Release(context.Context) {
}

// HandledAccessFS returns the filesystem access rights handled by this ruleset.
func (fd *RulesetFD) HandledAccessFS() uint64 {
	return fd.handledAccessFS
}
