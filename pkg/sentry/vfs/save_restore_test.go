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

package vfs

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

type saveRestoreTestFilesystem struct {
	FilesystemImpl

	vfsfs               Filesystem
	lastPrepareSaveOpts PrepareSaveOptions
	prepareSaveCalled   bool
}

var _ FilesystemImplSaveRestoreExtension = (*saveRestoreTestFilesystem)(nil)

func (fs *saveRestoreTestFilesystem) Release(ctx context.Context) {}

func (fs *saveRestoreTestFilesystem) PrepareSave(ctx context.Context, opts PrepareSaveOptions) error {
	fs.lastPrepareSaveOpts = opts
	fs.prepareSaveCalled = true
	return nil
}

func (fs *saveRestoreTestFilesystem) BeforeResume(ctx context.Context) {}

func (fs *saveRestoreTestFilesystem) CompleteRestore(ctx context.Context, opts CompleteRestoreOptions) error {
	return nil
}

type saveRestoreTestFilesystemType struct {
	fs *saveRestoreTestFilesystem
}

func (fstype *saveRestoreTestFilesystemType) GetFilesystem(ctx context.Context, vfsObj *VirtualFilesystem, creds *auth.Credentials, source string, opts GetFilesystemOptions) (*Filesystem, *Dentry, error) {
	fstype.fs.vfsfs.Init(vfsObj, fstype, fstype.fs)
	return &fstype.fs.vfsfs, newDentryTestDentry().dentry(), nil
}

func (saveRestoreTestFilesystemType) Name() string {
	return "saverestoretest"
}

func (saveRestoreTestFilesystemType) Release(ctx context.Context) {}

func TestPrepareSaveOptions(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}

	testFS := &saveRestoreTestFilesystem{}
	fsType := &saveRestoreTestFilesystemType{fs: testFS}
	vfsObj.MustRegisterFilesystemType("saverestoretest", fsType, &RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", "saverestoretest", &MountOptions{}, nil)
	if err != nil {
		t.Fatalf("failed to create mount namespace: %v", err)
	}
	defer mntns.DecRef(ctx)

	t.Run("DefaultOptionsWhenNil", func(t *testing.T) {
		testFS.prepareSaveCalled = false
		testFS.lastPrepareSaveOpts = PrepareSaveOptions{ValidateMetadata: true}
		if err := vfsObj.PrepareSave(ctx, nil); err != nil {
			t.Fatalf("PrepareSave(nil) failed: %v", err)
		}
		if !testFS.prepareSaveCalled {
			t.Fatalf("PrepareSave was not called")
		}
		if testFS.lastPrepareSaveOpts.ValidateMetadata {
			t.Errorf("got ValidateMetadata=true, want false")
		}
	})

	t.Run("ValidateMetadataFalse", func(t *testing.T) {
		testFS.prepareSaveCalled = false
		testFS.lastPrepareSaveOpts = PrepareSaveOptions{ValidateMetadata: true}
		if err := vfsObj.PrepareSave(ctx, &PrepareSaveOptions{ValidateMetadata: false}); err != nil {
			t.Fatalf("PrepareSave(ValidateMetadata: false) failed: %v", err)
		}
		if !testFS.prepareSaveCalled {
			t.Fatalf("PrepareSave was not called")
		}
		if testFS.lastPrepareSaveOpts.ValidateMetadata {
			t.Errorf("got ValidateMetadata=true, want false")
		}
	})

	t.Run("ValidateMetadataTrue", func(t *testing.T) {
		testFS.prepareSaveCalled = false
		testFS.lastPrepareSaveOpts = PrepareSaveOptions{ValidateMetadata: false}
		if err := vfsObj.PrepareSave(ctx, &PrepareSaveOptions{ValidateMetadata: true}); err != nil {
			t.Fatalf("PrepareSave(ValidateMetadata: true) failed: %v", err)
		}
		if !testFS.prepareSaveCalled {
			t.Fatalf("PrepareSave was not called")
		}
		if !testFS.lastPrepareSaveOpts.ValidateMetadata {
			t.Errorf("got ValidateMetadata=false, want true")
		}
	})
}
