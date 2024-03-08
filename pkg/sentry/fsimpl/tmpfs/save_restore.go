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

package tmpfs

import (
	goContext "context"
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// saveMf is called by stateify.
func (fs *filesystem) saveMf() string {
	if !fs.mf.IsSavable() {
		panic(fmt.Sprintf("Can't save tmpfs filesystem because its MemoryFile is not savable: %v", fs.mf))
	}
	return fs.mf.RestoreID()
}

// loadMf is called by stateify.
func (fs *filesystem) loadMf(ctx goContext.Context, restoreID string) {
	if restoreID == "" {
		fs.mf = pgalloc.MemoryFileFromContext(ctx)
		return
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	if mfmap == nil {
		panic("CtxMemoryFileMap was not provided")
	}
	mf, ok := mfmap[restoreID]
	if !ok {
		panic(fmt.Sprintf("Memory file for %q not found in CtxMemoryFileMap", restoreID))
	}
	fs.mf = mf
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ goContext.Context, parent *dentry) {
	d.parent.Store(parent)
}

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	restoreID := fs.mf.RestoreID()
	if restoreID == "" {
		return nil
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	if mfmap == nil {
		return fmt.Errorf("CtxMemoryFileMap was not provided")
	}
	if _, ok := mfmap[restoreID]; ok {
		return fmt.Errorf("memory file for %q already exists in CtxMemoryFileMap", restoreID)
	}
	mfmap[restoreID] = fs.mf
	return nil
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	return nil
}
