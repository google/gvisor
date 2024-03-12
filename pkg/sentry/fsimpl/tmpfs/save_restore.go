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

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(goContext.Context) {
	if !fs.privateMF {
		fs.mf = fs.mfp.MemoryFile()
	}
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
	if !fs.privateMF {
		return nil
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	if mfmap == nil {
		return fmt.Errorf("CtxMemoryFileMap was not provided")
	}
	if _, ok := mfmap[fs.uniqueID.String()]; ok {
		return fmt.Errorf("memory file for %q already exists in CtxMemoryFileMap", fs.uniqueID)
	}
	mfmap[fs.uniqueID.String()] = fs.mf
	return nil
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	if !fs.privateMF {
		return nil
	}
	mfmap := pgalloc.MemoryFileMapFromContext(ctx)
	if mfmap == nil {
		return fmt.Errorf("CtxMemoryFileMap was not provided")
	}
	mf, ok := mfmap[fs.uniqueID.String()]
	if !ok {
		return fmt.Errorf("memory file for %q not found in CtxMemoryFileMap", fs.uniqueID)
	}
	fs.mf = mf
	return nil
}
