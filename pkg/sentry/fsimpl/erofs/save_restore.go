// Copyright 2023 The gVisor Authors.
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
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Compile-time assertion that filesystem implements vfs.FilesystemImplSaveRestoreExtension.
var _ = vfs.FilesystemImplSaveRestoreExtension((*filesystem)(nil))

// PreprareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error {
	return nil
}

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	fdmapv := ctx.Value(vfs.CtxRestoreFilesystemFDMap)
	if fdmapv == nil {
		return fmt.Errorf("no image FD map available")
	}
	fdmap := fdmapv.(map[string]int)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		return fmt.Errorf("no image FD available for filesystem with unique ID %q", fs.iopts.UniqueID)
	}
	newImage, err := erofs.OpenImage(os.NewFile(uintptr(fd), "EROFS image file"))
	if err != nil {
		return err
	}
	if got, want := newImage.SuperBlock(), fs.image.SuperBlock(); got != want {
		return fmt.Errorf("superblock mismatch detected on restore, got %+v, expected %+v", got, want)
	}
	fs.image = newImage
	return nil
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(parent *dentry) {
	d.parent.Store(parent)
}
