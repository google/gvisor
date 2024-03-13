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
	"context"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/erofs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad(ctx context.Context) {
	fdmap := vfs.RestoreFilesystemFDMapFromContext(ctx)
	fd, ok := fdmap[fs.iopts.UniqueID]
	if !ok {
		panic(fmt.Sprintf("no image FD available for filesystem with unique ID %q", fs.iopts.UniqueID))
	}
	newImage, err := erofs.OpenImage(os.NewFile(uintptr(fd), "EROFS image file"))
	if err != nil {
		panic(fmt.Sprintf("erofs.OpenImage failed: %v", err))
	}
	if got, want := newImage.SuperBlock(), fs.image.SuperBlock(); got != want {
		panic(fmt.Sprintf("superblock mismatch detected on restore, got %+v, expected %+v", got, want))
	}
	// We need to update the image in place, as there are other pointers
	// pointing to this image as well.
	*fs.image = *newImage
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *dentry) loadParent(_ context.Context, parent *dentry) {
	d.parent.Store(parent)
}
