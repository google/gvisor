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

package gofer

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

// +stateify savable
type fifo struct {
	fs.InodeOperations
	fileIops *inodeOperations
}

var _ fs.InodeOperations = (*fifo)(nil)

// Rename implements fs.InodeOperations. It forwards the call to the underlying
// file inode to handle the file rename. Note that file key remains the same
// after the rename to keep the endpoint mapping.
func (i *fifo) Rename(ctx context.Context, inode *fs.Inode, oldParent *fs.Inode, oldName string, newParent *fs.Inode, newName string, replacement bool) error {
	return i.fileIops.Rename(ctx, inode, oldParent, oldName, newParent, newName, replacement)
}

// StatFS implements fs.InodeOperations.
func (i *fifo) StatFS(ctx context.Context) (fs.Info, error) {
	return i.fileIops.StatFS(ctx)
}
