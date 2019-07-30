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

package ext

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// namedPipe represents a named pipe inode. It is currently just a wrapper
// around pkg/sentry/kernel/pipe.
type namedPipe struct {
	inode inode

	p        *pipe.Pipe
	inodeOps fs.InodeOperations
}

// newNamedPipe is the namedPipe constructor.
func newNamedPipe(ctx context.Context, inode inode) *namedPipe {
	file := &namedPipe{inode: inode}
	file.inode.impl = file
	file.p = pipe.NewPipe(ctx, true /* isNamed */, pipe.DefaultPipeSize, usermem.PageSize)
	file.inodeOps = pipe.NewInodeOperations(ctx, fs.FilePermsFromMode(file.inode.diskInode.Mode()), file.p)
	return file
}
