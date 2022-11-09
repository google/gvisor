// Copyright 2022 The gVisor Authors.
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

package sys

import (
	"bytes"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// newNetDir returns a directory containing a subdirectory for each network
// interface.
func (fs *filesystem) newNetDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode) map[string]kernfs.Inode {
	// Get list of interfaces.
	stk := inet.StackFromContext(ctx)
	if stk == nil {
		return map[string]kernfs.Inode{}
	}

	subDirs := make(map[string]kernfs.Inode)
	for idx, iface := range stk.Interfaces() {
		subDirs[iface.Name] = fs.newIfaceDir(ctx, creds, mode, idx, stk)
	}
	return subDirs
}

// newIfaceDir returns a directory containing per-interface files.
func (fs *filesystem) newIfaceDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, idx int32, stk inet.Stack) kernfs.Inode {
	files := map[string]kernfs.Inode{
		"gro_flush_timeout": fs.newGROTimeoutFile(ctx, creds, mode, idx, stk),
	}
	return fs.newDir(ctx, creds, mode, files)
}

// groTimeoutFile enables the reading and writing of the GRO timeout.
//
// +stateify savable
type groTimeoutFile struct {
	implStatFS
	kernfs.DynamicBytesFile

	idx int32
	stk inet.Stack
}

// newGROTimeoutFile returns a file that can be used to read and set the GRO
// timeout.
func (fs *filesystem) newGROTimeoutFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, idx int32, stk inet.Stack) kernfs.Inode {
	file := groTimeoutFile{idx: idx, stk: stk}
	file.DynamicBytesFile.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), &file, mode)
	return &file
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (gf *groTimeoutFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	timeout, err := gf.stk.GROTimeout(gf.idx)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", timeout.Nanoseconds())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (gf *groTimeoutFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	val := []int32{0}
	nRead, err := usermem.CopyInt32StringsInVec(ctx, src.IO, src.Addrs, val, src.Opts)
	if err != nil {
		return 0, err
	}
	gf.stk.SetGROTimeout(gf.idx, time.Duration(val[0])*time.Nanosecond)
	return nRead, nil
}
