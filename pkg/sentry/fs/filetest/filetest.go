// Copyright 2018 The gVisor Authors.
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

// Package filetest provides a test implementation of an fs.File.
package filetest

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/anon"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TestFileOperations is an implementation of the File interface. It provides all
// required methods.
type TestFileOperations struct {
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

// NewTestFile creates and initializes a new test file.
func NewTestFile(tb testing.TB) *fs.File {
	ctx := contexttest.Context(tb)
	dirent := fs.NewDirent(ctx, anon.NewInode(ctx), "test")
	return fs.NewFile(ctx, dirent, fs.FileFlags{}, &TestFileOperations{})
}

// Read just fails the request.
func (*TestFileOperations) Read(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, fmt.Errorf("Readv not implemented")
}

// Write just fails the request.
func (*TestFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, fmt.Errorf("Writev not implemented")
}
