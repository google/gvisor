// Copyright 2018 Google LLC
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

// Package test provides a simple ramfs-based filesystem for use in testing.
package test

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
)

// Dir is a simple ramfs.Dir that supports save/restore as-is.
type Dir struct {
	ramfs.Dir
}

// NewDir returns a simple ramfs directory with the passed contents.
func NewDir(ctx context.Context, contents map[string]*fs.Inode, perms fs.FilePermissions) *Dir {
	d := &Dir{}
	d.InitDir(ctx, contents, fs.RootOwner, perms)
	return d
}

// File is a simple ramfs.File that supports save/restore as-is.
type File struct {
	ramfs.File
}

// NewFile returns a simple ramfs File.
func NewFile(ctx context.Context, perms fs.FilePermissions) *File {
	f := &File{}
	f.InitFile(ctx, fs.RootOwner, perms)
	return f
}
