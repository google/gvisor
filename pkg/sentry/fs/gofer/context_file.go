// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/fd"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
)

// contextFile is a wrapper around p9.File that notifies the context that
// it's about to sleep before calling the Gofer over P9.
type contextFile struct {
	file p9.File
}

func (c *contextFile) walk(ctx context.Context, names []string) ([]p9.QID, contextFile, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	q, f, err := c.file.Walk(names)
	if err != nil {
		return nil, contextFile{}, err
	}
	return q, contextFile{file: f}, nil
}

func (c *contextFile) statFS(ctx context.Context) (p9.FSStat, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.StatFS()
}

func (c *contextFile) getAttr(ctx context.Context, req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.GetAttr(req)
}

func (c *contextFile) setAttr(ctx context.Context, valid p9.SetAttrMask, attr p9.SetAttr) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.SetAttr(valid, attr)
}

func (c *contextFile) remove(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Remove()
}

func (c *contextFile) rename(ctx context.Context, directory contextFile, name string) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Rename(directory.file, name)
}

func (c *contextFile) close(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Close()
}

func (c *contextFile) open(ctx context.Context, mode p9.OpenFlags) (*fd.FD, p9.QID, uint32, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Open(mode)
}

func (c *contextFile) readAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.ReadAt(p, offset)
}

func (c *contextFile) writeAt(ctx context.Context, p []byte, offset uint64) (int, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.WriteAt(p, offset)
}

func (c *contextFile) fsync(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.FSync()
}

func (c *contextFile) create(ctx context.Context, name string, flags p9.OpenFlags, permissions p9.FileMode, uid p9.UID, gid p9.GID) (*fd.FD, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	fd, _, _, _, err := c.file.Create(name, flags, permissions, uid, gid)
	return fd, err
}

func (c *contextFile) mkdir(ctx context.Context, name string, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Mkdir(name, permissions, uid, gid)
}

func (c *contextFile) symlink(ctx context.Context, oldName string, newName string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Symlink(oldName, newName, uid, gid)
}

func (c *contextFile) link(ctx context.Context, target *contextFile, newName string) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Link(target.file, newName)
}

func (c *contextFile) mknod(ctx context.Context, name string, permissions p9.FileMode, major uint32, minor uint32, uid p9.UID, gid p9.GID) (p9.QID, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Mknod(name, permissions, major, minor, uid, gid)
}

func (c *contextFile) unlinkAt(ctx context.Context, name string, flags uint32) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.UnlinkAt(name, flags)
}

func (c *contextFile) readdir(ctx context.Context, offset uint64, count uint32) ([]p9.Dirent, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Readdir(offset, count)
}

func (c *contextFile) readlink(ctx context.Context) (string, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Readlink()
}

func (c *contextFile) flush(ctx context.Context) error {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Flush()
}

func (c *contextFile) walkGetAttr(ctx context.Context, names []string) ([]p9.QID, contextFile, p9.AttrMask, p9.Attr, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	q, f, m, a, err := c.file.WalkGetAttr(names)
	if err != nil {
		return nil, contextFile{}, p9.AttrMask{}, p9.Attr{}, err
	}
	return q, contextFile{file: f}, m, a, nil
}

func (c *contextFile) connect(ctx context.Context, flags p9.ConnectFlags) (*fd.FD, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	return c.file.Connect(flags)
}
