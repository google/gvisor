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

package kernfs_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const defaultMode linux.FileMode = 01777
const staticFileContent = "This is sample content for a static test file."

// RootDentryFn is a generator function for creating the root dentry of a test
// filesystem. See newTestSystem.
type RootDentryFn func(context.Context, *auth.Credentials, *filesystem) kernfs.Inode

// newTestSystem sets up a minimal environment for running a test, including an
// instance of a test filesystem. Tests can control the contents of the
// filesystem by providing an appropriate rootFn, which should return a
// pre-populated root dentry.
func newTestSystem(t *testing.T, rootFn RootDentryFn) *testutil.System {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	v := &vfs.VirtualFilesystem{}
	if err := v.Init(ctx); err != nil {
		t.Fatalf("VFS init: %v", err)
	}
	v.MustRegisterFilesystemType("testfs", &fsType{rootFn: rootFn}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mns, err := v.NewMountNamespace(ctx, creds, "", "testfs", &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("Failed to create testfs root mount: %v", err)
	}
	return testutil.NewSystem(ctx, t, v, mns)
}

type fsType struct {
	rootFn RootDentryFn
}

type filesystem struct {
	kernfs.Filesystem
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

type file struct {
	kernfs.DynamicBytesFile
	content string
}

func (fs *filesystem) newFile(ctx context.Context, creds *auth.Credentials, content string) kernfs.Inode {
	f := &file{}
	f.content = content
	f.DynamicBytesFile.Init(ctx, creds, 0 /* devMajor */, 0 /* devMinor */, fs.NextIno(), f, 0777)
	return f
}

func (f *file) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%s", f.content)
	return nil
}

type attrs struct {
	kernfs.InodeAttrs
}

func (*attrs) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

type readonlyDir struct {
	readonlyDirRefs
	attrs
	kernfs.InodeAlwaysValid
	kernfs.InodeDirectoryNoNewChildren
	kernfs.InodeNoStatFS
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary
	kernfs.OrderedChildren

	locks vfs.FileLocks
}

func (fs *filesystem) newReadonlyDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, contents map[string]kernfs.Inode) kernfs.Inode {
	dir := &readonlyDir{}
	dir.attrs.Init(ctx, creds, 0 /* devMajor */, 0 /* devMinor */, fs.NextIno(), linux.ModeDirectory|mode)
	dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	dir.InitRefs()
	dir.IncLinks(dir.OrderedChildren.Populate(contents))
	return dir
}

func (d *readonlyDir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, &d.OrderedChildren, &d.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

func (d *readonlyDir) DecRef(ctx context.Context) {
	d.readonlyDirRefs.DecRef(func() { d.Destroy(ctx) })
}

type dir struct {
	dirRefs
	attrs
	kernfs.InodeAlwaysValid
	kernfs.InodeNotSymlink
	kernfs.InodeNoStatFS
	kernfs.InodeTemporary
	kernfs.OrderedChildren

	locks vfs.FileLocks

	fs *filesystem
}

func (fs *filesystem) newDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, contents map[string]kernfs.Inode) kernfs.Inode {
	dir := &dir{}
	dir.fs = fs
	dir.attrs.Init(ctx, creds, 0 /* devMajor */, 0 /* devMinor */, fs.NextIno(), linux.ModeDirectory|mode)
	dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	dir.InitRefs()

	dir.IncLinks(dir.OrderedChildren.Populate(contents))
	return dir
}

func (d *dir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, &d.OrderedChildren, &d.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

func (d *dir) DecRef(ctx context.Context) {
	d.dirRefs.DecRef(func() { d.Destroy(ctx) })
}

func (d *dir) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	creds := auth.CredentialsFromContext(ctx)
	dir := d.fs.newDir(ctx, creds, opts.Mode, nil)
	if err := d.OrderedChildren.Insert(name, dir); err != nil {
		dir.DecRef(ctx)
		return nil, err
	}
	d.TouchCMtime(ctx)
	d.IncLinks(1)
	return dir, nil
}

func (d *dir) NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (kernfs.Inode, error) {
	creds := auth.CredentialsFromContext(ctx)
	f := d.fs.newFile(ctx, creds, "")
	if err := d.OrderedChildren.Insert(name, f); err != nil {
		f.DecRef(ctx)
		return nil, err
	}
	d.TouchCMtime(ctx)
	return f, nil
}

func (*dir) NewLink(context.Context, string, kernfs.Inode) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

func (*dir) NewSymlink(context.Context, string, string) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

func (*dir) NewNode(context.Context, string, vfs.MknodOptions) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

func (fsType) Name() string {
	return "kernfs"
}

func (fsType) Release(ctx context.Context) {}

func (fst fsType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opt vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fs := &filesystem{}
	fs.VFSFilesystem().Init(vfsObj, &fst, fs)
	root := fst.rootFn(ctx, creds, fs)
	var d kernfs.Dentry
	d.Init(&fs.Filesystem, root)
	return fs.VFSFilesystem(), d.VFSDentry(), nil
}

// -------------------- Remainder of the file are test cases --------------------

func TestBasic(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, map[string]kernfs.Inode{
			"file1": fs.newFile(ctx, creds, staticFileContent),
		})
	})
	defer sys.Destroy()
	sys.GetDentryOrDie(sys.PathOpAtRoot("file1")).DecRef(sys.Ctx)
}

func TestMkdirGetDentry(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, map[string]kernfs.Inode{
			"dir1": fs.newDir(ctx, creds, 0755, nil),
		})
	})
	defer sys.Destroy()

	pop := sys.PathOpAtRoot("dir1/a new directory")
	if err := sys.VFS.MkdirAt(sys.Ctx, sys.Creds, pop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt for PathOperation %+v failed: %v", pop, err)
	}
	sys.GetDentryOrDie(pop).DecRef(sys.Ctx)
}

func TestReadStaticFile(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, map[string]kernfs.Inode{
			"file1": fs.newFile(ctx, creds, staticFileContent),
		})
	})
	defer sys.Destroy()

	pop := sys.PathOpAtRoot("file1")
	fd, err := sys.VFS.OpenAt(sys.Ctx, sys.Creds, pop, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef(sys.Ctx)

	content, err := sys.ReadToEnd(fd)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if diff := cmp.Diff(staticFileContent, content); diff != "" {
		t.Fatalf("Read returned unexpected data:\n--- want\n+++ got\n%v", diff)
	}
}

func TestCreateNewFileInStaticDir(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, map[string]kernfs.Inode{
			"dir1": fs.newDir(ctx, creds, 0755, nil),
		})
	})
	defer sys.Destroy()

	pop := sys.PathOpAtRoot("dir1/newfile")
	opts := &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_EXCL, Mode: defaultMode}
	fd, err := sys.VFS.OpenAt(sys.Ctx, sys.Creds, pop, opts)
	if err != nil {
		t.Fatalf("OpenAt(pop:%+v, opts:%+v) failed: %v", pop, opts, err)
	}

	// Close the file. The file should persist.
	fd.DecRef(sys.Ctx)

	fd, err = sys.VFS.OpenAt(sys.Ctx, sys.Creds, pop, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		t.Fatalf("OpenAt(pop:%+v) = %+v failed: %v", pop, fd, err)
	}
	fd.DecRef(sys.Ctx)
}

func TestDirFDReadWrite(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, nil)
	})
	defer sys.Destroy()

	pop := sys.PathOpAtRoot("/")
	fd, err := sys.VFS.OpenAt(sys.Ctx, sys.Creds, pop, &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	})
	if err != nil {
		t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef(sys.Ctx)

	// Read/Write should fail for directory FDs.
	if _, err := fd.Read(sys.Ctx, usermem.BytesIOSequence([]byte{}), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.EISDIR, err) {
		t.Fatalf("Read for directory FD failed with unexpected error: %v", err)
	}
	if _, err := fd.Write(sys.Ctx, usermem.BytesIOSequence([]byte{}), vfs.WriteOptions{}); !linuxerr.Equals(linuxerr.EBADF, err) {
		t.Fatalf("Write for directory FD failed with unexpected error: %v", err)
	}
}

func TestDirFDIterDirents(t *testing.T) {
	sys := newTestSystem(t, func(ctx context.Context, creds *auth.Credentials, fs *filesystem) kernfs.Inode {
		return fs.newReadonlyDir(ctx, creds, 0755, map[string]kernfs.Inode{
			// Fill root with nodes backed by various inode implementations.
			"dir1": fs.newReadonlyDir(ctx, creds, 0755, nil),
			"dir2": fs.newDir(ctx, creds, 0755, map[string]kernfs.Inode{
				"dir3": fs.newDir(ctx, creds, 0755, nil),
			}),
			"file1": fs.newFile(ctx, creds, staticFileContent),
		})
	})
	defer sys.Destroy()

	pop := sys.PathOpAtRoot("/")
	sys.AssertAllDirentTypes(sys.ListDirents(pop), map[string]testutil.DirentType{
		"dir1":  linux.DT_DIR,
		"dir2":  linux.DT_DIR,
		"file1": linux.DT_REG,
	})
}
