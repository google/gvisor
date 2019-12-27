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
	"io"
	"runtime"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

const defaultMode linux.FileMode = 01777
const staticFileContent = "This is sample content for a static test file."

// RootDentryFn is a generator function for creating the root dentry of a test
// filesystem. See newTestSystem.
type RootDentryFn func(*auth.Credentials, *filesystem) *kernfs.Dentry

// TestSystem represents the context for a single test.
type TestSystem struct {
	t     *testing.T
	ctx   context.Context
	creds *auth.Credentials
	vfs   *vfs.VirtualFilesystem
	mns   *vfs.MountNamespace
	root  vfs.VirtualDentry
}

// newTestSystem sets up a minimal environment for running a test, including an
// instance of a test filesystem. Tests can control the contents of the
// filesystem by providing an appropriate rootFn, which should return a
// pre-populated root dentry.
func newTestSystem(t *testing.T, rootFn RootDentryFn) *TestSystem {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	v := vfs.New()
	v.MustRegisterFilesystemType("testfs", &fsType{rootFn: rootFn}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mns, err := v.NewMountNamespace(ctx, creds, "", "testfs", &vfs.GetFilesystemOptions{})
	if err != nil {
		t.Fatalf("Failed to create testfs root mount: %v", err)
	}

	s := &TestSystem{
		t:     t,
		ctx:   ctx,
		creds: creds,
		vfs:   v,
		mns:   mns,
		root:  mns.Root(),
	}
	runtime.SetFinalizer(s, func(s *TestSystem) { s.root.DecRef() })
	return s
}

// PathOpAtRoot constructs a vfs.PathOperation for a path from the
// root of the test filesystem.
//
// Precondition: path should be relative path.
func (s *TestSystem) PathOpAtRoot(path string) vfs.PathOperation {
	return vfs.PathOperation{
		Root:  s.root,
		Start: s.root,
		Path:  fspath.Parse(path),
	}
}

// GetDentryOrDie attempts to resolve a dentry referred to by the
// provided path operation. If unsuccessful, the test fails.
func (s *TestSystem) GetDentryOrDie(pop vfs.PathOperation) vfs.VirtualDentry {
	vd, err := s.vfs.GetDentryAt(s.ctx, s.creds, &pop, &vfs.GetDentryOptions{})
	if err != nil {
		s.t.Fatalf("GetDentryAt(pop:%+v) failed: %v", pop, err)
	}
	return vd
}

func (s *TestSystem) ReadToEnd(fd *vfs.FileDescription) (string, error) {
	buf := make([]byte, usermem.PageSize)
	bufIOSeq := usermem.BytesIOSequence(buf)
	opts := vfs.ReadOptions{}

	var content bytes.Buffer
	for {
		n, err := fd.Impl().Read(s.ctx, bufIOSeq, opts)
		if n == 0 || err != nil {
			if err == io.EOF {
				err = nil
			}
			return content.String(), err
		}
		content.Write(buf[:n])
	}
}

type fsType struct {
	rootFn RootDentryFn
}

type filesystem struct {
	kernfs.Filesystem
}

type file struct {
	kernfs.DynamicBytesFile
	content string
}

func (fs *filesystem) newFile(creds *auth.Credentials, content string) *kernfs.Dentry {
	f := &file{}
	f.content = content
	f.DynamicBytesFile.Init(creds, fs.NextIno(), f, 0777)

	d := &kernfs.Dentry{}
	d.Init(f)
	return d
}

func (f *file) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%s", f.content)
	return nil
}

type attrs struct {
	kernfs.InodeAttrs
}

func (a *attrs) SetStat(fs *vfs.Filesystem, opt vfs.SetStatOptions) error {
	return syserror.EPERM
}

type readonlyDir struct {
	attrs
	kernfs.InodeNotSymlink
	kernfs.InodeNoDynamicLookup
	kernfs.InodeDirectoryNoNewChildren

	kernfs.OrderedChildren
	dentry kernfs.Dentry
}

func (fs *filesystem) newReadonlyDir(creds *auth.Credentials, mode linux.FileMode, contents map[string]*kernfs.Dentry) *kernfs.Dentry {
	dir := &readonlyDir{}
	dir.attrs.Init(creds, fs.NextIno(), linux.ModeDirectory|mode)
	dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	dir.dentry.Init(dir)

	dir.IncLinks(dir.OrderedChildren.Populate(&dir.dentry, contents))

	return &dir.dentry
}

func (d *readonlyDir) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &d.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

type dir struct {
	attrs
	kernfs.InodeNotSymlink
	kernfs.InodeNoDynamicLookup

	fs     *filesystem
	dentry kernfs.Dentry
	kernfs.OrderedChildren
}

func (fs *filesystem) newDir(creds *auth.Credentials, mode linux.FileMode, contents map[string]*kernfs.Dentry) *kernfs.Dentry {
	dir := &dir{}
	dir.fs = fs
	dir.attrs.Init(creds, fs.NextIno(), linux.ModeDirectory|mode)
	dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	dir.dentry.Init(dir)

	dir.IncLinks(dir.OrderedChildren.Populate(&dir.dentry, contents))

	return &dir.dentry
}

func (d *dir) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	fd := &kernfs.GenericDirectoryFD{}
	fd.Init(rp.Mount(), vfsd, &d.OrderedChildren, flags)
	return fd.VFSFileDescription(), nil
}

func (d *dir) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (*vfs.Dentry, error) {
	creds := auth.CredentialsFromContext(ctx)
	dir := d.fs.newDir(creds, opts.Mode, nil)
	dirVFSD := dir.VFSDentry()
	if err := d.OrderedChildren.Insert(name, dirVFSD); err != nil {
		dir.DecRef()
		return nil, err
	}
	d.IncLinks(1)
	return dirVFSD, nil
}

func (d *dir) NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (*vfs.Dentry, error) {
	creds := auth.CredentialsFromContext(ctx)
	f := d.fs.newFile(creds, "")
	fVFSD := f.VFSDentry()
	if err := d.OrderedChildren.Insert(name, fVFSD); err != nil {
		f.DecRef()
		return nil, err
	}
	return fVFSD, nil
}

func (*dir) NewLink(context.Context, string, kernfs.Inode) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

func (*dir) NewSymlink(context.Context, string, string) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

func (*dir) NewNode(context.Context, string, vfs.MknodOptions) (*vfs.Dentry, error) {
	return nil, syserror.EPERM
}

func (fst *fsType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opt vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fs := &filesystem{}
	fs.Init(vfsObj)
	root := fst.rootFn(creds, fs)
	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// -------------------- Remainder of the file are test cases --------------------

func TestBasic(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, map[string]*kernfs.Dentry{
			"file1": fs.newFile(creds, staticFileContent),
		})
	})
	sys.GetDentryOrDie(sys.PathOpAtRoot("file1")).DecRef()
}

func TestMkdirGetDentry(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, map[string]*kernfs.Dentry{
			"dir1": fs.newDir(creds, 0755, nil),
		})
	})

	pop := sys.PathOpAtRoot("dir1/a new directory")
	if err := sys.vfs.MkdirAt(sys.ctx, sys.creds, &pop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt for PathOperation %+v failed: %v", pop, err)
	}
	sys.GetDentryOrDie(pop).DecRef()
}

func TestReadStaticFile(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, map[string]*kernfs.Dentry{
			"file1": fs.newFile(creds, staticFileContent),
		})
	})

	pop := sys.PathOpAtRoot("file1")
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef()

	content, err := sys.ReadToEnd(fd)
	if err != nil {
		sys.t.Fatalf("Read failed: %v", err)
	}
	if diff := cmp.Diff(staticFileContent, content); diff != "" {
		sys.t.Fatalf("Read returned unexpected data:\n--- want\n+++ got\n%v", diff)
	}
}

func TestCreateNewFileInStaticDir(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, map[string]*kernfs.Dentry{
			"dir1": fs.newDir(creds, 0755, nil),
		})
	})

	pop := sys.PathOpAtRoot("dir1/newfile")
	opts := &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_EXCL, Mode: defaultMode}
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, opts)
	if err != nil {
		sys.t.Fatalf("OpenAt(pop:%+v, opts:%+v) failed: %v", pop, opts, err)
	}

	// Close the file. The file should persist.
	fd.DecRef()

	fd, err = sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt(pop:%+v) = %+v failed: %v", pop, fd, err)
	}
	fd.DecRef()
}

// direntCollector provides an implementation for vfs.IterDirentsCallback for
// testing. It simply iterates to the end of a given directory FD and collects
// all dirents emitted by the callback.
type direntCollector struct {
	mu      sync.Mutex
	dirents map[string]vfs.Dirent
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (d *direntCollector) Handle(dirent vfs.Dirent) bool {
	d.mu.Lock()
	if d.dirents == nil {
		d.dirents = make(map[string]vfs.Dirent)
	}
	d.dirents[dirent.Name] = dirent
	d.mu.Unlock()
	return true
}

// count returns the number of dirents currently in the collector.
func (d *direntCollector) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dirents)
}

// contains checks whether the collector has a dirent with the given name and
// type.
func (d *direntCollector) contains(name string, typ uint8) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dirent, ok := d.dirents[name]
	if !ok {
		return fmt.Errorf("No dirent named %q found", name)
	}
	if dirent.Type != typ {
		return fmt.Errorf("Dirent named %q found, but was expecting type %d, got: %+v", name, typ, dirent)
	}
	return nil
}

func TestDirFDReadWrite(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, nil)
	})

	pop := sys.PathOpAtRoot("/")
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef()

	// Read/Write should fail for directory FDs.
	if _, err := fd.Read(sys.ctx, usermem.BytesIOSequence([]byte{}), vfs.ReadOptions{}); err != syserror.EISDIR {
		sys.t.Fatalf("Read for directory FD failed with unexpected error: %v", err)
	}
	if _, err := fd.Write(sys.ctx, usermem.BytesIOSequence([]byte{}), vfs.WriteOptions{}); err != syserror.EISDIR {
		sys.t.Fatalf("Wrire for directory FD failed with unexpected error: %v", err)
	}
}

func TestDirFDIterDirents(t *testing.T) {
	sys := newTestSystem(t, func(creds *auth.Credentials, fs *filesystem) *kernfs.Dentry {
		return fs.newReadonlyDir(creds, 0755, map[string]*kernfs.Dentry{
			// Fill root with nodes backed by various inode implementations.
			"dir1": fs.newReadonlyDir(creds, 0755, nil),
			"dir2": fs.newDir(creds, 0755, map[string]*kernfs.Dentry{
				"dir3": fs.newDir(creds, 0755, nil),
			}),
			"file1": fs.newFile(creds, staticFileContent),
		})
	})

	pop := sys.PathOpAtRoot("/")
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef()

	collector := &direntCollector{}
	if err := fd.IterDirents(sys.ctx, collector); err != nil {
		sys.t.Fatalf("IterDirent failed: %v", err)
	}

	// Root directory should contain ".", ".." and 3 children:
	if collector.count() != 5 {
		sys.t.Fatalf("IterDirent returned too many dirents")
	}
	for _, dirName := range []string{".", "..", "dir1", "dir2"} {
		if err := collector.contains(dirName, linux.DT_DIR); err != nil {
			sys.t.Fatalf("IterDirent had unexpected results: %v", err)
		}
	}
	if err := collector.contains("file1", linux.DT_REG); err != nil {
		sys.t.Fatalf("IterDirent had unexpected results: %v", err)
	}

}
