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

package memdirfs_test

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/memdirfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

const defaultMode linux.FileMode = 01777

type fsContentFunc = func(fs *testFS, creds *auth.Credentials) map[string]*memdirfs.Dentry

// All tests in this file use a test-only filesystem based on
// memdirfs, implemented below by the following types:
//
// - testFSType
// - testFS
// - testFSDentry
// - testFSStaticFileInode
// - testFSDynamicDirInode

// testFSType implements vfs.FilesystemType.
type testFSType struct {
	// Callback to generate the contents of the test filesystem. This
	// is callback rather than a tree of dentries because the dentries
	// need to be constructed with ownership specified at runtime via
	// auth.Credentials.
	generateRoot fsContentFunc
}

// NewFilesystem implements vfs.FilesystemType.NewFilesystem.
func (tfs *testFSType) NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts vfs.NewFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	fs := &testFS{}
	fs.Init(memdirfs.NewFilesystemOptions{
		BlkSize: 1,
		NewEmptyFileInodeImpl: func() memdirfs.InodeImpl {
			return newTestFSStaticFileInode("")
		},
	})
	root := fs.NewDirectory(creds, defaultMode, tfs.generateRoot(fs, creds))
	return fs.VFSFilesystem(), root.VFSDentry(), nil
}

// testFS represents an instance of the test filesystem.
type testFS struct {
	memdirfs.Filesystem
}

// testFSDentry implements vfs.DentryImpl.
type testFSDentry struct {
	memdirfs.Dentry
}

// testFSStaticFileInode represents a regular read-only file with
// static content. It implements memdirfs.InodeImpl (via
// DynamicBytesFileDefaultInodeImpl) and vfs.DynamicBytesSource.
type testFSStaticFileInode struct {
	memdirfs.DynamicBytesFileDefaultInodeImpl
	content string
}

func newTestFSStaticFileInode(content string) *testFSStaticFileInode {
	f := &testFSStaticFileInode{
		content: content,
	}
	f.Init(f)
	return f
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (i *testFSStaticFileInode) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%s", i.content)
	return nil
}

// testFSDynamicDirInode represents a directory on the test filesystem
// whose contents are dynamically created on each path resolution. It
// implements memdirfs.InodeImpl.
type testFSDynamicDirInode struct {
	memdirfs.Directory

	// Set of names to return an empty file for.
	fileSet map[string]struct{}
	// Set of names to return an empty dir for.
	dirSet map[string]struct{}
}

func newTestFSDynamicDirInode(fs *testFS, creds *auth.Credentials, mode linux.FileMode, files, dirs []string) *memdirfs.Inode {
	fileSet := make(map[string]struct{})
	dirSet := make(map[string]struct{})
	for _, f := range files {
		fileSet[f] = struct{}{}
	}
	for _, d := range dirs {
		dirSet[d] = struct{}{}
	}

	return fs.NewInode(memdirfs.InodeOpts{Creds: creds, Mode: mode, Dir: true, Impl: &testFSDynamicDirInode{
		fileSet: fileSet,
		dirSet:  dirSet,
	}})
}

// DynamicLookup overrides memdirfs.InodeImpl.DynamicLookup from d.Directory.
func (d *testFSDynamicDirInode) DynamicLookup(rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	name := rp.Component()
	fs := rp.Mount().Filesystem().Impl().(*memdirfs.Filesystem)

	if _, ok := d.fileSet[name]; ok {
		file := fs.NewInode(memdirfs.InodeOpts{Creds: rp.Credentials(), Mode: defaultMode, Impl: fs.NewEmptyFileInodeImpl()}).NewDentry()
		return file.VFSDentry(), nil
	}
	if _, ok := d.dirSet[name]; ok {
		dir := fs.NewDirectory(rp.Credentials(), defaultMode, nil)
		return dir.VFSDentry(), nil
	}

	return nil, syserror.ENOENT
}

const staticFile1Content = "This is the content for static file #1."

// fsContent generates a tree of nodes representing the contents of a
// test filesystem. The resulting filesystem looks like this:
//
// / (root directory)
//   /staticFile1 (contains staticFile1Content)
//   /staticDir1 (empty static directory)
//   /dynDir1 (dynamic directory)
//     /dynDir1/file1 (empty file)
//     /dynDir1/file2 (empty file)
//     /dynDir1/dir1  (empty directory)
//     /dynDir1/dir2  (empty directory)
func fsContent(fs *testFS, creds *auth.Credentials) map[string]*memdirfs.Dentry {
	return map[string]*memdirfs.Dentry{
		"staticFile1": fs.NewInode(memdirfs.InodeOpts{
			Creds: creds,
			Mode:  defaultMode,
			Impl:  newTestFSStaticFileInode(staticFile1Content),
		}).NewDentry(),
		"staticDir1": fs.NewDirectory(creds, defaultMode, nil),
		"dynDir1":    newTestFSDynamicDirInode(fs, creds, defaultMode, []string{"dynDir1File1", "dynDir1File2"}, []string{"dynDir1Dir1", "dynDir1Dir2"}).NewDentry(),
	}
}

// TestSystem represents the context for a single test.
type TestSystem struct {
	t     *testing.T
	ctx   context.Context
	creds *auth.Credentials
	vfs   *vfs.VirtualFilesystem
	mns   *vfs.MountNamespace
	root  vfs.VirtualDentry
}

func newTestSystem(t *testing.T, generateRoot fsContentFunc) *TestSystem {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	v := vfs.New()
	v.MustRegisterFilesystemType("testfs", &testFSType{generateRoot: generateRoot})
	mns, err := v.NewMountNamespace(ctx, creds, "", "testfs", &vfs.NewFilesystemOptions{})
	if err != nil {
		t.Fatalf("Failed to create testfs root mount: %v", err)
	}

	s := &TestSystem{
		t:     t,
		ctx:   ctx,
		creds: creds,
		vfs:   v,
		mns:   mns,
		root:  mns.Root(), // Ref dropped in s.destroy.
	}
	runtime.SetFinalizer(s, func(s *TestSystem) { s.destroy() })
	return s
}

func (s *TestSystem) destroy() {
	s.root.DecRef()
}

// PathOpAtRoot constructs a vfs.PathOperation for a path from the
// root of the test filesystem.
//
// Precondition: path should be relative path.
func (s *TestSystem) PathOpAtRoot(path string) vfs.PathOperation {
	return vfs.PathOperation{
		Root:     s.root,
		Start:    s.root,
		Pathname: path,
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

// -------------------- Remainer of the file are test cases --------------------

func TestGetFileInitializedByFS(t *testing.T) {
	sys := newTestSystem(t, fsContent)
	sys.GetDentryOrDie(sys.PathOpAtRoot("staticFile1")).DecRef()
}

func TestMkdirGetDentry(t *testing.T) {
	sys := newTestSystem(t, fsContent)
	name := "a new directory"
	p := sys.PathOpAtRoot(name)

	if err := sys.vfs.MkdirAt(sys.ctx, sys.creds, &p, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt for dir %q failed: %v", name, err)
	}
	sys.GetDentryOrDie(p).DecRef()
}

func TestReadFile(t *testing.T) {
	sys := newTestSystem(t, fsContent)

	pop := sys.PathOpAtRoot("staticFile1")
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef()

	buf := make([]byte, usermem.PageSize)
	n, err := fd.Impl().Read(sys.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil {
		sys.t.Fatalf("Read failed: %v", err)
	}
	if diff := cmp.Diff([]byte(staticFile1Content), buf[:n]); diff != "" {
		sys.t.Fatalf("Read returned unexpected data:\n--- want\n+++ got\n%v", diff)
	}
}

func TestGetFileInDynDir(t *testing.T) {
	sys := newTestSystem(t, fsContent)
	sys.GetDentryOrDie(sys.PathOpAtRoot("dynDir1/dynDir1File1")).DecRef()
	sys.GetDentryOrDie(sys.PathOpAtRoot("dynDir1/dynDir1File2")).DecRef()
	sys.GetDentryOrDie(sys.PathOpAtRoot("dynDir1/dynDir1Dir1")).DecRef()
	sys.GetDentryOrDie(sys.PathOpAtRoot("dynDir1/dynDir1Dir2")).DecRef()

	// Try find something that we don't expect to exist in the dynamic directory.
	pop := sys.PathOpAtRoot(fmt.Sprintf("dynDir1/this entry doesn't exist"))
	d, err := sys.vfs.GetDentryAt(sys.ctx, sys.creds, &pop, &vfs.GetDentryOptions{})
	if err != syserror.ENOENT {
		sys.t.Fatalf("Didn't expect to find node at %+v, but found %+v (with err = %v)", pop, d, err)
	}

}

func TestCreateNewFileInDynamicDir(t *testing.T) {
	sys := newTestSystem(t, fsContent)

	pop := sys.PathOpAtRoot("dynDir1/dynDir1Dir1/newfile")
	opts := &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_EXCL}
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, opts)
	if err != nil {
		sys.t.Fatalf("OpenAt(pop:%+v, opts:%+v) failed: %v", pop, opts, err)
	}

	// Close the file. This should remove the child since it was
	// created under a dynamic directory, which is not persisted.
	fd.DecRef()

	// Try lookup the file again. It shouldn't exist this time.
	fd, err = sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != syserror.ENOENT {
		sys.t.Fatalf("Didn't expect to find node at %+v, but found %+v (with err = %v)", pop, fd, err)
	}
}

func TestCreateNewFileInStaticDir(t *testing.T) {
	sys := newTestSystem(t, fsContent)

	pop := sys.PathOpAtRoot("staticDir1/newfile")
	opts := &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_EXCL, Mode: defaultMode}
	fd, err := sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, opts)
	if err != nil {
		sys.t.Fatalf("OpenAt(pop:%+v, opts:%+v) fails: %v", pop, opts, err)
	}

	// Close the file. The file should persist.
	fd.DecRef()
	fd, err = sys.vfs.OpenAt(sys.ctx, sys.creds, &pop, &vfs.OpenOptions{})
	if err != nil {
		sys.t.Fatalf("OpenAt(pop:%+v) = %+v failed: %v", pop, fd, err)
	}
	fd.DecRef()
}
