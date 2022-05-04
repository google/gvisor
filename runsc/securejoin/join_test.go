// Copyright (C) 2017 SUSE LLC. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package securejoin

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TODO: These tests won't work on plan9 because it doesn't have symlinks, and
//       also we use '/' here explicitly which probably won't work on Windows.

func symlink(t *testing.T, oldname, newname string) {
	if err := os.Symlink(oldname, newname); err != nil {
		t.Fatal(err)
	}
}

// Test basic handling of symlink expansion.
func TestSymlink(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSymlink")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	symlink(t, "somepath", filepath.Join(dir, "etc"))
	symlink(t, "../../../../../../../../../../../../../etc", filepath.Join(dir, "etclink"))
	symlink(t, "/../../../../../../../../../../../../../etc/passwd", filepath.Join(dir, "passwd"))

	for _, test := range []struct {
		root, unsafe string
		expected     string
	}{
		// Make sure that expansion with a root of '/' proceeds in the expected fashion.
		{"/", filepath.Join(dir, "passwd"), "/etc/passwd"},
		{"/", filepath.Join(dir, "etclink"), "/etc"},
		{"/", filepath.Join(dir, "etc"), filepath.Join(dir, "somepath")},
		// Now test scoped expansion.
		{dir, "passwd", filepath.Join(dir, "somepath", "passwd")},
		{dir, "etclink", filepath.Join(dir, "somepath")},
		{dir, "etc", filepath.Join(dir, "somepath")},
		{dir, "etc/test", filepath.Join(dir, "somepath", "test")},
		{dir, "etc/test/..", filepath.Join(dir, "somepath")},
	} {
		got, err := SecureJoin(test.root, test.unsafe)
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
			continue
		}
		// This is only for OS X, where /etc is a symlink to /private/etc. In
		// principle, SecureJoin(/, pth) is the same as EvalSymlinks(pth) in
		// the case where the path exists.
		if test.root == "/" {
			if expected, err := filepath.EvalSymlinks(test.expected); err == nil {
				test.expected = expected
			}
		}
		if got != test.expected {
			t.Errorf("securejoin(%q, %q): expected %q, got %q", test.root, test.unsafe, test.expected, got)
			continue
		}
	}
}

// In a path without symlinks, SecureJoin is equivalent to Clean+Join.
func TestNoSymlink(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestNoSymlink")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	for _, test := range []struct {
		root, unsafe string
	}{
		// TODO: Do we need to have some conditional FromSlash handling here?
		{dir, "somepath"},
		{dir, "even/more/path"},
		{dir, "/this/is/a/path"},
		{dir, "also/a/../path/././/with/some/./.././junk"},
		{dir, "yetanother/../path/././/with/some/./.././junk../../../../../../../../../../../../etc/passwd"},
		{dir, "/../../../../../../../../../../../../../../../../etc/passwd"},
		{dir, "../../../../../../../../../../../../../../../../somedir"},
		{dir, "../../../../../../../../../../../../../../../../"},
		{dir, "./../../.././././../../../../../../../../../../../../../../../../etc passwd"},
	} {
		expected := filepath.Join(test.root, filepath.Clean(string(filepath.Separator)+test.unsafe))
		got, err := SecureJoin(test.root, test.unsafe)
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
			continue
		}
		if got != expected {
			t.Errorf("securejoin(%q, %q): expected %q, got %q", test.root, test.unsafe, expected, got)
			continue
		}
	}
}

// Make sure that .. is **not** expanded lexically.
func TestNonLexical(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestNonLexical")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.MkdirAll(filepath.Join(dir, "cousinparent", "cousin"), 0755)
	symlink(t, "../cousinparent/cousin", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/../cousinparent/cousin", filepath.Join(dir, "subdir", "link2"))
	symlink(t, "/../../../../../../../../../../../../../../../../cousinparent/cousin", filepath.Join(dir, "subdir", "link3"))

	for _, test := range []struct {
		root, unsafe string
		expected     string
	}{
		{dir, "subdir", filepath.Join(dir, "subdir")},
		{dir, "subdir/link/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link2/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link3/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/../test", filepath.Join(dir, "test")},
		// This is the divergence from a simple filepath.Clean implementation.
		{dir, "subdir/link/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link2/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link3/../test", filepath.Join(dir, "cousinparent", "test")},
	} {
		got, err := SecureJoin(test.root, test.unsafe)
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
			continue
		}
		if got != test.expected {
			t.Errorf("securejoin(%q, %q): expected %q, got %q", test.root, test.unsafe, test.expected, got)
			continue
		}
	}
}

// Make sure that symlink loops result in errors.
func TestSymlinkLoop(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSymlinkLoop")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	symlink(t, "../../../../../../../../../../../../../../../../path", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/subdir/link", filepath.Join(dir, "path"))
	symlink(t, "/../../../../../../../../../../../../../../../../self", filepath.Join(dir, "self"))

	for _, test := range []struct {
		root, unsafe string
	}{
		{dir, "subdir/link"},
		{dir, "path"},
		{dir, "../../path"},
		{dir, "subdir/link/../.."},
		{dir, "../../../../../../../../../../../../../../../../subdir/link/../../../../../../../../../../../../../../../.."},
		{dir, "self"},
		{dir, "self/.."},
		{dir, "/../../../../../../../../../../../../../../../../self/.."},
		{dir, "/self/././.."},
	} {
		got, err := SecureJoin(test.root, test.unsafe)
		if !errors.Is(err, syscall.ELOOP) {
			t.Errorf("securejoin(%q, %q): expected ELOOP, got %v & %q", test.root, test.unsafe, err, got)
			continue
		}
	}
}

// Make sure that ENOTDIR is correctly handled.
func TestEnotdir(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestEnotdir")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	ioutil.WriteFile(filepath.Join(dir, "notdir"), []byte("I am not a directory!"), 0755)
	symlink(t, "/../../../notdir/somechild", filepath.Join(dir, "subdir", "link"))

	for _, test := range []struct {
		root, unsafe string
	}{
		{dir, "subdir/link"},
		{dir, "notdir"},
		{dir, "notdir/child"},
	} {
		_, err := SecureJoin(test.root, test.unsafe)
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
			continue
		}
	}
}

// Some silly tests to make sure that all error types are correctly handled.
func TestIsNotExist(t *testing.T) {
	for _, test := range []struct {
		err      error
		expected bool
	}{
		{&os.PathError{Op: "test1", Err: syscall.ENOENT}, true},
		{&os.LinkError{Op: "test1", Err: syscall.ENOENT}, true},
		{&os.SyscallError{Syscall: "test1", Err: syscall.ENOENT}, true},
		{&os.PathError{Op: "test2", Err: syscall.ENOTDIR}, true},
		{&os.LinkError{Op: "test2", Err: syscall.ENOTDIR}, true},
		{&os.SyscallError{Syscall: "test2", Err: syscall.ENOTDIR}, true},
		{&os.PathError{Op: "test3", Err: syscall.EACCES}, false},
		{&os.LinkError{Op: "test3", Err: syscall.EACCES}, false},
		{&os.SyscallError{Syscall: "test3", Err: syscall.EACCES}, false},
		{errors.New("not a proper error"), false},
	} {
		got := IsNotExist(test.err)
		if got != test.expected {
			t.Errorf("IsNotExist(%#v): expected %v, got %v", test.err, test.expected, got)
		}
	}
}

type mockVFS struct {
	lstat    func(path string) (os.FileInfo, error)
	readlink func(path string) (string, error)
}

func (m mockVFS) Lstat(path string) (os.FileInfo, error) { return m.lstat(path) }
func (m mockVFS) Readlink(path string) (string, error)   { return m.readlink(path) }

// Make sure that SecureJoinVFS actually does use the given VFS interface.
func TestSecureJoinVFS(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestNonLexical")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.MkdirAll(filepath.Join(dir, "cousinparent", "cousin"), 0755)
	symlink(t, "../cousinparent/cousin", filepath.Join(dir, "subdir", "link"))
	symlink(t, "/../cousinparent/cousin", filepath.Join(dir, "subdir", "link2"))
	symlink(t, "/../../../../../../../../../../../../../../../../cousinparent/cousin", filepath.Join(dir, "subdir", "link3"))

	for _, test := range []struct {
		root, unsafe string
		expected     string
	}{
		{dir, "subdir", filepath.Join(dir, "subdir")},
		{dir, "subdir/link/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link2/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/link3/test", filepath.Join(dir, "cousinparent", "cousin", "test")},
		{dir, "subdir/../test", filepath.Join(dir, "test")},
		// This is the divergence from a simple filepath.Clean implementation.
		{dir, "subdir/link/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link2/../test", filepath.Join(dir, "cousinparent", "test")},
		{dir, "subdir/link3/../test", filepath.Join(dir, "cousinparent", "test")},
	} {
		var nLstat, nReadlink int
		mock := mockVFS{
			lstat:    func(path string) (os.FileInfo, error) { nLstat++; return os.Lstat(path) },
			readlink: func(path string) (string, error) { nReadlink++; return os.Readlink(path) },
		}

		got, err := SecureJoinVFS(test.root, test.unsafe, mock)
		if err != nil {
			t.Errorf("securejoin(%q, %q): unexpected error: %v", test.root, test.unsafe, err)
			continue
		}
		if got != test.expected {
			t.Errorf("securejoin(%q, %q): expected %q, got %q", test.root, test.unsafe, test.expected, got)
			continue
		}
		if nLstat == 0 && nReadlink == 0 {
			t.Errorf("securejoin(%q, %q): expected to use either lstat or readlink, neither were used", test.root, test.unsafe)
		}
	}
}

// Make sure that SecureJoinVFS actually does use the given VFS interface, and
// that errors are correctly propagated.
func TestSecureJoinVFSErrors(t *testing.T) {
	var (
		lstatErr    = errors.New("lstat error")
		readlinkErr = errors.New("readlink err")
	)

	// Set up directory.
	dir, err := ioutil.TempDir("", "TestSecureJoinVFSErrors")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// Make a link.
	symlink(t, "../../../../../../../../../../../../../../../../path", filepath.Join(dir, "link"))

	// Define some fake mock functions.
	lstatFailFn := func(path string) (os.FileInfo, error) { return nil, lstatErr }
	readlinkFailFn := func(path string) (string, error) { return "", readlinkErr }

	// Make sure that the set of {lstat, readlink} failures do propagate.
	for idx, test := range []struct {
		vfs      VFS
		expected []error
	}{
		{
			expected: []error{nil},
			vfs: mockVFS{
				lstat:    os.Lstat,
				readlink: os.Readlink,
			},
		},
		{
			expected: []error{lstatErr},
			vfs: mockVFS{
				lstat:    lstatFailFn,
				readlink: os.Readlink,
			},
		},
		{
			expected: []error{readlinkErr},
			vfs: mockVFS{
				lstat:    os.Lstat,
				readlink: readlinkFailFn,
			},
		},
		{
			expected: []error{lstatErr, readlinkErr},
			vfs: mockVFS{
				lstat:    lstatFailFn,
				readlink: readlinkFailFn,
			},
		},
	} {
		_, err := SecureJoinVFS(dir, "link", test.vfs)

		success := false
		for _, exp := range test.expected {
			if err == exp {
				success = true
			}
		}
		if !success {
			t.Errorf("SecureJoinVFS.mock%d: expected to get lstatError, got %v", idx, err)
		}
	}
}
