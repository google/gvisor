// Copyright 2021 The gVisor Authors.
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

// Package testsuite provides a integration testing suite for lisafs.
// These tests are intended for servers serving the local filesystem.
package testsuite

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/unet"
)

// Tester is the client code using this test suite. This interface abstracts
// away all the caller specific details.
type Tester interface {
	// NewServer returns a new instance of the tester server.
	NewServer(t *testing.T) *lisafs.Server

	// LinkSupported returns true if the backing server supports LinkAt.
	LinkSupported() bool

	// SetUserGroupIDSupported returns true if the backing server supports
	// changing UID/GID for files.
	SetUserGroupIDSupported() bool
}

// RunAllLocalFSTests runs all local FS tests as subtests.
func RunAllLocalFSTests(t *testing.T, tester Tester) {
	for name, testFn := range localFSTests {
		t.Run(name, func(t *testing.T) {
			runServerClient(t, tester, testFn)
		})
	}
}

type testFunc func(context.Context, *testing.T, Tester, lisafs.ClientFD)

var localFSTests map[string]testFunc = map[string]testFunc{
	"Stat":            testStat,
	"RegularFileIO":   testRegularFileIO,
	"RegularFileOpen": testRegularFileOpen,
	"SetStat":         testSetStat,
	"Allocate":        testAllocate,
	"StatFS":          testStatFS,
	"Unlink":          testUnlink,
	"Symlink":         testSymlink,
	"HardLink":        testHardLink,
	"Walk":            testWalk,
	"Rename":          testRename,
	"Mknod":           testMknod,
	"Getdents":        testGetdents,
}

func runServerClient(t *testing.T, tester Tester, testFn testFunc) {
	mountPath, err := ioutil.TempDir(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("creation of temporary mountpoint failed: %v", err)
	}
	defer os.RemoveAll(mountPath)

	// fsgofer should run with a umask of 0, because we want to preserve file
	// modes exactly for testing purposes.
	unix.Umask(0)

	serverSocket, clientSocket, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}

	server := tester.NewServer(t)
	conn, err := server.CreateConnection(serverSocket, false /* readonly */)
	if err != nil {
		t.Fatalf("starting connection failed: %v", err)
		return
	}
	server.StartConnection(conn)

	c, root, err := lisafs.NewClient(clientSocket, mountPath)
	if err != nil {
		t.Fatalf("client creation failed: %v", err)
	}

	if !root.ControlFD.Ok() {
		t.Fatalf("root control FD is not valid")
	}
	rootFile := c.NewFD(root.ControlFD)

	ctx := context.Background()
	testFn(ctx, t, tester, rootFile)
	closeFD(ctx, t, rootFile)

	c.Close() // This should trigger client and server shutdown.
	server.Wait()
}

func closeFD(ctx context.Context, t testing.TB, fdLisa lisafs.ClientFD) {
	if err := fdLisa.Close(ctx); err != nil {
		t.Errorf("failed to close FD: %v", err)
	}
}

func statTo(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, stat *linux.Statx) {
	if err := fdLisa.StatTo(ctx, stat); err != nil {
		t.Fatalf("stat failed: %v", err)
	}
}

func openCreateFile(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, name string) (lisafs.ClientFD, linux.Statx, lisafs.ClientFD, int) {
	child, childFD, childHostFD, err := fdLisa.OpenCreateAt(ctx, name, unix.O_RDWR, 0777, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()))
	if err != nil {
		t.Fatalf("OpenCreateAt failed: %v", err)
	}
	if childHostFD == -1 {
		t.Error("no host FD donated")
	}
	client := fdLisa.Client()
	return client.NewFD(child.ControlFD), child.Stat, fdLisa.Client().NewFD(childFD), childHostFD
}

func openFile(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, flags uint32, isReg bool) (lisafs.ClientFD, int) {
	openFD, hostFD, err := fdLisa.OpenAt(ctx, flags)
	if err != nil {
		t.Fatalf("OpenAt failed: %v", err)
	}
	if hostFD == -1 && isReg {
		t.Error("no host FD donated")
	}
	return fdLisa.Client().NewFD(openFD), hostFD
}

func unlinkFile(ctx context.Context, t *testing.T, dir lisafs.ClientFD, name string, isDir bool) {
	var flags uint32
	if isDir {
		flags = unix.AT_REMOVEDIR
	}
	if err := dir.UnlinkAt(ctx, name, flags); err != nil {
		t.Errorf("unlinking file %s failed: %v", name, err)
	}
}

func symlink(ctx context.Context, t *testing.T, dir lisafs.ClientFD, name, target string) (lisafs.ClientFD, linux.Statx) {
	linkIno, err := dir.SymlinkAt(ctx, name, target, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()))
	if err != nil {
		t.Fatalf("symlink failed: %v", err)
	}
	return dir.Client().NewFD(linkIno.ControlFD), linkIno.Stat
}

func link(ctx context.Context, t *testing.T, dir lisafs.ClientFD, name string, target lisafs.ClientFD) (lisafs.ClientFD, linux.Statx) {
	linkIno, err := dir.LinkAt(ctx, target.ID(), name)
	if err != nil {
		t.Fatalf("link failed: %v", err)
	}
	return dir.Client().NewFD(linkIno.ControlFD), linkIno.Stat
}

func mkdir(ctx context.Context, t *testing.T, dir lisafs.ClientFD, name string) (lisafs.ClientFD, linux.Statx) {
	childIno, err := dir.MkdirAt(ctx, name, 0777, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()))
	if err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	return dir.Client().NewFD(childIno.ControlFD), childIno.Stat
}

func mknod(ctx context.Context, t *testing.T, dir lisafs.ClientFD, name string) (lisafs.ClientFD, linux.Statx) {
	nodeIno, err := dir.MknodAt(ctx, name, unix.S_IFREG|0777, lisafs.UID(unix.Getuid()), lisafs.GID(unix.Getgid()), 0, 0)
	if err != nil {
		t.Fatalf("mknod failed: %v", err)
	}
	return dir.Client().NewFD(nodeIno.ControlFD), nodeIno.Stat
}

func walk(ctx context.Context, t *testing.T, dir lisafs.ClientFD, names []string) []lisafs.Inode {
	_, inodes, err := dir.WalkMultiple(ctx, names)
	if err != nil {
		t.Fatalf("walk failed while trying to walk components %+v: %v", names, err)
	}
	return inodes
}

func walkStat(ctx context.Context, t *testing.T, dir lisafs.ClientFD, names []string) []linux.Statx {
	stats, err := dir.WalkStat(ctx, names)
	if err != nil {
		t.Fatalf("walk failed while trying to walk components %+v: %v", names, err)
	}
	return stats
}

func writeFD(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, off uint64, buf []byte) error {
	count, err := fdLisa.Write(ctx, buf, off)
	if err != nil {
		return err
	}
	if int(count) != len(buf) {
		t.Errorf("partial write: buf size = %d, written = %d", len(buf), count)
	}
	return nil
}

func readFDAndCmp(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, off uint64, want []byte) {
	buf := make([]byte, len(want))
	n, err := fdLisa.Read(ctx, buf, off)
	if err != nil {
		t.Errorf("read failed: %v", err)
		return
	}
	if int(n) != len(want) {
		t.Errorf("partial read: buf size = %d, read = %d", len(want), n)
		return
	}
	if bytes.Compare(buf, want) != 0 {
		t.Errorf("bytes read differ from what was expected: want = %v, got = %v", want, buf)
	}
}

func allocateAndVerify(ctx context.Context, t *testing.T, fdLisa lisafs.ClientFD, off uint64, length uint64) {
	if err := fdLisa.Allocate(ctx, 0, off, length); err != nil {
		t.Fatalf("fallocate failed: %v", err)
	}

	var stat linux.Statx
	statTo(ctx, t, fdLisa, &stat)
	if want := off + length; stat.Size != want {
		t.Errorf("incorrect file size after allocate: expected %d, got %d", off+length, stat.Size)
	}
}

func cmpStatx(t *testing.T, want, got linux.Statx) {
	if got.Mask&unix.STATX_MODE != 0 && want.Mask&unix.STATX_MODE != 0 {
		if got.Mode != want.Mode {
			t.Errorf("mode differs: want %d, got %d", want.Mode, got.Mode)
		}
	}
	if got.Mask&unix.STATX_INO != 0 && want.Mask&unix.STATX_INO != 0 {
		if got.Ino != want.Ino {
			t.Errorf("inode number differs: want %d, got %d", want.Ino, got.Ino)
		}
	}
	if got.Mask&unix.STATX_NLINK != 0 && want.Mask&unix.STATX_NLINK != 0 {
		if got.Nlink != want.Nlink {
			t.Errorf("nlink differs: want %d, got %d", want.Nlink, got.Nlink)
		}
	}
	if got.Mask&unix.STATX_UID != 0 && want.Mask&unix.STATX_UID != 0 {
		if got.UID != want.UID {
			t.Errorf("UID differs: want %d, got %d", want.UID, got.UID)
		}
	}
	if got.Mask&unix.STATX_GID != 0 && want.Mask&unix.STATX_GID != 0 {
		if got.GID != want.GID {
			t.Errorf("GID differs: want %d, got %d", want.GID, got.GID)
		}
	}
	if got.Mask&unix.STATX_SIZE != 0 && want.Mask&unix.STATX_SIZE != 0 {
		if got.Size != want.Size {
			t.Errorf("size differs: want %d, got %d", want.Size, got.Size)
		}
	}
	if got.Mask&unix.STATX_BLOCKS != 0 && want.Mask&unix.STATX_BLOCKS != 0 {
		if got.Blocks != want.Blocks {
			t.Errorf("blocks differs: want %d, got %d", want.Blocks, got.Blocks)
		}
	}
	if got.Mask&unix.STATX_ATIME != 0 && want.Mask&unix.STATX_ATIME != 0 {
		if got.Atime != want.Atime {
			t.Errorf("atime differs: want %d, got %d", want.Atime, got.Atime)
		}
	}
	if got.Mask&unix.STATX_MTIME != 0 && want.Mask&unix.STATX_MTIME != 0 {
		if got.Mtime != want.Mtime {
			t.Errorf("mtime differs: want %d, got %d", want.Mtime, got.Mtime)
		}
	}
	if got.Mask&unix.STATX_CTIME != 0 && want.Mask&unix.STATX_CTIME != 0 {
		if got.Ctime != want.Ctime {
			t.Errorf("ctime differs: want %d, got %d", want.Ctime, got.Ctime)
		}
	}
}

func hasCapability(c capability.Cap) bool {
	caps, err := capability.NewPid2(os.Getpid())
	if err != nil {
		return false
	}
	if err := caps.Load(); err != nil {
		return false
	}
	return caps.Get(capability.EFFECTIVE, c)
}

func testStat(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	var rootStat linux.Statx
	if err := root.StatTo(ctx, &rootStat); err != nil {
		t.Errorf("stat on the root dir failed: %v", err)
	}

	if ftype := rootStat.Mode & unix.S_IFMT; ftype != unix.S_IFDIR {
		t.Errorf("root inode is not a directory, file type = %d", ftype)
	}
}

func testRegularFileIO(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	controlFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	// Test Read/Write RPCs with 2MB of data to test IO in chunks.
	data := make([]byte, 1<<21)
	rand.Read(data)
	if err := writeFD(ctx, t, fd, 0, data); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	readFDAndCmp(ctx, t, fd, 0, data)
	readFDAndCmp(ctx, t, fd, 50, data[50:])

	// Make sure the host FD is configured properly.
	hostReadData := make([]byte, len(data))
	if n, err := unix.Pread(hostFD, hostReadData, 0); err != nil {
		t.Errorf("host read failed: %v", err)
	} else if n != len(hostReadData) {
		t.Errorf("partial read: buf size = %d, read = %d", len(hostReadData), n)
	} else if bytes.Compare(hostReadData, data) != 0 {
		t.Errorf("bytes read differ from what was expected: want = %v, got = %v", data, hostReadData)
	}

	// Test syncing the writable FD.
	if err := fd.Sync(ctx); err != nil {
		t.Errorf("syncing the FD failed: %v", err)
	}
}

func testRegularFileOpen(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	controlFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	// Open a readonly FD and try writing to it to get an EBADF.
	roFile, roHostFD := openFile(ctx, t, controlFile, unix.O_RDONLY, true /* isReg */)
	defer closeFD(ctx, t, roFile)
	defer unix.Close(roHostFD)
	if err := writeFD(ctx, t, roFile, 0, []byte{1, 2, 3}); err != unix.EBADF {
		t.Errorf("writing to read only FD should generate EBADF, but got %v", err)
	}
}

func testSetStat(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	controlFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	now := time.Now()
	wantStat := linux.Statx{
		Mask:  unix.STATX_MODE | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_SIZE,
		Mode:  0760,
		UID:   uint32(unix.Getuid()),
		GID:   uint32(unix.Getgid()),
		Size:  50,
		Atime: linux.NsecToStatxTimestamp(now.UnixNano()),
		Mtime: linux.NsecToStatxTimestamp(now.UnixNano()),
	}
	if tester.SetUserGroupIDSupported() {
		wantStat.Mask |= unix.STATX_UID | unix.STATX_GID
	}
	failureMask, failureErr, err := controlFile.SetStat(ctx, &wantStat)
	if err != nil {
		t.Fatalf("setstat failed: %v", err)
	}
	if failureMask != 0 {
		t.Fatalf("some setstat operations failed: failureMask = %#b, failureErr = %v", failureMask, failureErr)
	}

	// Verify that attributes were updated.
	var gotStat linux.Statx
	statTo(ctx, t, controlFile, &gotStat)
	if gotStat.Mode&07777 != wantStat.Mode ||
		gotStat.Size != wantStat.Size ||
		gotStat.Atime.ToNsec() != wantStat.Atime.ToNsec() ||
		gotStat.Mtime.ToNsec() != wantStat.Mtime.ToNsec() ||
		(tester.SetUserGroupIDSupported() && (uint32(gotStat.UID) != wantStat.UID || uint32(gotStat.GID) != wantStat.GID)) {
		t.Errorf("setStat did not update file correctly: setStat = %+v, stat = %+v", wantStat, gotStat)
	}
}

func testAllocate(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	controlFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	allocateAndVerify(ctx, t, fd, 0, 40)
	allocateAndVerify(ctx, t, fd, 20, 100)
}

func testStatFS(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	var statFS lisafs.StatFS
	if err := root.StatFSTo(ctx, &statFS); err != nil {
		t.Errorf("statfs failed: %v", err)
	}
}

func testUnlink(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	controlFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	unlinkFile(ctx, t, root, name, false /* isDir */)
	if inodes := walk(ctx, t, root, []string{name}); len(inodes) > 0 {
		t.Errorf("deleted file should not be generating inodes on walk: %+v", inodes)
	}
}

func testSymlink(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	target := "/tmp/some/path"
	name := "symlinkFile"
	link, linkStat := symlink(ctx, t, root, name, target)
	defer closeFD(ctx, t, link)

	if linkStat.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Errorf("stat return from symlink RPC indicates that the inode is not a symlink: mode = %d", linkStat.Mode)
	}

	if gotTarget, err := link.ReadLinkAt(ctx); err != nil {
		t.Fatalf("readlink failed: %v", err)
	} else if gotTarget != target {
		t.Errorf("readlink return incorrect target: expected %q, got %q", target, gotTarget)
	}
}

func testHardLink(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	if !tester.LinkSupported() {
		t.Skipf("server does not support LinkAt RPC")
	}
	if !hasCapability(capability.CAP_DAC_READ_SEARCH) {
		t.Skipf("TestHardLink requires CAP_DAC_READ_SEARCH, running as %d", unix.Getuid())
	}
	name := "tempFile"
	controlFile, fileIno, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, controlFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	link, linkStat := link(ctx, t, root, name, controlFile)
	defer closeFD(ctx, t, link)

	if linkStat.Ino != fileIno.Ino {
		t.Errorf("hard linked files have different inode numbers: %d %d", linkStat.Ino, fileIno.Ino)
	}
	if linkStat.DevMinor != fileIno.DevMinor {
		t.Errorf("hard linked files have different minor device numbers: %d %d", linkStat.DevMinor, fileIno.DevMinor)
	}
	if linkStat.DevMajor != fileIno.DevMajor {
		t.Errorf("hard linked files have different major device numbers: %d %d", linkStat.DevMajor, fileIno.DevMajor)
	}
}

func testWalk(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	// Create 10 nested directories.
	n := 10
	curDir := root

	dirNames := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("tmpdir-%d", i)
		childDir, _ := mkdir(ctx, t, curDir, name)
		defer closeFD(ctx, t, childDir)
		defer unlinkFile(ctx, t, curDir, name, true /* isDir */)

		curDir = childDir
		dirNames = append(dirNames, name)
	}

	// Walk all these directories. Add some junk at the end which should not be
	// walked on.
	dirNames = append(dirNames, []string{"a", "b", "c"}...)
	inodes := walk(ctx, t, root, dirNames)
	if len(inodes) != n {
		t.Errorf("walk returned the incorrect number of inodes: wanted %d, got %d", n, len(inodes))
	}

	// Close all control FDs and collect stat results for all dirs including
	// the root directory.
	dirStats := make([]linux.Statx, 0, n+1)
	var stat linux.Statx
	statTo(ctx, t, root, &stat)
	dirStats = append(dirStats, stat)
	for _, inode := range inodes {
		dirStats = append(dirStats, inode.Stat)
		closeFD(ctx, t, root.Client().NewFD(inode.ControlFD))
	}

	// Test WalkStat which additonally returns Statx for root because the first
	// path component is "".
	dirNames = append([]string{""}, dirNames...)
	gotStats := walkStat(ctx, t, root, dirNames)
	if len(gotStats) != len(dirStats) {
		t.Errorf("walkStat returned the incorrect number of statx: wanted %d, got %d", len(dirStats), len(gotStats))
	} else {
		for i := range gotStats {
			cmpStatx(t, dirStats[i], gotStats[i])
		}
	}
}

func testRename(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "tempFile"
	tempFile, _, fd, hostFD := openCreateFile(ctx, t, root, name)
	defer closeFD(ctx, t, tempFile)
	defer closeFD(ctx, t, fd)
	defer unix.Close(hostFD)

	tempDir, _ := mkdir(ctx, t, root, "tempDir")
	defer closeFD(ctx, t, tempDir)

	// Move tempFile into tempDir.
	if err := tempFile.RenameTo(ctx, tempDir.ID(), "movedFile"); err != nil {
		t.Fatalf("rename failed: %v", err)
	}

	inodes := walkStat(ctx, t, root, []string{"tempDir", "movedFile"})
	if len(inodes) != 2 {
		t.Errorf("expected 2 files on walk but only found %d", len(inodes))
	}
}

func testMknod(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	name := "namedPipe"
	pipeFile, pipeStat := mknod(ctx, t, root, name)
	defer closeFD(ctx, t, pipeFile)

	var stat linux.Statx
	statTo(ctx, t, pipeFile, &stat)

	if stat.Mode != pipeStat.Mode {
		t.Errorf("mknod mode is incorrect: want %d, got %d", pipeStat.Mode, stat.Mode)
	}
	if stat.UID != pipeStat.UID {
		t.Errorf("mknod UID is incorrect: want %d, got %d", pipeStat.UID, stat.UID)
	}
	if stat.GID != pipeStat.GID {
		t.Errorf("mknod GID is incorrect: want %d, got %d", pipeStat.GID, stat.GID)
	}
}

func testGetdents(ctx context.Context, t *testing.T, tester Tester, root lisafs.ClientFD) {
	tempDir, _ := mkdir(ctx, t, root, "tempDir")
	defer closeFD(ctx, t, tempDir)
	defer unlinkFile(ctx, t, root, "tempDir", true /* isDir */)

	// Create 10 files in tempDir.
	n := 10
	fileStats := make(map[string]linux.Statx)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("file-%d", i)
		newFile, fileStat := mknod(ctx, t, tempDir, name)
		defer closeFD(ctx, t, newFile)
		defer unlinkFile(ctx, t, tempDir, name, false /* isDir */)

		fileStats[name] = fileStat
	}

	// Use opened directory FD for getdents.
	openDirFile, dirHostFD := openFile(ctx, t, tempDir, unix.O_RDONLY, false /* isReg */)
	unix.Close(dirHostFD)
	defer closeFD(ctx, t, openDirFile)

	dirents := make([]lisafs.Dirent64, 0, n)
	for i := 0; i < n+2; i++ {
		gotDirents, err := openDirFile.Getdents64(ctx, 40)
		if err != nil {
			t.Fatalf("getdents failed: %v", err)
		}
		if len(gotDirents) == 0 {
			break
		}
		for _, dirent := range gotDirents {
			if dirent.Name != "." && dirent.Name != ".." {
				dirents = append(dirents, dirent)
			}
		}
	}

	if len(dirents) != n {
		t.Errorf("got incorrect number of dirents: wanted %d, got %d", n, len(dirents))
	}
	for _, dirent := range dirents {
		stat, ok := fileStats[string(dirent.Name)]
		if !ok {
			t.Errorf("received a dirent that was not created: %+v", dirent)
			continue
		}

		if dirent.Type != unix.DT_REG {
			t.Errorf("dirent type of %s is incorrect: %d", dirent.Name, dirent.Type)
		}
		if uint64(dirent.Ino) != stat.Ino {
			t.Errorf("dirent ino of %s is incorrect: want %d, got %d", dirent.Name, stat.Ino, dirent.Ino)
		}
		if uint32(dirent.DevMinor) != stat.DevMinor {
			t.Errorf("dirent dev minor of %s is incorrect: want %d, got %d", dirent.Name, stat.DevMinor, dirent.DevMinor)
		}
		if uint32(dirent.DevMajor) != stat.DevMajor {
			t.Errorf("dirent dev major of %s is incorrect: want %d, got %d", dirent.Name, stat.DevMajor, dirent.DevMajor)
		}
	}
}
