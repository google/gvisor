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

package lisafs_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/runsc/fsgofer"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Note that these are not supposed to be extensive or robust tests. These unit
// tests provide a sanity check that all RPCs at least work in obvious ways.
// For more fine grained testing, add syscall or integration tests.

func init() {
	log.SetLevel(log.Debug)
	if err := fsgofer.OpenProcSelfFD(); err != nil {
		panic(err)
	}
}

func runServerClient(t testing.TB, clientFn func(c *lisafs.Client, root lisafs.Inode)) {
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

	var serverWg sync.WaitGroup
	serverWg.Add(1)
	go func() {
		defer serverWg.Done()

		var cm lisafs.ConnectionManager
		conf := &fsgofer.Config{HostUDS: true, EnableVerityXattr: true}
		if err := cm.StartConnection(serverSocket, mountPath, fsgofer.LisafsHandlers[:], conf); err != nil {
			t.Fatalf("starting connection failed: %v", err)
			return
		}

		cm.Wait()
	}()

	c, root, err := lisafs.NewClient(clientSocket, "/")
	if err != nil {
		t.Fatalf("client creation failed: %v", err)
	}

	if root.ControlFD == lisafs.InvalidFDID {
		t.Fatalf("root control FD is not valid")
	}
	clientFn(c, root)
	closeFD(t, c, root.ControlFD)

	c.Close() // This should trigger client and server shutdown.
	serverWg.Wait()
}

func closeFD(t testing.TB, c *lisafs.Client, fd lisafs.FDID) {
	fdArr := [1]lisafs.FDID{fd}
	req := lisafs.CloseReq{FDs: fdArr[:]}
	if err := c.SndRcvMessage(lisafs.Close, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil); err != nil {
		t.Errorf("failed to close root FD: %v", err)
	}
}

func statTo(t *testing.T, c *lisafs.Client, fd lisafs.FDID, stat *lisafs.Statx) error {
	req := lisafs.StatReq{FD: fd}
	return c.SndRcvMessage(lisafs.Fstat, uint32(req.SizeBytes()), req.MarshalUnsafe, stat.UnmarshalUnsafe, nil)
}

func openCreateFile(t *testing.T, c *lisafs.Client, dirFD lisafs.FDID, name string) (lisafs.Inode, lisafs.FDID, int) {
	var req lisafs.OpenCreateAtReq
	req.DirFD = dirFD
	req.Name = lisafs.SizedString(name)
	req.Flags = unix.O_RDWR
	req.Mode = 0777
	req.UID = lisafs.UID(unix.Getuid())
	req.GID = lisafs.GID(unix.Getgid())

	var resp lisafs.OpenCreateAtResp
	respFD := [1]int{-1}
	if err := c.SndRcvMessage(lisafs.OpenCreateAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, respFD[:]); err != nil {
		t.Fatalf("OpenCreateAt failed: %v", err)
	}
	if respFD[0] == -1 {
		t.Error("no host FD donated")
	}
	return resp.Child, resp.NewFD, respFD[0]
}

func openFile(t *testing.T, c *lisafs.Client, fd lisafs.FDID, flags uint32, isReg bool) (lisafs.FDID, int) {
	req := lisafs.OpenAtReq{
		FD:    fd,
		Flags: flags,
	}
	var resp lisafs.OpenAtResp
	respFD := [1]int{-1}
	if err := c.SndRcvMessage(lisafs.OpenAt, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalUnsafe, respFD[:]); err != nil {
		t.Fatalf("OpenAt failed: %v", err)
	}
	if respFD[0] == -1 && isReg {
		t.Error("no host FD donated")
	}
	return resp.NewFD, respFD[0]
}

func unlinkFile(t *testing.T, c *lisafs.Client, dirFD lisafs.FDID, name string, isDir bool) {
	req := lisafs.UnlinkAtReq{
		DirFD: dirFD,
		Name:  lisafs.SizedString(name),
	}
	if isDir {
		req.Flags = unix.AT_REMOVEDIR
	}
	if err := c.SndRcvMessage(lisafs.UnlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, nil, nil); err != nil {
		t.Errorf("unlinking file %s failed: %v", name, err)
	}
}

func walk(t *testing.T, c *lisafs.Client, dirFD lisafs.FDID, names []string) []lisafs.Inode {
	req := lisafs.WalkReq{
		DirFD: dirFD,
		Path:  lisafs.StringArray(names),
	}

	var resp lisafs.WalkResp
	if err := c.SndRcvMessage(lisafs.Walk, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil); err != nil {
		t.Errorf("walk failed while trying to walk components %+v: %v", names, err)
	}
	return resp.Inodes
}

func walkStat(t *testing.T, c *lisafs.Client, dirFD lisafs.FDID, names []string) []lisafs.Statx {
	req := lisafs.WalkReq{
		DirFD: dirFD,
		Path:  lisafs.StringArray(names),
	}

	var resp lisafs.WalkStatResp
	if err := c.SndRcvMessage(lisafs.WalkStat, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalBytes, nil); err != nil {
		t.Errorf("walk failed while trying to walk components %+v: %v", names, err)
	}
	return resp.Stats
}

func writeFD(t *testing.T, c *lisafs.Client, fd lisafs.FDID, off uint64, buf []byte) error {
	req := lisafs.PWriteReq{
		Offset:   primitive.Uint64(off),
		FD:       fd,
		NumBytes: primitive.Uint32(len(buf)),
		Buf:      buf,
	}

	var resp lisafs.PWriteResp
	if err := c.SndRcvMessage(lisafs.PWrite, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil); err != nil {
		return err
	}
	if int(resp.Count) != len(buf) {
		t.Errorf("partial write: buf size = %d, written = %d", len(buf), resp.Count)
	}
	return nil
}

func readFDAndCmp(t *testing.T, c *lisafs.Client, fd lisafs.FDID, off uint64, want []byte) {
	req := lisafs.PReadReq{
		Offset: off,
		FD:     fd,
		Count:  uint32(len(want)),
	}
	resp := lisafs.PReadResp{
		Buf: make([]byte, len(want)),
	}
	if err := c.SndRcvMessage(lisafs.PRead, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil); err != nil {
		t.Errorf("read failed: %v", err)
		return
	}
	if int(resp.NumBytes) != len(want) {
		t.Errorf("partial read: buf size = %d, read = %d", len(want), resp.NumBytes)
		return
	}
	if bytes.Compare(resp.Buf, want) != 0 {
		t.Errorf("bytes read differ from what was expected: want = %v, got = %v", want, resp.Buf)
	}
}

func allocateAndVerify(t *testing.T, c *lisafs.Client, fd lisafs.FDID, off uint64, length uint64) {
	fallocateReq := lisafs.FAllocateReq{
		FD:     fd,
		Mode:   0,
		Offset: off,
		Length: length,
	}
	if err := c.SndRcvMessage(lisafs.FAllocate, uint32(fallocateReq.SizeBytes()), fallocateReq.MarshalUnsafe, nil, nil); err != nil {
		t.Errorf("fallocate failed: %v", err)
	} else {
		var stat lisafs.Statx
		if err := statTo(t, c, fd, &stat); err != nil {
			t.Errorf("stat required to verify fallocate failed: %v", err)
		} else if stat.Size != off+length {
			t.Errorf("incorrect file size after allocate: expected %d, got %d", off+length, stat.Size)
		}
	}
}

func cmpStatx(t *testing.T, want, got lisafs.Statx) {
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

func TestMount(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		if ftype := root.Stat.Mode & unix.S_IFMT; ftype != unix.S_IFDIR {
			t.Errorf("root inode is not a directory, file type = %d", ftype)
		}
	})
}

func TestStat(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, rootInode lisafs.Inode) {
		var rootStat lisafs.Statx
		if err := statTo(t, c, rootInode.ControlFD, &rootStat); err != nil {
			t.Errorf("stat on the root dir failed: %v", err)
		}

		// Compare stat results with rootInode, they should be the same.
		cmpStatx(t, rootInode.Stat, rootStat)
	})
}

func TestRegularFileIO(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		// Test Read/Write RPCs.
		data := make([]byte, 100)
		rand.Read(data)
		if err := writeFD(t, c, fd, 0, data); err != nil {
			t.Fatalf("write failed: %v", err)
		}
		readFDAndCmp(t, c, fd, 0, data)
		readFDAndCmp(t, c, fd, 50, data[50:])

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
		syncReq := lisafs.FsyncReq{FDs: []lisafs.FDID{fd}}
		if err := c.SndRcvMessage(lisafs.Fsync, uint32(syncReq.SizeBytes()), syncReq.MarshalBytes, nil, nil); err != nil {
			t.Errorf("syncing the FD failed: %v", err)
		}
	})
}

func TestRegularFileOpen(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		// Open a readonly FD and try writing to it to get an EBADF.
		roFD, roHostFD := openFile(t, c, ino.ControlFD, unix.O_RDONLY, true /* isReg */)
		defer closeFD(t, c, roFD)
		defer unix.Close(roHostFD)
		if err := writeFD(t, c, roFD, 0, []byte{1, 2, 3}); err != unix.EBADF {
			t.Errorf("writing to read only FD should generate EBADF, but got %v", err)
		}
	})
}

func TestSetStat(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		now := time.Now()
		wantStat := lisafs.SetStatReq{
			FD:   ino.ControlFD,
			Mask: unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_SIZE,
			Mode: 0760,
			UID:  lisafs.UID(unix.Getuid()),
			GID:  lisafs.GID(unix.Getgid()),
			Size: 50,
			Atime: linux.Timespec{
				Sec:  now.Unix(),
				Nsec: now.UnixNano() % 1e9,
			},
			Mtime: linux.Timespec{
				Sec:  now.Unix(),
				Nsec: now.UnixNano() % 1e9,
			},
		}
		var setStatResp lisafs.SetStatResp
		if err := c.SndRcvMessage(lisafs.SetStat, uint32(wantStat.SizeBytes()), wantStat.MarshalUnsafe, setStatResp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("setstat failed: %v", err)
		}

		if setStatResp.FailureMask != 0 {
			t.Fatalf("some setstat operations failed: failureMask = %#b", setStatResp.FailureMask)
		}

		// Verify that attributes were updated.
		var gotStat lisafs.Statx
		if err := statTo(t, c, ino.ControlFD, &gotStat); err != nil {
			t.Fatalf("stat required to verify setstat failed: %v", err)
		}
		if gotStat.Mode&07777 != wantStat.Mode ||
			gotStat.UID != wantStat.UID ||
			gotStat.GID != wantStat.GID ||
			gotStat.Size != wantStat.Size ||
			gotStat.Atime != wantStat.Atime ||
			gotStat.Mtime != wantStat.Mtime {
			t.Errorf("setStat did not update file correctly: setStat = %+v, stat = %+v", wantStat, gotStat)
		}
	})
}

func TestAllocate(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		allocateAndVerify(t, c, fd, 0, 40)
		allocateAndVerify(t, c, fd, 20, 100)
	})
}

func TestStatFS(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		var statFS lisafs.StatFS
		statFSReq := lisafs.FStatFSReq{FD: root.ControlFD}
		if err := c.SndRcvMessage(lisafs.FStatFS, uint32(statFSReq.SizeBytes()), statFSReq.MarshalUnsafe, statFS.UnmarshalUnsafe, nil); err != nil {
			t.Errorf("statfs failed: %v", err)
		}
	})
}

func TestUnlink(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		unlinkFile(t, c, root.ControlFD, name, false /* isDir */)
		if inodes := walk(t, c, root.ControlFD, []string{name}); len(inodes) > 0 {
			t.Errorf("deleted file should not be generating inodes on walk: %+v", inodes)
		}
	})
}

func TestSymlink(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		target := "/tmp/some/path"
		name := "symlinkFile"
		req := lisafs.SymlinkAtReq{
			DirFD:  root.ControlFD,
			Name:   lisafs.SizedString(name),
			Target: lisafs.SizedString(target),
			UID:    lisafs.UID(unix.Getuid()),
			GID:    lisafs.GID(unix.Getgid()),
		}

		var resp lisafs.SymlinkAtResp
		if err := c.SndRcvMessage(lisafs.SymlinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("symlink creation failed: %v", err)
		}
		defer closeFD(t, c, resp.Symlink.ControlFD)

		if resp.Symlink.Stat.Mode&unix.S_IFMT != unix.S_IFLNK {
			t.Errorf("stat return from symlink RPC indicates that the inode is not a symlink: mode = %d", resp.Symlink.Stat.Mode)
		}

		var readLinkResp lisafs.ReadLinkAtResp
		readlinkReq := lisafs.ReadLinkAtReq{FD: resp.Symlink.ControlFD}
		if err := c.SndRcvMessage(lisafs.ReadLinkAt, uint32(readlinkReq.SizeBytes()), readlinkReq.MarshalUnsafe, readLinkResp.UnmarshalBytes, nil); err != nil {
			t.Fatalf("readlink failed: %v", err)
		}
		if string(readLinkResp.Target) != target {
			t.Errorf("readlink return incorrect target: expected %q, got %q", target, readLinkResp.Target)
		}
	})
}

func TestHardLink(t *testing.T) {
	if !specutils.HasCapabilities(capability.CAP_DAC_READ_SEARCH) {
		t.Skipf("TestHardLink requires CAP_DAC_READ_SEARCH, running as %d", unix.Getuid())
	}
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		fileIno, openFD, hostFD := openCreateFile(t, c, root.ControlFD, "tempFile")
		defer unix.Close(hostFD)
		defer closeFD(t, c, openFD)
		defer closeFD(t, c, fileIno.ControlFD)

		req := lisafs.LinkAtReq{
			DirFD:  root.ControlFD,
			Target: fileIno.ControlFD,
			Name:   "hardLink",
		}
		var resp lisafs.LinkAtResp
		if err := c.SndRcvMessage(lisafs.LinkAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("linkat RPC failed: %v", err)
		}
		defer closeFD(t, c, resp.Link.ControlFD)

		if resp.Link.Stat.Ino != fileIno.Stat.Ino {
			t.Errorf("hard linked files have different inode numbers: %d %d", resp.Link.Stat.Ino, fileIno.Stat.Ino)
		}
		if resp.Link.Stat.Dev != fileIno.Stat.Dev {
			t.Errorf("hard linked files have different device numbers: %d %d", resp.Link.Stat.Dev, fileIno.Stat.Dev)
		}
	})
}

func TestWalk(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		// Create 10 nested directories.
		n := 10
		curDir := root.ControlFD
		var mkdirReq lisafs.MkdirAtReq
		mkdirReq.Mode = 0777
		mkdirReq.UID = lisafs.UID(unix.Getuid())
		mkdirReq.GID = lisafs.GID(unix.Getgid())
		var mkdirResp lisafs.MkdirAtResp
		dirNames := make([]string, 0, n)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("tmpdir-%d", i)
			mkdirReq.DirFD = curDir
			mkdirReq.Name = lisafs.SizedString(name)
			if err := c.SndRcvMessage(lisafs.MkdirAt, uint32(mkdirReq.SizeBytes()), mkdirReq.MarshalBytes, mkdirResp.UnmarshalUnsafe, nil); err != nil {
				t.Fatalf("mkdir failed: %v", err)
			}
			defer closeFD(t, c, mkdirResp.ChildDir.ControlFD)
			defer unlinkFile(t, c, curDir, name, true /* isDir */)

			curDir = mkdirResp.ChildDir.ControlFD
			dirNames = append(dirNames, name)
		}

		// Walk all these directories. Add some junk at the end which should not be
		// walked on.
		dirNames = append(dirNames, []string{"a", "b", "c"}...)
		inodes := walk(t, c, root.ControlFD, dirNames)
		if len(inodes) != n {
			t.Errorf("walk returned the incorrect number of inodes: wanted %d, got %d", n, len(inodes))
		}

		// Close all control FDs and collect stat results for all dirs including
		// the root directory.
		dirStats := make([]lisafs.Statx, 0, n+1)
		var stat lisafs.Statx
		if err := statTo(t, c, root.ControlFD, &stat); err != nil {
			t.Fatalf("root stat failed: %v", err)
		}
		dirStats = append(dirStats, stat)
		for _, inode := range inodes {
			if err := statTo(t, c, inode.ControlFD, &stat); err != nil {
				t.Fatalf("stat failed: %v", err)
			}
			dirStats = append(dirStats, stat)
			closeFD(t, c, inode.ControlFD)
		}

		// Test WalkStat which additonally returns Statx for root because the first
		// path component is "".
		dirNames = append([]string{""}, dirNames...)
		gotStats := walkStat(t, c, root.ControlFD, dirNames)
		if len(gotStats) != len(dirStats) {
			t.Errorf("walkStat returned the incorrect number of statx: wanted %d, got %d", len(dirStats), len(gotStats))
		} else {
			for i := range gotStats {
				cmpStatx(t, dirStats[i], gotStats[i])
			}
		}
	})
}

func TestRename(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "tempFile"
		ino, fd, hostFD := openCreateFile(t, c, root.ControlFD, name)
		defer closeFD(t, c, ino.ControlFD)
		defer closeFD(t, c, fd)
		defer unix.Close(hostFD)

		var mkdirResp lisafs.MkdirAtResp
		var mkdirReq lisafs.MkdirAtReq
		mkdirReq.Mode = 0777
		mkdirReq.UID = lisafs.UID(unix.Getuid())
		mkdirReq.GID = lisafs.GID(unix.Getgid())
		mkdirReq.Name = "tempDir"
		mkdirReq.DirFD = root.ControlFD

		if err := c.SndRcvMessage(lisafs.MkdirAt, uint32(mkdirReq.SizeBytes()), mkdirReq.MarshalBytes, mkdirResp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		defer closeFD(t, c, mkdirResp.ChildDir.ControlFD)

		// Move tempFile into tempDir.
		renameReq := lisafs.RenameAtReq{
			Renamed: ino.ControlFD,
			NewDir:  mkdirResp.ChildDir.ControlFD,
			NewName: "movedFile",
		}
		if err := c.SndRcvMessage(lisafs.RenameAt, uint32(renameReq.SizeBytes()), renameReq.MarshalBytes, nil, nil); err != nil {
			t.Fatalf("rename failed: %v", err)
		}

		inodes := walkStat(t, c, root.ControlFD, []string{"tempDir", "movedFile"})
		if len(inodes) != 2 {
			t.Errorf("expected 2 files on walk but only found %d", len(inodes))
		}
	})
}

func TestMknod(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		name := "namedPipe"
		var req lisafs.MknodAtReq
		req.DirFD = root.ControlFD
		req.Name = lisafs.SizedString(name)
		req.Mode = unix.S_IFREG | 0777
		req.UID = lisafs.UID(unix.Getuid())
		req.GID = lisafs.GID(unix.Getgid())

		var resp lisafs.MknodAtResp
		if err := c.SndRcvMessage(lisafs.MknodAt, uint32(req.SizeBytes()), req.MarshalBytes, resp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("mknod failed: %v", err)
		}
		defer closeFD(t, c, resp.Child.ControlFD)

		var stat lisafs.Statx
		if err := statTo(t, c, resp.Child.ControlFD, &stat); err != nil {
			t.Fatalf("stat needed to verify mknod failed: %v", err)
		}

		if stat.Mode != uint32(req.Mode) {
			t.Errorf("mknod mode is incorrect: want %d, got %d", req.Mode, stat.Mode)
		}
		if stat.UID != req.UID {
			t.Errorf("mknod UID is incorrect: want %d, got %d", req.UID, stat.UID)
		}
		if stat.GID != req.GID {
			t.Errorf("mknod GID is incorrect: want %d, got %d", req.GID, stat.GID)
		}
	})
}

func TestGetdents(t *testing.T) {
	runServerClient(t, func(c *lisafs.Client, root lisafs.Inode) {
		var mkdirResp lisafs.MkdirAtResp
		var mkdirReq lisafs.MkdirAtReq
		mkdirReq.Mode = 0777
		mkdirReq.UID = lisafs.UID(unix.Getuid())
		mkdirReq.GID = lisafs.GID(unix.Getgid())
		mkdirReq.Name = "tempDir"
		mkdirReq.DirFD = root.ControlFD

		if err := c.SndRcvMessage(lisafs.MkdirAt, uint32(mkdirReq.SizeBytes()), mkdirReq.MarshalBytes, mkdirResp.UnmarshalUnsafe, nil); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		defer closeFD(t, c, mkdirResp.ChildDir.ControlFD)
		defer unlinkFile(t, c, root.ControlFD, "tempDir", true /* isDir */)

		// Create 10 files in tempDir.
		n := 10
		var mknodReq lisafs.MknodAtReq
		mknodReq.DirFD = mkdirResp.ChildDir.ControlFD
		mknodReq.Mode = unix.S_IFREG | 0777
		mknodReq.UID = lisafs.UID(unix.Getuid())
		mknodReq.GID = lisafs.GID(unix.Getgid())
		var mknodResp lisafs.MknodAtResp
		files := make(map[string]lisafs.Inode)
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("file-%d", i)
			mknodReq.Name = lisafs.SizedString(name)
			if err := c.SndRcvMessage(lisafs.MknodAt, uint32(mknodReq.SizeBytes()), mknodReq.MarshalBytes, mknodResp.UnmarshalUnsafe, nil); err != nil {
				t.Fatalf("mkdir failed: %v", err)
			}
			defer closeFD(t, c, mknodResp.Child.ControlFD)
			defer unlinkFile(t, c, mkdirResp.ChildDir.ControlFD, name, false /* isDir */)

			files[name] = mknodResp.Child
		}

		// Use opened directory FD for getdents.
		openDirFD, _ := openFile(t, c, mkdirResp.ChildDir.ControlFD, unix.O_RDONLY, false /* isReg */)
		defer closeFD(t, c, openDirFD)

		dirents := make([]lisafs.Dirent64, 0, n)
		req := lisafs.Getdents64Req{
			DirFD: openDirFD,
			Count: 40,
		}
		var resp lisafs.Getdents64Resp
		for i := 0; i < n+2; i++ {
			if err := c.SndRcvMessage(lisafs.Getdents64, uint32(req.SizeBytes()), req.MarshalUnsafe, resp.UnmarshalBytes, nil); err != nil {
				t.Fatalf("getdents failed: %v", err)
			}
			if len(resp.Dirents) == 0 {
				break
			}
			for _, dirent := range resp.Dirents {
				if dirent.Name != "." && dirent.Name != ".." {
					dirents = append(dirents, dirent)
				}
			}
		}

		if len(dirents) != n {
			t.Errorf("got incorrect number of dirents: wanted %d, got %d", n, len(dirents))
		}
		for _, dirent := range resp.Dirents {
			inode, ok := files[string(dirent.Name)]
			if !ok {
				t.Errorf("received a dirent that was not created: %+v", dirent)
				continue
			}

			if dirent.Type != unix.DT_REG {
				t.Errorf("dirent type is of incorrect: %d", dirent.Type)
			}
			if uint64(dirent.Ino) != inode.Stat.Ino {
				t.Errorf("dirent ino is of incorrect: want %d, got %d", inode.Stat.Ino, dirent.Ino)
			}
			if uint64(dirent.Dev) != inode.Stat.Dev {
				t.Errorf("dirent dev is of incorrect: want %d, got %d", inode.Stat.Dev, dirent.Dev)
			}
		}
	})
}
