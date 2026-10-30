// Copyright 2026 The gVisor Authors.
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

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

const (
	shmPageSize       = 4096
	shmTotalSize      = 2 * shmPageSize
	tcpInflightBytes  = 16 * 1024
	stateEnvKey       = "STATE_WORKLOAD_ENV"
	stateEnvValue     = "preserved-across-sr-hops"
	stateXattrName    = "user.state_hop"
	workerShmFD       = 3
	workerReqReadFD   = 4
	workerRespWriteFD = 5
)

// stateWorkload runs a multi-subsystem stateful workload across chained
// checkpoint/restore hops, exercising processes/PGIDs, shared memfd mappings,
// anonymous and file-backed mmaps, open/unlinked tmpfs files, file offsets,
// advisory locks, xattrs, symlinks, custom signal handlers, loopback TCP/UDP
// sockets with unread in-flight payloads, Unix sockets with in-flight
// SCM_RIGHTS file descriptors, epoll over pipe/eventfd/timerfd, and open,
// mapped, renamed, and unlinked files in tmpfs, host bind mounts, and overlay
// root filesystems.
type stateWorkload struct {
	controlDir string
	scratchDir string
	hostDir    string
	rootfsDir  string
	hops       int
	worker     bool
}

// Name implements subcommands.Command.Name.
func (*stateWorkload) Name() string { return "state-workload" }

// Synopsis implements subcommands.Command.Synopsis.
func (*stateWorkload) Synopsis() string {
	return "exercises multi-subsystem stateful resources across chained checkpoint/restore hops"
}

// Usage implements subcommands.Command.Usage.
func (*stateWorkload) Usage() string {
	return "state-workload --control-dir=<dir> [--scratch-dir=/scratch] [--host-dir=<dir>] [--rootfs-dir=<dir>] [--hops=2]\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (w *stateWorkload) SetFlags(f *flag.FlagSet) {
	f.StringVar(&w.controlDir, "control-dir", "", "shared host directory for phase handshakes")
	f.StringVar(&w.scratchDir, "scratch-dir", "/scratch", "in-Sentry tmpfs directory for stateful filesystem objects")
	f.StringVar(&w.hostDir, "host-dir", "", "if set, a host bind mount directory to exercise")
	f.StringVar(&w.rootfsDir, "rootfs-dir", "", "if set, a directory in an overlay root filesystem to exercise")
	f.IntVar(&w.hops, "hops", 2, "number of checkpoint/restore hops to execute")
	f.BoolVar(&w.worker, "worker", false, "internal child worker mode")
}

func shmParentMagic(hop int) uint64 {
	return 0x504152454e540000 | uint64(uint16(hop+1))
}

func shmChildMagic(hop int) uint64 {
	return 0x4348494c44000000 | uint64(uint16(hop+1))
}

func deterministicPattern(tag string, hop int, n int) []byte {
	out := make([]byte, n)
	header := fmt.Sprintf("[%s:hop=%d]", tag, hop)
	for i := 0; i < n; i++ {
		out[i] = header[i%len(header)] ^ byte((i*31+hop*17)&0xff)
	}
	return out
}

func (w *stateWorkload) runWorker() subcommands.ExitStatus {
	shm, err := unix.Mmap(workerShmFD, 0, shmTotalSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		log.Printf("worker mmap failed: %v", err)
		return subcommands.ExitFailure
	}
	defer unix.Munmap(shm)

	reqFile := os.NewFile(uintptr(workerReqReadFD), "worker-req")
	defer reqFile.Close()
	respFile := os.NewFile(uintptr(workerRespWriteFD), "worker-resp")
	defer respFile.Close()

	scanner := bufio.NewScanner(reqFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "QUIT" {
			return subcommands.ExitSuccess
		}
		if !strings.HasPrefix(line, "PING ") {
			fmt.Fprintf(respFile, "ERR unexpected command %q\n", line)
			return subcommands.ExitFailure
		}
		hop, err := strconv.Atoi(strings.TrimPrefix(line, "PING "))
		if err != nil {
			fmt.Fprintf(respFile, "ERR bad hop %q: %v\n", line, err)
			return subcommands.ExitFailure
		}
		gotMagic := binary.LittleEndian.Uint64(shm[0:8])
		wantMagic := shmParentMagic(hop)
		if gotMagic != wantMagic {
			fmt.Fprintf(respFile, "ERR shm magic got %#x want %#x\n", gotMagic, wantMagic)
			return subcommands.ExitFailure
		}
		wantParentSlice := deterministicPattern("shm-parent", hop, shmPageSize-16)
		if !bytes.Equal(shm[16:shmPageSize], wantParentSlice) {
			fmt.Fprintf(respFile, "ERR shm parent payload mismatch at hop %d\n", hop)
			return subcommands.ExitFailure
		}

		binary.LittleEndian.PutUint64(shm[8:16], shmChildMagic(hop))
		copy(shm[shmPageSize:shmTotalSize], deterministicPattern("shm-child", hop, shmPageSize))

		pgid, err := unix.Getpgid(0)
		if err != nil {
			fmt.Fprintf(respFile, "ERR getpgid: %v\n", err)
			return subcommands.ExitFailure
		}
		if _, err := fmt.Fprintf(respFile, "PONG hop=%d pid=%d pgid=%d\n", hop, os.Getpid(), pgid); err != nil {
			return subcommands.ExitFailure
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("worker scanner error: %v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (w *stateWorkload) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	if w.controlDir != "" {
		f, err := os.OpenFile(filepath.Join(w.controlDir, "workload.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			fmt.Fprintln(f, msg)
			f.Close()
		}
	}
}

func (w *stateWorkload) failf(format string, args ...any) subcommands.ExitStatus {
	w.logf("FAIL: "+format, args...)
	return subcommands.ExitFailure
}

func writeControlMarker(dir, name, content string) error {
	tmp := filepath.Join(dir, "."+name+".tmp")
	dst := filepath.Join(dir, name)
	if err := os.WriteFile(tmp, []byte(content), 0666); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func waitForControlMarker(dir, name string, timeout time.Duration) error {
	path := filepath.Join(dir, name)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(15 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", path)
}

// Execute implements subcommands.Command.Execute.
func (w *stateWorkload) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if w.worker {
		return w.runWorker()
	}
	if w.controlDir == "" || w.hops < 1 {
		log.Printf("--control-dir is required and --hops must be >= 1")
		return subcommands.ExitUsageError
	}

	// 1. Set up tmpfs directory hierarchy, working directory, symlink, xattr, and env.
	workDir := filepath.Join(w.scratchDir, "workdir")
	nestedDir := filepath.Join(workDir, "nested")
	if err := os.MkdirAll(nestedDir, 0755); err != nil {
		return w.failf("MkdirAll(%q): %v", nestedDir, err)
	}
	if err := os.Chdir(workDir); err != nil {
		return w.failf("Chdir(%q): %v", workDir, err)
	}
	if err := os.Setenv(stateEnvKey, stateEnvValue); err != nil {
		return w.failf("Setenv: %v", err)
	}
	targetFile := filepath.Join(nestedDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("symlink-target-payload"), 0644); err != nil {
		return w.failf("WriteFile(%q): %v", targetFile, err)
	}
	symlinkPath := filepath.Join(workDir, "sym")
	if err := os.Symlink("nested/target.txt", symlinkPath); err != nil {
		return w.failf("Symlink: %v", err)
	}

	// 2. Register custom signal handler for SIGUSR1.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, unix.SIGUSR1)
	defer signal.Stop(sigCh)

	// 3. Set up private anonymous mmap and file-backed MAP_SHARED mmap.
	privMap, err := unix.Mmap(-1, 0, shmTotalSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return w.failf("anonymous Mmap: %v", err)
	}
	defer unix.Munmap(privMap)

	mmapPath := filepath.Join(w.scratchDir, "mmap-backing")
	mmapFile, err := os.OpenFile(mmapPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return w.failf("OpenFile(%q): %v", mmapPath, err)
	}
	defer mmapFile.Close()
	if err := mmapFile.Truncate(shmTotalSize); err != nil {
		return w.failf("Truncate(%q): %v", mmapPath, err)
	}
	fileMap, err := unix.Mmap(int(mmapFile.Fd()), 0, shmTotalSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return w.failf("file-backed Mmap: %v", err)
	}
	defer unix.Munmap(fileMap)

	// 4. Open file with seek offset and file with advisory flock.
	seekPath := filepath.Join(w.scratchDir, "seek-file")
	seekData := deterministicPattern("seek-file", 0, 4096)
	if err := os.WriteFile(seekPath, seekData, 0644); err != nil {
		return w.failf("WriteFile(%q): %v", seekPath, err)
	}
	seekFile, err := os.Open(seekPath)
	if err != nil {
		return w.failf("Open(%q): %v", seekPath, err)
	}
	defer seekFile.Close()

	lockPath := filepath.Join(w.scratchDir, "flock-file")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return w.failf("OpenFile(%q): %v", lockPath, err)
	}
	defer lockFile.Close()
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return w.failf("Flock(LOCK_EX): %v", err)
	}

	// 4b. Hold open files, shared file mappings, and directory state in each
	// kind of filesystem: tmpfs, and optionally a host bind mount and an
	// overlay root filesystem.
	probeRoots := []struct{ name, dir string }{{"tmpfs", w.scratchDir}}
	if w.hostDir != "" {
		probeRoots = append(probeRoots, struct{ name, dir string }{"hostbind", w.hostDir})
	}
	if w.rootfsDir != "" {
		probeRoots = append(probeRoots, struct{ name, dir string }{"rootfs", w.rootfsDir})
	}
	var probes []*fsProbe
	defer func() {
		for _, p := range probes {
			p.close()
		}
	}()
	for _, r := range probeRoots {
		p, err := newFSProbe(r.name, r.dir, true /* allowUnlinked */)
		if err != nil {
			return w.failf("newFSProbe(%s): %v", r.name, err)
		}
		probes = append(probes, p)
	}

	// 5. Spawn child worker in a separate process group sharing a memfd MAP_SHARED region and pipes.
	memFD, err := unix.MemfdCreate("state-shm", unix.MFD_CLOEXEC)
	if err != nil {
		return w.failf("MemfdCreate: %v", err)
	}
	shmFile := os.NewFile(uintptr(memFD), "state-shm")
	defer shmFile.Close()
	if err := shmFile.Truncate(shmTotalSize); err != nil {
		return w.failf("shmFile.Truncate: %v", err)
	}
	shmMap, err := unix.Mmap(int(shmFile.Fd()), 0, shmTotalSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return w.failf("shmFile Mmap: %v", err)
	}
	defer unix.Munmap(shmMap)

	childReqR, childReqW, err := os.Pipe()
	if err != nil {
		return w.failf("os.Pipe req: %v", err)
	}
	defer childReqW.Close()
	childRespR, childRespW, err := os.Pipe()
	if err != nil {
		childReqR.Close()
		return w.failf("os.Pipe resp: %v", err)
	}
	defer childRespR.Close()

	childCmd := exec.Command("/proc/self/exe", "state-workload", "--worker")
	childCmd.Stderr = os.Stderr
	childCmd.ExtraFiles = []*os.File{shmFile, childReqR, childRespW}
	childCmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	if err := childCmd.Start(); err != nil {
		childReqR.Close()
		childRespW.Close()
		return w.failf("childCmd.Start: %v", err)
	}
	childReqR.Close()
	childRespW.Close()
	childPID := childCmd.Process.Pid
	childReader := bufio.NewReader(childRespR)

	pingWorker := func(hop int) error {
		if _, err := fmt.Fprintf(childReqW, "PING %d\n", hop); err != nil {
			return fmt.Errorf("write PING %d: %w", hop, err)
		}
		resp, err := childReader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read PONG %d: %w", hop, err)
		}
		resp = strings.TrimSpace(resp)
		wantResp := fmt.Sprintf("PONG hop=%d pid=%d pgid=%d", hop, childPID, childPID)
		if resp != wantResp {
			return fmt.Errorf("worker response got %q, want %q", resp, wantResp)
		}
		if got := binary.LittleEndian.Uint64(shmMap[8:16]); got != shmChildMagic(hop) {
			return fmt.Errorf("shm child magic got %#x, want %#x", got, shmChildMagic(hop))
		}
		wantChildSlice := deterministicPattern("shm-child", hop, shmPageSize)
		if !bytes.Equal(shmMap[shmPageSize:shmTotalSize], wantChildSlice) {
			return fmt.Errorf("shm child payload mismatch at hop %d", hop)
		}
		return nil
	}

	// Verify initial worker handshake before first checkpoint.
	binary.LittleEndian.PutUint64(shmMap[0:8], shmParentMagic(-1))
	copy(shmMap[16:shmPageSize], deterministicPattern("shm-parent", -1, shmPageSize-16))
	if err := pingWorker(-1); err != nil {
		return w.failf("initial worker ping: %v", err)
	}

	// 6. Set up loopback TCP listener + persistent connected pair, and loopback UDP sockets.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return w.failf("net.Listen tcp: %v", err)
	}
	defer tcpLn.Close()

	acceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := tcpLn.Accept()
		if err != nil {
			acceptCh <- nil
			return
		}
		acceptCh <- c
	}()
	tcpClient, err := net.Dial("tcp", tcpLn.Addr().String())
	if err != nil {
		return w.failf("net.Dial tcp: %v", err)
	}
	defer tcpClient.Close()
	tcpServer := <-acceptCh
	if tcpServer == nil {
		return w.failf("tcpLn.Accept returned nil")
	}
	defer tcpServer.Close()

	udpServer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return w.failf("net.ListenPacket udp: %v", err)
	}
	defer udpServer.Close()
	udpClient, err := net.Dial("udp", udpServer.LocalAddr().String())
	if err != nil {
		return w.failf("net.Dial udp: %v", err)
	}
	defer udpClient.Close()

	// 7. Set up filesystem Unix stream socket + AF_UNIX SOCK_SEQPACKET socketpair for SCM_RIGHTS.
	udsPath := filepath.Join(w.scratchDir, "stream.sock")
	udsLn, err := net.Listen("unix", udsPath)
	if err != nil {
		return w.failf("net.Listen unix: %v", err)
	}
	defer udsLn.Close()
	udsAcceptCh := make(chan net.Conn, 1)
	go func() {
		c, err := udsLn.Accept()
		if err != nil {
			udsAcceptCh <- nil
			return
		}
		udsAcceptCh <- c
	}()
	udsClient, err := net.Dial("unix", udsPath)
	if err != nil {
		return w.failf("net.Dial unix: %v", err)
	}
	defer udsClient.Close()
	udsServer := <-udsAcceptCh
	if udsServer == nil {
		return w.failf("udsLn.Accept returned nil")
	}
	defer udsServer.Close()

	spFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return w.failf("Socketpair(AF_UNIX, SOCK_SEQPACKET): %v", err)
	}
	defer unix.Close(spFDs[0])
	defer unix.Close(spFDs[1])

	// 8. Set up epoll monitoring pipe + eventfd + periodic timerfd.
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return w.failf("EpollCreate1: %v", err)
	}
	defer unix.Close(epfd)

	var epPipe [2]int
	if err := unix.Pipe2(epPipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return w.failf("Pipe2: %v", err)
	}
	defer unix.Close(epPipe[0])
	defer unix.Close(epPipe[1])

	efd, err := unix.Eventfd(0, unix.EFD_NONBLOCK|unix.EFD_CLOEXEC)
	if err != nil {
		return w.failf("Eventfd: %v", err)
	}
	defer unix.Close(efd)

	tfd, err := unix.TimerfdCreate(unix.CLOCK_MONOTONIC, unix.TFD_NONBLOCK|unix.TFD_CLOEXEC)
	if err != nil {
		return w.failf("TimerfdCreate: %v", err)
	}
	defer unix.Close(tfd)

	for _, fd := range []int{epPipe[0], efd, tfd} {
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, &unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(fd),
		}); err != nil {
			return w.failf("EpollCtl(ADD, %d): %v", fd, err)
		}
	}
	if err := unix.TimerfdSettime(tfd, 0, &unix.ItimerSpec{
		Interval: unix.Timespec{Nsec: 25_000_000}, // 25ms
		Value:    unix.Timespec{Nsec: 25_000_000},
	}, nil); err != nil {
		return w.failf("TimerfdSettime: %v", err)
	}

	w.logf("INIT_OK pid=%d child_pid=%d hops=%d", os.Getpid(), childPID, w.hops)

	// Execute chained checkpoint/restore hops.
	for hop := 0; hop < w.hops; hop++ {
		// Mutate memory mappings, xattrs, and file seek offset before checkpoint.
		wantPriv := deterministicPattern("priv-mmap", hop, shmTotalSize)
		copy(privMap, wantPriv)

		wantFileMap := deterministicPattern("file-mmap", hop, shmTotalSize)
		copy(fileMap, wantFileMap)

		wantXattr := fmt.Sprintf("xattr-hop-%d", hop)
		if err := unix.Setxattr(targetFile, stateXattrName, []byte(wantXattr), 0); err != nil {
			return w.failf("hop %d Setxattr: %v", hop, err)
		}

		wantOffset := int64(128 + hop*64)
		if off, err := seekFile.Seek(wantOffset, io.SeekStart); err != nil || off != wantOffset {
			return w.failf("hop %d Seek(%d): off=%d err=%v", hop, wantOffset, off, err)
		}

		// Populate shared memfd for the worker to verify AFTER restore.
		binary.LittleEndian.PutUint64(shmMap[0:8], shmParentMagic(hop))
		copy(shmMap[16:shmPageSize], deterministicPattern("shm-parent", hop, shmPageSize-16))

		// Queue unread in-flight TCP, UDP, and Unix stream bytes across checkpoint.
		wantTCP := deterministicPattern("tcp-inflight", hop, tcpInflightBytes)
		if _, err := tcpServer.Write(wantTCP); err != nil {
			return w.failf("hop %d tcpServer.Write: %v", hop, err)
		}
		wantUDP := deterministicPattern("udp-inflight", hop, 512)
		if _, err := udpClient.Write(wantUDP); err != nil {
			return w.failf("hop %d udpClient.Write: %v", hop, err)
		}
		wantUDS := deterministicPattern("uds-inflight", hop, 1024)
		if _, err := udsServer.Write(wantUDS); err != nil {
			return w.failf("hop %d udsServer.Write: %v", hop, err)
		}

		// Create an unlinked tmpfs file, send its FD over SCM_RIGHTS, and close our
		// local handle so the FD lives solely inside the socket's control buffer across S/R.
		unlinkedPath := filepath.Join(w.scratchDir, fmt.Sprintf("unlinked-hop-%d", hop))
		unlinkedFile, err := os.OpenFile(unlinkedPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if err != nil {
			return w.failf("hop %d OpenFile unlinked: %v", hop, err)
		}
		wantUnlinked := fmt.Sprintf("unlinked-secret-payload-hop-%d", hop)
		if _, err := unlinkedFile.WriteString(wantUnlinked); err != nil {
			unlinkedFile.Close()
			return w.failf("hop %d WriteString unlinked: %v", hop, err)
		}
		if err := os.Remove(unlinkedPath); err != nil {
			unlinkedFile.Close()
			return w.failf("hop %d Remove unlinked: %v", hop, err)
		}
		oob := unix.UnixRights(int(unlinkedFile.Fd()))
		msgTag := []byte(fmt.Sprintf("SCM_HOP_%d", hop))
		if err := unix.Sendmsg(spFDs[0], msgTag, oob, nil, 0); err != nil {
			unlinkedFile.Close()
			return w.failf("hop %d Sendmsg SCM_RIGHTS: %v", hop, err)
		}
		if err := unlinkedFile.Close(); err != nil {
			return w.failf("hop %d Close sender unlinked FD: %v", hop, err)
		}

		// Queue unread pipe bytes and eventfd counter for epoll across S/R.
		wantPipe := []byte(fmt.Sprintf("epoll-pipe-hop-%d", hop))
		if _, err := unix.Write(epPipe[1], wantPipe); err != nil {
			return w.failf("hop %d Write epPipe: %v", hop, err)
		}
		var efdVal [8]byte
		wantEFD := uint64(100 + hop)
		binary.NativeEndian.PutUint64(efdVal[:], wantEFD)
		if _, err := unix.Write(efd, efdVal[:]); err != nil {
			return w.failf("hop %d Write eventfd: %v", hop, err)
		}

		for _, p := range probes {
			if err := p.prepare(hop); err != nil {
				return w.failf("hop %d fsProbe prepare: %v", hop, err)
			}
		}

		readyName := fmt.Sprintf("phase%d.ready", hop)
		if err := writeControlMarker(w.controlDir, readyName, fmt.Sprintf("hop=%d\n", hop)); err != nil {
			return w.failf("hop %d writeControlMarker(%q): %v", hop, readyName, err)
		}
		w.logf("READY hop=%d", hop)

		// Wait until host checkpoints, restores into next container, and writes phase<hop+1>.go.
		goName := fmt.Sprintf("phase%d.go", hop+1)
		if err := waitForControlMarker(w.controlDir, goName, 90*time.Second); err != nil {
			return w.failf("hop %d waitForControlMarker(%q): %v", hop, goName, err)
		}
		w.logf("RESUMED hop=%d", hop)

		// --- Post-Restore Verification for Hop ---

		// Verify CWD, environment, symlink, and xattr.
		if cwd, err := os.Getwd(); err != nil || cwd != workDir {
			return w.failf("hop %d Getwd got (%q, %v), want %q", hop, cwd, err, workDir)
		}
		if gotEnv := os.Getenv(stateEnvKey); gotEnv != stateEnvValue {
			return w.failf("hop %d env %s got %q, want %q", hop, stateEnvKey, gotEnv, stateEnvValue)
		}
		if symData, err := os.ReadFile(symlinkPath); err != nil || string(symData) != "symlink-target-payload" {
			return w.failf("hop %d ReadFile symlink got (%q, %v)", hop, symData, err)
		}
		xattrBuf := make([]byte, 128)
		xn, err := unix.Getxattr(targetFile, stateXattrName, xattrBuf)
		if err != nil || string(xattrBuf[:xn]) != wantXattr {
			return w.failf("hop %d Getxattr got (%q, %v), want %q", hop, xattrBuf[:max(xn, 0)], err, wantXattr)
		}

		// Verify custom SIGUSR1 signal handler survived restore.
		if err := unix.Kill(os.Getpid(), unix.SIGUSR1); err != nil {
			return w.failf("hop %d Kill(SIGUSR1): %v", hop, err)
		}
		select {
		case <-sigCh:
		case <-time.After(5 * time.Second):
			return w.failf("hop %d timed out waiting for SIGUSR1 delivery after restore", hop)
		}

		// Verify private anonymous mmap and file-backed MAP_SHARED coherence.
		if !bytes.Equal(privMap, wantPriv) {
			return w.failf("hop %d privMap contents corrupted after restore", hop)
		}
		if !bytes.Equal(fileMap, wantFileMap) {
			return w.failf("hop %d fileMap contents corrupted after restore", hop)
		}
		preadBuf := make([]byte, shmTotalSize)
		if _, err := mmapFile.ReadAt(preadBuf, 0); err != nil || !bytes.Equal(preadBuf, wantFileMap) {
			return w.failf("hop %d mmapFile.ReadAt mismatch (err=%v)", hop, err)
		}
		probeByte := []byte{byte(0xa5 ^ hop)}
		if _, err := mmapFile.WriteAt(probeByte, 7); err != nil {
			return w.failf("hop %d mmapFile.WriteAt: %v", hop, err)
		}
		if fileMap[7] != probeByte[0] {
			return w.failf("hop %d MAP_SHARED coherence lost after restore: fileMap[7]=%#x, want %#x", hop, fileMap[7], probeByte[0])
		}

		// Verify open file seek offset and read from saved offset.
		if curOff, err := seekFile.Seek(0, io.SeekCurrent); err != nil || curOff != wantOffset {
			return w.failf("hop %d seek offset got (%d, %v), want %d", hop, curOff, err, wantOffset)
		}
		seekSlice := make([]byte, 32)
		if _, err := io.ReadFull(seekFile, seekSlice); err != nil {
			return w.failf("hop %d ReadFull seekFile: %v", hop, err)
		}
		if !bytes.Equal(seekSlice, seekData[wantOffset:wantOffset+32]) {
			return w.failf("hop %d seekFile read data mismatch after restore", hop)
		}

		// Verify advisory flock is still exclusively held across S/R.
		contendLock, err := os.OpenFile(lockPath, os.O_RDWR, 0)
		if err != nil {
			return w.failf("hop %d OpenFile contendLock: %v", hop, err)
		}
		flockErr := unix.Flock(int(contendLock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		contendLock.Close()
		if flockErr != unix.EWOULDBLOCK {
			return w.failf("hop %d contending Flock got %v, want EWOULDBLOCK", hop, flockErr)
		}

		// Verify child worker process, separate PGID, pipes, and shared memfd MAP_SHARED.
		if err := pingWorker(hop); err != nil {
			return w.failf("hop %d post-restore worker ping: %v", hop, err)
		}

		// Drain and verify in-flight loopback TCP bytes + bidirectional echo + fresh accept on tcpLn.
		gotTCP := make([]byte, tcpInflightBytes)
		if err := tcpClient.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return w.failf("hop %d tcpClient.SetReadDeadline: %v", hop, err)
		}
		if _, err := io.ReadFull(tcpClient, gotTCP); err != nil {
			return w.failf("hop %d ReadFull tcpClient in-flight: %v", hop, err)
		}
		if !bytes.Equal(gotTCP, wantTCP) {
			return w.failf("hop %d in-flight TCP payload mismatch after restore", hop)
		}
		replyTCP := []byte(fmt.Sprintf("tcp-ack-hop-%d", hop))
		if _, err := tcpClient.Write(replyTCP); err != nil {
			return w.failf("hop %d tcpClient.Write ack: %v", hop, err)
		}
		gotAck := make([]byte, len(replyTCP))
		if _, err := io.ReadFull(tcpServer, gotAck); err != nil || !bytes.Equal(gotAck, replyTCP) {
			return w.failf("hop %d tcpServer read ack got (%q, %v)", hop, gotAck, err)
		}

		freshAcceptCh := make(chan error, 1)
		go func() {
			c, err := tcpLn.Accept()
			if err != nil {
				freshAcceptCh <- err
				return
			}
			defer c.Close()
			_, err = c.Write([]byte("fresh-tcp-ok"))
			freshAcceptCh <- err
		}()
		freshConn, err := net.DialTimeout("tcp", tcpLn.Addr().String(), 5*time.Second)
		if err != nil {
			return w.failf("hop %d fresh Dial tcpLn after restore: %v", hop, err)
		}
		freshBytes, err := io.ReadAll(freshConn)
		freshConn.Close()
		if err != nil || string(freshBytes) != "fresh-tcp-ok" {
			return w.failf("hop %d fresh TCP read got (%q, %v)", hop, freshBytes, err)
		}
		if err := <-freshAcceptCh; err != nil {
			return w.failf("hop %d fresh Accept tcpLn: %v", hop, err)
		}

		// Drain and verify in-flight UDP datagram.
		if err := udpServer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return w.failf("hop %d udpServer.SetReadDeadline: %v", hop, err)
		}
		gotUDP := make([]byte, 1024)
		un, _, err := udpServer.ReadFrom(gotUDP)
		if err != nil || !bytes.Equal(gotUDP[:un], wantUDP) {
			return w.failf("hop %d ReadFrom udpServer got (n=%d, err=%v)", hop, un, err)
		}

		// Drain and verify in-flight Unix stream payload + fresh UDS dial.
		gotUDS := make([]byte, len(wantUDS))
		if _, err := io.ReadFull(udsClient, gotUDS); err != nil || !bytes.Equal(gotUDS, wantUDS) {
			return w.failf("hop %d ReadFull udsClient got err=%v", hop, err)
		}
		udsFreshCh := make(chan error, 1)
		go func() {
			c, err := udsLn.Accept()
			if err != nil {
				udsFreshCh <- err
				return
			}
			defer c.Close()
			_, err = c.Write([]byte("fresh-uds-ok"))
			udsFreshCh <- err
		}()
		freshUDS, err := net.DialTimeout("unix", udsPath, 5*time.Second)
		if err != nil {
			return w.failf("hop %d fresh Dial unix after restore: %v", hop, err)
		}
		freshUDSBytes, err := io.ReadAll(freshUDS)
		freshUDS.Close()
		if err != nil || string(freshUDSBytes) != "fresh-uds-ok" {
			return w.failf("hop %d fresh UDS read got (%q, %v)", hop, freshUDSBytes, err)
		}
		if err := <-udsFreshCh; err != nil {
			return w.failf("hop %d fresh Accept udsLn: %v", hop, err)
		}

		// Receive and verify in-flight SCM_RIGHTS FD pointing to the unlinked tmpfs file.
		recvMsgBuf := make([]byte, 64)
		recvOOB := make([]byte, unix.CmsgSpace(4))
		msgN, oobN, _, _, err := unix.Recvmsg(spFDs[1], recvMsgBuf, recvOOB, 0)
		if err != nil {
			return w.failf("hop %d Recvmsg SCM_RIGHTS: %v", hop, err)
		}
		if !bytes.Equal(recvMsgBuf[:msgN], msgTag) {
			return w.failf("hop %d Recvmsg tag got %q, want %q", hop, recvMsgBuf[:msgN], msgTag)
		}
		cmsgs, err := unix.ParseSocketControlMessage(recvOOB[:oobN])
		if err != nil || len(cmsgs) != 1 {
			return w.failf("hop %d ParseSocketControlMessage: cmsgs=%d err=%v", hop, len(cmsgs), err)
		}
		rightsFDs, err := unix.ParseUnixRights(&cmsgs[0])
		if err != nil || len(rightsFDs) != 1 {
			return w.failf("hop %d ParseUnixRights: fds=%v err=%v", hop, rightsFDs, err)
		}
		recvFile := os.NewFile(uintptr(rightsFDs[0]), "scm-unlinked")
		if _, err := recvFile.Seek(0, io.SeekStart); err != nil {
			recvFile.Close()
			return w.failf("hop %d recvFile.Seek: %v", hop, err)
		}
		gotUnlinked, err := io.ReadAll(recvFile)
		if err != nil || string(gotUnlinked) != wantUnlinked {
			recvFile.Close()
			return w.failf("hop %d unlinked SCM_RIGHTS read got (%q, %v), want %q", hop, gotUnlinked, err, wantUnlinked)
		}
		if _, err := recvFile.WriteString(":mutated-post-restore"); err != nil {
			recvFile.Close()
			return w.failf("hop %d recvFile.WriteString post-restore: %v", hop, err)
		}
		if _, err := recvFile.Seek(0, io.SeekStart); err != nil {
			recvFile.Close()
			return w.failf("hop %d recvFile.Seek(0) post-write: %v", hop, err)
		}
		gotUnlinkedMut, err := io.ReadAll(recvFile)
		recvFile.Close()
		if err != nil || string(gotUnlinkedMut) != wantUnlinked+":mutated-post-restore" {
			return w.failf("hop %d unlinked mutated read got (%q, %v)", hop, gotUnlinkedMut, err)
		}

		// Verify epoll readiness for pipe, eventfd, and periodic timerfd after restore.
		seenPipe, seenEFD, seenTFD := false, false, false
		epDeadline := time.Now().Add(5 * time.Second)
		events := make([]unix.EpollEvent, 8)
		for !(seenPipe && seenEFD && seenTFD) && time.Now().Before(epDeadline) {
			n, err := unix.EpollWait(epfd, events, 200)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return w.failf("hop %d EpollWait: %v", hop, err)
			}
			for i := 0; i < n; i++ {
				switch int(events[i].Fd) {
				case epPipe[0]:
					buf := make([]byte, 64)
					rn, err := unix.Read(epPipe[0], buf)
					if err != nil || !bytes.Equal(buf[:rn], wantPipe) {
						return w.failf("hop %d epPipe read got (%q, %v), want %q", hop, buf[:max(rn, 0)], err, wantPipe)
					}
					seenPipe = true
				case efd:
					var valBuf [8]byte
					rn, err := unix.Read(efd, valBuf[:])
					if err != nil || rn != 8 {
						return w.failf("hop %d eventfd read n=%d err=%v", hop, rn, err)
					}
					if gotVal := binary.NativeEndian.Uint64(valBuf[:]); gotVal != wantEFD {
						return w.failf("hop %d eventfd val got %d, want %d", hop, gotVal, wantEFD)
					}
					seenEFD = true
				case tfd:
					var expBuf [8]byte
					rn, err := unix.Read(tfd, expBuf[:])
					if err != nil || rn != 8 || binary.NativeEndian.Uint64(expBuf[:]) == 0 {
						return w.failf("hop %d timerfd read n=%d err=%v", hop, rn, err)
					}
					seenTFD = true
				}
			}
		}
		if !(seenPipe && seenEFD && seenTFD) {
			return w.failf("hop %d missing epoll events: pipe=%v eventfd=%v timerfd=%v", hop, seenPipe, seenEFD, seenTFD)
		}

		// Confirm periodic timerfd continues ticking post-restore.
		freshTick := false
		tickDeadline := time.Now().Add(5 * time.Second)
		for !freshTick && time.Now().Before(tickDeadline) {
			n, err := unix.EpollWait(epfd, events, 200)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return w.failf("hop %d EpollWait fresh timerfd tick: %v", hop, err)
			}
			for i := 0; i < n; i++ {
				if int(events[i].Fd) == tfd {
					var expBuf [8]byte
					if rn, err := unix.Read(tfd, expBuf[:]); err == nil && rn == 8 && binary.NativeEndian.Uint64(expBuf[:]) > 0 {
						freshTick = true
					}
				}
			}
		}
		if !freshTick {
			return w.failf("hop %d periodic timerfd failed to tick again after restore", hop)
		}

		// Verify filesystem state in tmpfs, host bind mount, and overlay root.
		for _, p := range probes {
			if err := p.verify(hop); err != nil {
				return w.failf("hop %d fsProbe verify: %v", hop, err)
			}
		}

		w.logf("VERIFIED hop=%d", hop)
	}

	// Shut down child worker cleanly and reap it.
	if _, err := fmt.Fprintln(childReqW, "QUIT"); err != nil {
		return w.failf("write QUIT to worker: %v", err)
	}
	if err := childCmd.Wait(); err != nil {
		return w.failf("childCmd.Wait: %v", err)
	}

	if err := writeControlMarker(w.controlDir, "done.ok", "OK\n"); err != nil {
		return w.failf("writeControlMarker(done.ok): %v", err)
	}
	w.logf("ALL_HOPS_OK hops=%d", w.hops)
	return subcommands.ExitSuccess
}
