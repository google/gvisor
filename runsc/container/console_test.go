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

package container

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kr/pty"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

// socketPath creates a path inside bundleDir and ensures that the returned
// path is under 108 charactors (the unix socket path length limit),
// relativizing the path if necessary.
func socketPath(bundleDir string) (string, error) {
	path := filepath.Join(bundleDir, "socket")
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("error getting cwd: %v", err)
	}
	relPath, err := filepath.Rel(cwd, path)
	if err != nil {
		return "", fmt.Errorf("error getting relative path for %q from cwd %q: %v", path, cwd, err)
	}
	if len(path) > len(relPath) {
		path = relPath
	}
	const maxPathLen = 108
	if len(path) > maxPathLen {
		return "", fmt.Errorf("could not get socket path under length limit %d: %s", maxPathLen, path)
	}
	return path, nil
}

// createConsoleSocket creates a socket at the given path that will receive a
// console fd from the sandbox. If an error occurs, t.Fatalf will be called.
// The function returning should be deferred as cleanup.
func createConsoleSocket(t *testing.T, path string) (*unet.ServerSocket, func()) {
	t.Helper()
	srv, err := unet.BindAndListen(path, false)
	if err != nil {
		t.Fatalf("error binding and listening to socket %q: %v", path, err)
	}

	cleanup := func() {
		// Log errors; nothing can be done.
		if err := srv.Close(); err != nil {
			t.Logf("error closing socket %q: %v", path, err)
		}
		if err := os.Remove(path); err != nil {
			t.Logf("error removing socket %q: %v", path, err)
		}
	}

	return srv, cleanup
}

// receiveConsolePTY accepts a connection on the server socket and reads fds.
// It fails if more than one FD is received, or if the FD is not a PTY. It
// returns the PTY master file.
func receiveConsolePTY(srv *unet.ServerSocket) (*os.File, error) {
	sock, err := srv.Accept()
	if err != nil {
		return nil, fmt.Errorf("error accepting socket connection: %v", err)
	}

	// Allow 3 fds to be received.  We only expect 1.
	r := sock.Reader(true /* blocking */)
	r.EnableFDs(1)

	// The socket is closed right after sending the FD, so EOF is
	// an allowed error.
	b := [][]byte{{}}
	if _, err := r.ReadVec(b); err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading from socket connection: %v", err)
	}

	// We should have gotten a control message.
	fds, err := r.ExtractFDs()
	if err != nil {
		return nil, fmt.Errorf("error extracting fds from socket connection: %v", err)
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("got %d fds from socket, wanted 1", len(fds))
	}

	// Verify that the fd is a terminal.
	if _, err := unix.IoctlGetTermios(fds[0], unix.TCGETS); err != nil {
		return nil, fmt.Errorf("fd is not a terminal (ioctl TGGETS got %v)", err)
	}

	return os.NewFile(uintptr(fds[0]), "pty_master"), nil
}

// Test that an pty FD is sent over the console socket if one is provided.
func TestConsoleSocket(t *testing.T) {
	for name, conf := range configsWithVFS2(t, all...) {
		t.Run(name, func(t *testing.T) {
			spec := testutil.NewSpecWithArgs("true")
			spec.Process.Terminal = true
			_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer cleanup()

			sock, err := socketPath(bundleDir)
			if err != nil {
				t.Fatalf("error getting socket path: %v", err)
			}
			srv, cleanup := createConsoleSocket(t, sock)
			defer cleanup()

			// Create the container and pass the socket name.
			args := Args{
				ID:            testutil.RandomContainerID(),
				Spec:          spec,
				BundleDir:     bundleDir,
				ConsoleSocket: sock,
			}
			c, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			defer c.Destroy()

			// Make sure we get a console PTY.
			ptyMaster, err := receiveConsolePTY(srv)
			if err != nil {
				t.Fatalf("error receiving console FD: %v", err)
			}
			ptyMaster.Close()
		})
	}
}

// Test that job control signals work on a console created with "exec -ti".
func TestJobControlSignalExec(t *testing.T) {
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	conf := testutil.TestConfig(t)

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	// Create and start the container.
	args := Args{
		ID:        testutil.RandomContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	c, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Create a pty master/replica. The replica will be passed to the exec
	// process.
	ptyMaster, ptyReplica, err := pty.Open()
	if err != nil {
		t.Fatalf("error opening pty: %v", err)
	}
	defer ptyMaster.Close()
	defer ptyReplica.Close()

	// Exec bash and attach a terminal. Note that occasionally /bin/sh
	// may be a different shell or have a different configuration (such
	// as disabling interactive mode and job control). Since we want to
	// explicitly test interactive mode, use /bin/bash. See b/116981926.
	execArgs := &control.ExecArgs{
		Filename: "/bin/bash",
		// Don't let bash execute from profile or rc files, otherwise
		// our PID counts get messed up.
		Argv: []string{"/bin/bash", "--noprofile", "--norc"},
		// Pass the pty replica as FD 0, 1, and 2.
		FilePayload: urpc.FilePayload{
			Files: []*os.File{ptyReplica, ptyReplica, ptyReplica},
		},
		StdioIsPty: true,
	}

	pid, err := c.Execute(execArgs)
	if err != nil {
		t.Fatalf("error executing: %v", err)
	}
	if pid != 2 {
		t.Fatalf("exec got pid %d, wanted %d", pid, 2)
	}

	// Make sure all the processes are running.
	expectedPL := []*control.Process{
		// Root container process.
		{PID: 1, Cmd: "sleep", Threads: []kernel.ThreadID{1}},
		// Bash from exec process.
		{PID: 2, Cmd: "bash", Threads: []kernel.ThreadID{2}},
	}
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Error(err)
	}

	// Execute sleep.
	ptyMaster.Write([]byte("sleep 100\n"))

	// Wait for it to start. Sleep's PPID is bash's PID.
	expectedPL = append(expectedPL, &control.Process{PID: 3, PPID: 2, Cmd: "sleep", Threads: []kernel.ThreadID{3}})
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Error(err)
	}

	// Send a SIGTERM to the foreground process for the exec PID. Note that
	// although we pass in the PID of "bash", it should actually terminate
	// "sleep", since that is the foreground process.
	if err := c.Sandbox.SignalProcess(c.ID, pid, syscall.SIGTERM, true /* fgProcess */); err != nil {
		t.Fatalf("error signaling container: %v", err)
	}

	// Sleep process should be gone.
	expectedPL = expectedPL[:len(expectedPL)-1]
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Error(err)
	}

	// Sleep is dead, but it may take more time for bash to notice and
	// change the foreground process back to itself. We know it is done
	// when bash writes "Terminated" to the pty.
	if err := testutil.WaitUntilRead(ptyMaster, "Terminated", nil, 5*time.Second); err != nil {
		t.Fatalf("bash did not take over pty: %v", err)
	}

	// Send a SIGKILL to the foreground process again. This time "bash"
	// should be killed. We use SIGKILL instead of SIGTERM or SIGINT
	// because bash ignores those.
	if err := c.Sandbox.SignalProcess(c.ID, pid, syscall.SIGKILL, true /* fgProcess */); err != nil {
		t.Fatalf("error signaling container: %v", err)
	}
	expectedPL = expectedPL[:1]
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Error(err)
	}

	// Make sure the process indicates it was killed by a SIGKILL.
	ws, err := c.WaitPID(pid)
	if err != nil {
		t.Errorf("waiting on container failed: %v", err)
	}
	if !ws.Signaled() {
		t.Error("ws.Signaled() got false, want true")
	}
	if got, want := ws.Signal(), syscall.SIGKILL; got != want {
		t.Errorf("ws.Signal() got %v, want %v", got, want)
	}
}

// Test that job control signals work on a console created with "run -ti".
func TestJobControlSignalRootContainer(t *testing.T) {
	conf := testutil.TestConfig(t)
	// Don't let bash execute from profile or rc files, otherwise our PID
	// counts get messed up.
	spec := testutil.NewSpecWithArgs("/bin/bash", "--noprofile", "--norc")
	spec.Process.Terminal = true

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer cleanup()

	sock, err := socketPath(bundleDir)
	if err != nil {
		t.Fatalf("error getting socket path: %v", err)
	}
	srv, cleanup := createConsoleSocket(t, sock)
	defer cleanup()

	// Create the container and pass the socket name.
	args := Args{
		ID:            testutil.RandomContainerID(),
		Spec:          spec,
		BundleDir:     bundleDir,
		ConsoleSocket: sock,
	}
	c, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()

	// Get the PTY master.
	ptyMaster, err := receiveConsolePTY(srv)
	if err != nil {
		t.Fatalf("error receiving console FD: %v", err)
	}
	defer ptyMaster.Close()

	// Bash output as well as sandbox output will be written to the PTY
	// file. Writes after a certain point will block unless we drain the
	// PTY, so we must continually copy from it.
	//
	// We log the output to stderr for debugabilitly, and also to a buffer,
	// since we wait on particular output from bash below. We use a custom
	// blockingBuffer which is thread-safe and also blocks on Read calls,
	// which makes this a suitable Reader for WaitUntilRead.
	ptyBuf := newBlockingBuffer()
	tee := io.TeeReader(ptyMaster, ptyBuf)
	go io.Copy(os.Stderr, tee)

	// Start the container.
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// Start waiting for the container to exit in a goroutine. We do this
	// very early, otherwise it might exit before we have a chance to call
	// Wait.
	var (
		ws syscall.WaitStatus
		wg sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		var err error
		ws, err = c.Wait()
		if err != nil {
			t.Errorf("error waiting on container: %v", err)
		}
		wg.Done()
	}()

	// Wait for bash to start.
	expectedPL := []*control.Process{
		{PID: 1, Cmd: "bash", Threads: []kernel.ThreadID{1}},
	}
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Fatalf("error waiting for processes: %v", err)
	}

	// Execute sleep via the terminal.
	ptyMaster.Write([]byte("sleep 100\n"))

	// Wait for sleep to start.
	expectedPL = append(expectedPL, &control.Process{PID: 2, PPID: 1, Cmd: "sleep", Threads: []kernel.ThreadID{2}})
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Fatalf("error waiting for processes: %v", err)
	}

	// Reset the pty buffer, so there is less output for us to scan later.
	ptyBuf.Reset()

	// Send a SIGTERM to the foreground process. We pass PID=0, indicating
	// that the root process should be killed. However, by setting
	// fgProcess=true, the signal should actually be sent to sleep.
	if err := c.Sandbox.SignalProcess(c.ID, 0 /* PID */, syscall.SIGTERM, true /* fgProcess */); err != nil {
		t.Fatalf("error signaling container: %v", err)
	}

	// Sleep process should be gone.
	expectedPL = expectedPL[:len(expectedPL)-1]
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Error(err)
	}

	// Sleep is dead, but it may take more time for bash to notice and
	// change the foreground process back to itself. We know it is done
	// when bash writes "Terminated" to the pty.
	if err := testutil.WaitUntilRead(ptyBuf, "Terminated", nil, 5*time.Second); err != nil {
		t.Fatalf("bash did not take over pty: %v", err)
	}

	// Send a SIGKILL to the foreground process again. This time "bash"
	// should be killed. We use SIGKILL instead of SIGTERM or SIGINT
	// because bash ignores those.
	if err := c.Sandbox.SignalProcess(c.ID, 0 /* PID */, syscall.SIGKILL, true /* fgProcess */); err != nil {
		t.Fatalf("error signaling container: %v", err)
	}

	// Wait for the sandbox to exit. It should exit with a SIGKILL status.
	wg.Wait()
	if !ws.Signaled() {
		t.Error("ws.Signaled() got false, want true")
	}
	if got, want := ws.Signal(), syscall.SIGKILL; got != want {
		t.Errorf("ws.Signal() got %v, want %v", got, want)
	}
}

// blockingBuffer is a thread-safe buffer that blocks when reading if the
// buffer is empty.  It implements io.ReadWriter.
type blockingBuffer struct {
	// A send to readCh indicates that a previously empty buffer now has
	// data for reading.
	readCh chan struct{}

	// mu protects buf.
	mu  sync.Mutex
	buf bytes.Buffer
}

func newBlockingBuffer() *blockingBuffer {
	return &blockingBuffer{
		readCh: make(chan struct{}, 1),
	}
}

// Write implements Writer.Write.
func (bb *blockingBuffer) Write(p []byte) (int, error) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	l := bb.buf.Len()
	n, err := bb.buf.Write(p)
	if l == 0 && n > 0 {
		// New data!
		bb.readCh <- struct{}{}
	}
	return n, err
}

// Read implements Reader.Read. It will block until data is available.
func (bb *blockingBuffer) Read(p []byte) (int, error) {
	for {
		bb.mu.Lock()
		n, err := bb.buf.Read(p)
		if n > 0 || err != io.EOF {
			if bb.buf.Len() == 0 {
				// Reset the readCh.
				select {
				case <-bb.readCh:
				default:
				}
			}
			bb.mu.Unlock()
			return n, err
		}
		bb.mu.Unlock()

		// Wait for new data.
		<-bb.readCh
	}
}

// Reset resets the buffer.
func (bb *blockingBuffer) Reset() {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	bb.buf.Reset()
	// Reset the readCh.
	select {
	case <-bb.readCh:
	default:
	}
}
