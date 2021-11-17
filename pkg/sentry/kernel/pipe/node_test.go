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

package pipe

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

type openResult struct {
	*fs.File
	error
}

var perms fs.FilePermissions = fs.FilePermissions{
	User: fs.PermMask{Read: true, Write: true},
}

func testOpenOrDie(ctx context.Context, t *testing.T, n fs.InodeOperations, flags fs.FileFlags, doneChan chan<- struct{}) (*fs.File, error) {
	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{Type: fs.Pipe})
	d := fs.NewDirent(ctx, inode, "pipe")
	file, err := n.GetFile(ctx, d, flags)
	if err != nil {
		t.Errorf("open with flags %+v failed: %v", flags, err)
		return nil, err
	}
	if doneChan != nil {
		doneChan <- struct{}{}
	}
	return file, err
}

func testOpen(ctx context.Context, t *testing.T, n fs.InodeOperations, flags fs.FileFlags, resChan chan<- openResult) (*fs.File, error) {
	inode := fs.NewMockInode(ctx, fs.NewMockMountSource(nil), fs.StableAttr{Type: fs.Pipe})
	d := fs.NewDirent(ctx, inode, "pipe")
	file, err := n.GetFile(ctx, d, flags)
	if resChan != nil {
		resChan <- openResult{file, err}
	}
	return file, err
}

func newNamedPipe(t *testing.T) *Pipe {
	return NewPipe(true, DefaultPipeSize)
}

func newAnonPipe(t *testing.T) *Pipe {
	return NewPipe(false, DefaultPipeSize)
}

// assertRecvBlocks ensures that a recv attempt on c blocks for at least
// blockDuration. This is useful for checking that a goroutine that is supposed
// to be executing a blocking operation is actually blocking.
func assertRecvBlocks(t *testing.T, c <-chan struct{}, blockDuration time.Duration, failMsg string) {
	t.Helper()
	select {
	case <-c:
		t.Fatalf(failMsg)
	case <-time.After(blockDuration):
		// Ok, blocked for the required duration.
	}
}

func TestReadOpenBlocksForWriteOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone)

	// Verify that the open for read is blocking.
	assertRecvBlocks(t, rDone, time.Millisecond*100,
		"open for read not blocking with no writers")

	wDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)

	<-wDone
	<-rDone
}

func TestWriteOpenBlocksForReadOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	wDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)

	// Verify that the open for write is blocking
	assertRecvBlocks(t, wDone, time.Millisecond*100,
		"open for write not blocking with no readers")

	rDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone)

	<-rDone
	<-wDone
}

func TestMultipleWriteOpenDoesntCountAsReadOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rDone1 := make(chan struct{})
	rDone2 := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone1)
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone2)

	assertRecvBlocks(t, rDone1, time.Millisecond*100,
		"open for read didn't block with no writers")
	assertRecvBlocks(t, rDone2, time.Millisecond*100,
		"open for read didn't block with no writers")

	wDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)

	<-wDone
	<-rDone2
	<-rDone1
}

func TestClosedReaderBlocksWriteOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rFile, _ := testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true, NonBlocking: true}, nil)
	rFile.DecRef(ctx)

	wDone := make(chan struct{})
	// This open for write should block because the reader is now gone.
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)
	assertRecvBlocks(t, wDone, time.Millisecond*100,
		"open for write didn't block with no concurrent readers")

	// Open for read again. This should unblock the open for write.
	rDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone)

	<-rDone
	<-wDone
}

func TestReadWriteOpenNeverBlocks(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rwDone := make(chan struct{})
	// Open for read-write never wait for a reader or writer, even if the
	// nonblocking flag is not set.
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true, Write: true, NonBlocking: false}, rwDone)
	<-rwDone
}

func TestReadWriteOpenUnblocksReadOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone)

	rwDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true, Write: true}, rwDone)

	<-rwDone
	<-rDone
}

func TestReadWriteOpenUnblocksWriteOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	wDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)

	rwDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true, Write: true}, rwDone)

	<-rwDone
	<-wDone
}

func TestBlockedOpenIsCancellable(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	done := make(chan openResult)
	go testOpen(ctx, t, f, fs.FileFlags{Read: true}, done)
	select {
	case <-done:
		t.Fatalf("open for read didn't block with no writers")
	case <-time.After(time.Millisecond * 100):
		// Ok.
	}

	ctx.Interrupt()

	// If the cancel on the sleeper didn't work, the open for read would never
	// return.
	res := <-done
	if res.error != linuxerr.ErrInterrupted {
		t.Fatalf("Cancellation didn't cause GetFile to return fs.ErrInterrupted, got %v.",
			res.error)
	}
}

func TestNonblockingReadOpenFileNoWriters(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Read: true, NonBlocking: true}, nil); err != nil {
		t.Fatalf("Nonblocking open for read failed with error %v.", err)
	}
}

func TestNonblockingWriteOpenFileNoReaders(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Write: true, NonBlocking: true}, nil); !linuxerr.Equals(linuxerr.ENXIO, err) {
		t.Fatalf("Nonblocking open for write failed unexpected error %v.", err)
	}
}

func TestNonBlockingReadOpenWithWriter(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	wDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Write: true}, wDone)

	// Open for write blocks since there are no readers yet.
	assertRecvBlocks(t, wDone, time.Millisecond*100,
		"Open for write didn't block with no reader.")

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Read: true, NonBlocking: true}, nil); err != nil {
		t.Fatalf("Nonblocking open for read failed with error %v.", err)
	}

	// Open for write should now be unblocked.
	<-wDone
}

func TestNonBlockingWriteOpenWithReader(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newNamedPipe(t))

	rDone := make(chan struct{})
	go testOpenOrDie(ctx, t, f, fs.FileFlags{Read: true}, rDone)

	// Open for write blocked, since no reader yet.
	assertRecvBlocks(t, rDone, time.Millisecond*100,
		"Open for reader didn't block with no writer.")

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Write: true, NonBlocking: true}, nil); err != nil {
		t.Fatalf("Nonblocking open for write failed with error %v.", err)
	}

	// Open for write should now be unblocked.
	<-rDone
}

func TestAnonReadOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newAnonPipe(t))

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Read: true}, nil); err != nil {
		t.Fatalf("open anon pipe for read failed: %v", err)
	}
}

func TestAnonWriteOpen(t *testing.T) {
	ctx := contexttest.Context(t)
	f := NewInodeOperations(ctx, perms, newAnonPipe(t))

	if _, err := testOpen(ctx, t, f, fs.FileFlags{Write: true}, nil); err != nil {
		t.Fatalf("open anon pipe for write failed: %v", err)
	}
}
