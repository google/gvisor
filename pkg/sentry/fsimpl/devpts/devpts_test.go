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

package devpts

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestSimpleMasterToReplica(t *testing.T) {
	ld := newLineDiscipline(linux.DefaultReplicaTermios, nil)
	ctx := contexttest.Context(t)
	inBytes := []byte("hello, tty\n")
	src := usermem.BytesIOSequence(inBytes)
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)

	// Write to the input queue.
	nw, err := ld.inputQueueWrite(ctx, src)
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err := ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != int64(len(inBytes)) {
		t.Fatalf("read wrong length: got %d, want %d", nr, len(inBytes))
	}

	outStr := string(outBytes[:nr])
	inStr := string(inBytes)
	if outStr != inStr {
		t.Fatalf("written and read strings do not match: got %q, want %q", outStr, inStr)
	}
}

func TestEchoDeadlock(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	termios.LocalFlags |= linux.ECHO
	ld := newLineDiscipline(termios, nil)
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)
	entry := waiter.NewFunctionEntry(waiter.ReadableEvents, func(waiter.EventMask) {
		// Read synchronously without notifying this waiter queue again.
		ld.termiosMu.RLock()
		defer ld.termiosMu.RUnlock()
		_, _, _, _ = ld.inQueue.read(ctx, dst, ld, false /* packet */)
	})
	ld.masterWaiter.EventRegister(&entry)
	defer ld.masterWaiter.EventUnregister(&entry)
	inBytes := []byte("hello, tty\n")
	n, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("inputQueueWrite: %v", err)
	}
	if int(n) != len(inBytes) {
		t.Fatalf("read wrong length: got %d, want %d", n, len(inBytes))
	}
	outStr := string(outBytes[:n])
	inStr := string(inBytes)
	if outStr != inStr {
		t.Fatalf("written and read strings do not match: got %q, want %q", outStr, inStr)
	}
}

func TestEndOfFileHandling(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	ld := newLineDiscipline(termios, nil)

	// EOF with non-empty read buffer.
	inBytes := []byte("hello, tty")
	inBytes = append(inBytes, termios.ControlCharacters[linux.VEOF])
	outBytes := make([]byte, 32)
	dst := usermem.BytesIOSequence(outBytes)
	// Write to the input queue.
	nw, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err := ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != int64(len(inBytes)-1) {
		t.Fatalf("read wrong length: got %d, want %d", nr, len(inBytes)-1)
	}

	// EOF with empty read buffer.
	inBytes = []byte{termios.ControlCharacters[linux.VEOF]}
	outBytes = make([]byte, 32)
	dst = usermem.BytesIOSequence(outBytes)
	// Write to the input queue.
	nw, err = ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inBytes))
	if err != nil {
		t.Fatalf("error writing to input queue: %v", err)
	}
	if nw != int64(len(inBytes)) {
		t.Fatalf("wrote wrong length: got %d, want %d", nw, len(inBytes))
	}

	// Read from the input queue.
	nr, err = ld.inputQueueRead(ctx, dst)
	if err != nil {
		t.Fatalf("error reading from input queue: %v", err)
	}
	if nr != 0 {
		t.Fatalf("read length should be zero: got %d", nr)
	}
}

// The mode and gid mount options name the mode and group of replicas, not of
// the root directory, which keeps a fixed mode. See
// fs/devpts/inode.c:devpts_fill_super() and fs/devpts/inode.c:devpts_pty_new().
func TestReplicaModeAndOwner(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)

	for _, test := range []struct {
		name     string
		opts     fileSystemOpts
		wantMode linux.FileMode
		wantGID  auth.KGID
	}{
		{
			name:     "replica takes mode and gid from the mount options",
			opts:     fileSystemOpts{mode: 0620, gid: auth.KGID(5), setgid: true},
			wantMode: 0620,
			wantGID:  auth.KGID(5),
		},
		{
			name:     "replica falls back to the creating process without gid",
			opts:     fileSystemOpts{mode: 0620},
			wantMode: 0620,
			wantGID:  creds.EffectiveKGID,
		},
		{
			// The mode option names replicas, so its default is the one Linux
			// gives them rather than the one it gives the root directory.
			name:     "replica takes 0600 without the mode option",
			opts:     fileSystemOpts{mode: defaultReplicaMode},
			wantMode: 0600,
			wantGID:  creds.EffectiveKGID,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := &rootInode{
				opts:     test.opts,
				replicas: make(map[uint32]*replicaInode),
			}
			root.InodeAttrs.InitWithIDs(ctx, test.opts.uid, test.opts.gid, linux.UNNAMED_MAJOR, 0 /* devMinor */, 1, linux.ModeDirectory|rootMode)

			term, err := root.allocateTerminal(ctx, creds)
			if err != nil {
				t.Fatalf("allocateTerminal: %v", err)
			}
			replica, ok := root.replicas[term.n]
			if !ok {
				t.Fatalf("no replica for terminal %d", term.n)
			}

			if got := replica.InodeAttrs.Mode().Permissions(); got != test.wantMode {
				t.Errorf("replica mode: got %#o, want %#o", got, test.wantMode)
			}
			if got := replica.InodeAttrs.GID(); got != test.wantGID {
				t.Errorf("replica gid: got %d, want %d", got, test.wantGID)
			}
			if got := root.InodeAttrs.Mode().Permissions(); got != rootMode {
				t.Errorf("root mode: got %#o, want %#o", got, rootMode)
			}
		})
	}
}

func TestOutputQueueEchoRespectsWaitBufMaxBytes(t *testing.T) {
	ctx := contexttest.Context(t)
	termios := linux.DefaultReplicaTermios
	termios.LocalFlags |= linux.ECHO
	ld := newLineDiscipline(termios, nil)

	// Fill outQueue.readBuf to nonCanonMaxBytes, then fill outQueue.waitBuf to
	// waitBufMaxBytes.
	readBufFill := bytes.Repeat([]byte("a"), nonCanonMaxBytes)
	if n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence(readBufFill)); err != nil || n != int64(len(readBufFill)) {
		t.Fatalf("outputQueueWrite(readBufFill): got (%d, %v), want (%d, nil)", n, err, len(readBufFill))
	}
	waitBufFill := bytes.Repeat([]byte("b"), waitBufMaxBytes)
	if n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence(waitBufFill)); err != nil || n != int64(len(waitBufFill)) {
		t.Fatalf("outputQueueWrite(waitBufFill): got (%d, %v), want (%d, nil)", n, err, len(waitBufFill))
	}

	ld.outQueue.mu.Lock()
	gotWaitLen := ld.outQueue.waitBufLen
	ld.outQueue.mu.Unlock()
	if gotWaitLen != waitBufMaxBytes {
		t.Fatalf("outQueue.waitBufLen before echo: got %d, want %d", gotWaitLen, waitBufMaxBytes)
	}

	// Echoing master input onto a full output queue must not push waitBufLen
	// past waitBufMaxBytes.
	if _, err := ld.inputQueueWrite(ctx, usermem.BytesIOSequence([]byte("exit\r"))); err != nil {
		t.Fatalf("inputQueueWrite: %v", err)
	}

	ld.outQueue.mu.Lock()
	gotWaitLen = ld.outQueue.waitBufLen
	ld.outQueue.mu.Unlock()
	if gotWaitLen > waitBufMaxBytes {
		t.Fatalf("outQueue.waitBufLen after echo: got %d, want <= %d", gotWaitLen, waitBufMaxBytes)
	}

	// Subsequent replica writes must block instead of underflowing room.
	n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence(bytes.Repeat([]byte("c"), 4096)))
	if !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || n != 0 {
		t.Fatalf("outputQueueWrite on full queue after echo: got (%d, %v), want (0, ErrWouldBlock)", n, err)
	}
	ld.outQueue.mu.Lock()
	gotWaitLen = ld.outQueue.waitBufLen
	ld.outQueue.mu.Unlock()
	if gotWaitLen > waitBufMaxBytes {
		t.Fatalf("outQueue.waitBufLen after blocked write: got %d, want <= %d", gotWaitLen, waitBufMaxBytes)
	}
}

func TestQueueWriteWaitBufOverflowGuard(t *testing.T) {
	ctx := contexttest.Context(t)
	ld := newLineDiscipline(linux.DefaultReplicaTermios, nil)

	ld.outQueue.mu.Lock()
	ld.outQueue.waitBufLen = waitBufMaxBytes + 5
	ld.outQueue.mu.Unlock()

	n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence([]byte("hello")))
	if !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || n != 0 {
		t.Fatalf("outputQueueWrite with waitBufLen > waitBufMaxBytes: got (%d, %v), want (0, ErrWouldBlock)", n, err)
	}

	ld.outQueue.mu.Lock()
	gotWaitLen := ld.outQueue.waitBufLen
	ld.outQueue.mu.Unlock()
	if gotWaitLen != waitBufMaxBytes+5 {
		t.Fatalf("outQueue.waitBufLen changed on ErrWouldBlock: got %d, want %d", gotWaitLen, waitBufMaxBytes+5)
	}

	// Zero-length writes return (0, nil) even when waitBuf is full.
	if n, err := ld.outputQueueWrite(ctx, usermem.BytesIOSequence(nil)); err != nil || n != 0 {
		t.Fatalf("zero-length outputQueueWrite: got (%d, %v), want (0, nil)", n, err)
	}
}

func TestMasterCloseFlushesAndReturnsEIO(t *testing.T) {
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	root := &rootInode{
		opts:     fileSystemOpts{mode: defaultReplicaMode},
		replicas: make(map[uint32]*replicaInode),
	}
	root.InodeAttrs.InitWithIDs(ctx, root.opts.uid, root.opts.gid, linux.UNNAMED_MAJOR, 0 /* devMinor */, 1, linux.ModeDirectory|rootMode)

	term, err := root.allocateTerminal(ctx, creds)
	if err != nil {
		t.Fatalf("allocateTerminal: %v", err)
	}

	// Populate both readBuf and waitBuf of outQueue.
	data := bytes.Repeat([]byte("x"), nonCanonMaxBytes+4096)
	if n, err := term.ld.outputQueueWrite(ctx, usermem.BytesIOSequence(data)); err != nil || n != int64(len(data)) {
		t.Fatalf("outputQueueWrite before close: got (%d, %v), want (%d, nil)", n, err, len(data))
	}

	var notifiedEvents waiter.EventMask
	entry := waiter.NewFunctionEntry(waiter.EventHUp|waiter.EventErr|waiter.ReadableEvents|waiter.WritableEvents, func(mask waiter.EventMask) {
		notifiedEvents |= mask
	})
	term.ld.replicaWaiter.EventRegister(&entry)
	defer term.ld.replicaWaiter.EventUnregister(&entry)

	root.masterClose(ctx, term)

	term.ld.outQueue.mu.Lock()
	gotWaitLen := term.ld.outQueue.waitBufLen
	gotReadLen := len(term.ld.outQueue.readBuf)
	gotWaitChunks := len(term.ld.outQueue.waitBuf)
	term.ld.outQueue.mu.Unlock()
	if gotWaitLen != 0 || gotReadLen != 0 || gotWaitChunks != 0 {
		t.Fatalf("outQueue not flushed after masterClose: waitBufLen=%d readBuf=%d waitBuf=%d", gotWaitLen, gotReadLen, gotWaitChunks)
	}

	wantMask := waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents
	if notifiedEvents&wantMask != wantMask {
		t.Fatalf("replicaWaiter notified events: got %#x, want all bits of %#x", notifiedEvents, wantMask)
	}
	if readiness := term.ld.replicaReadiness(); readiness&wantMask != wantMask {
		t.Fatalf("replicaReadiness after masterClose: got %#x, want all bits of %#x", readiness, wantMask)
	}

	if n, err := term.ld.outputQueueWrite(ctx, usermem.BytesIOSequence([]byte("after close"))); !linuxerr.Equals(linuxerr.EIO, err) || n != 0 {
		t.Fatalf("outputQueueWrite after masterClose: got (%d, %v), want (0, EIO)", n, err)
	}
	term.ld.outQueue.mu.Lock()
	gotWaitLen = term.ld.outQueue.waitBufLen
	gotReadLen = len(term.ld.outQueue.readBuf)
	term.ld.outQueue.mu.Unlock()
	if gotWaitLen != 0 || gotReadLen != 0 {
		t.Fatalf("outQueue grew after masterClose write: waitBufLen=%d readBuf=%d", gotWaitLen, gotReadLen)
	}

	if n, err := term.ld.inputQueueRead(ctx, usermem.BytesIOSequence(make([]byte, 16))); err != nil || n != 0 {
		t.Fatalf("inputQueueRead after masterClose: got (%d, %v), want (0, nil)", n, err)
	}
}
