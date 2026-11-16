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
	if term.ld.isMasterClosed() {
		t.Fatalf("isMasterClosed before masterClose: got true, want false")
	}
	if err := term.ld.replicaOpen(); err != nil {
		t.Fatalf("replicaOpen before masterClose: got %v, want nil", err)
	}

	// Populate both readBuf and waitBuf of inQueue (in canonical mode, the
	// first line fills readBuf and marks it readable while the second stays in
	// waitBuf).
	inData := []byte("line1\nline2\n")
	if n, err := term.ld.inputQueueWrite(ctx, usermem.BytesIOSequence(inData)); err != nil || n != int64(len(inData)) {
		t.Fatalf("inputQueueWrite before close: got (%d, %v), want (%d, nil)", n, err, len(inData))
	}
	term.ld.inQueue.mu.Lock()
	inWaitLenBefore := term.ld.inQueue.waitBufLen
	inReadLenBefore := len(term.ld.inQueue.readBuf)
	inWaitChunksBefore := len(term.ld.inQueue.waitBuf)
	term.ld.inQueue.mu.Unlock()
	if inWaitLenBefore == 0 || inReadLenBefore == 0 || inWaitChunksBefore == 0 {
		t.Fatalf("inQueue before masterClose: got (waitBufLen=%d, len(readBuf)=%d, len(waitBuf)=%d), want all non-zero", inWaitLenBefore, inReadLenBefore, inWaitChunksBefore)
	}

	// Populate both readBuf and waitBuf of outQueue.
	outData := bytes.Repeat([]byte("x"), nonCanonMaxBytes+4096)
	if n, err := term.ld.outputQueueWrite(ctx, usermem.BytesIOSequence(outData)); err != nil || n != int64(len(outData)) {
		t.Fatalf("outputQueueWrite before close: got (%d, %v), want (%d, nil)", n, err, len(outData))
	}
	term.ld.outQueue.mu.Lock()
	outWaitLenBefore := term.ld.outQueue.waitBufLen
	outReadLenBefore := len(term.ld.outQueue.readBuf)
	outWaitChunksBefore := len(term.ld.outQueue.waitBuf)
	term.ld.outQueue.mu.Unlock()
	if outWaitLenBefore == 0 || outReadLenBefore == 0 || outWaitChunksBefore == 0 {
		t.Fatalf("outQueue before masterClose: got (waitBufLen=%d, len(readBuf)=%d, len(waitBuf)=%d), want all non-zero", outWaitLenBefore, outReadLenBefore, outWaitChunksBefore)
	}

	var notifiedEvents waiter.EventMask
	entry := waiter.NewFunctionEntry(waiter.EventHUp|waiter.EventErr|waiter.ReadableEvents|waiter.WritableEvents, func(mask waiter.EventMask) {
		notifiedEvents |= mask
	})
	term.ld.replicaWaiter.EventRegister(&entry)
	defer term.ld.replicaWaiter.EventUnregister(&entry)

	root.masterClose(ctx, term)

	root.mu.Lock()
	_, replicaStillPresent := root.replicas[term.n]
	root.mu.Unlock()
	if replicaStillPresent {
		t.Errorf("root.replicas[%d] still present after masterClose: got true, want false", term.n)
	}

	term.ld.inQueue.mu.Lock()
	gotInWaitLen := term.ld.inQueue.waitBufLen
	gotInReadLen := len(term.ld.inQueue.readBuf)
	gotInWaitChunks := len(term.ld.inQueue.waitBuf)
	term.ld.inQueue.mu.Unlock()
	if gotInWaitLen != 0 || gotInReadLen != 0 || gotInWaitChunks != 0 {
		t.Errorf("inQueue after masterClose: got (%d, %d, %d), want (0, 0, 0) for (waitBufLen, len(readBuf), len(waitBuf))", gotInWaitLen, gotInReadLen, gotInWaitChunks)
	}

	term.ld.outQueue.mu.Lock()
	gotOutWaitLen := term.ld.outQueue.waitBufLen
	gotOutReadLen := len(term.ld.outQueue.readBuf)
	gotOutWaitChunks := len(term.ld.outQueue.waitBuf)
	term.ld.outQueue.mu.Unlock()
	if gotOutWaitLen != 0 || gotOutReadLen != 0 || gotOutWaitChunks != 0 {
		t.Errorf("outQueue after masterClose: got (%d, %d, %d), want (0, 0, 0) for (waitBufLen, len(readBuf), len(waitBuf))", gotOutWaitLen, gotOutReadLen, gotOutWaitChunks)
	}

	wantMask := waiter.EventHUp | waiter.EventErr | waiter.ReadableEvents | waiter.WritableEvents
	if notifiedEvents&wantMask != wantMask {
		t.Errorf("replicaWaiter notified events: got %#x, want all bits of %#x", notifiedEvents, wantMask)
	}
	if readiness := term.ld.replicaReadiness(); readiness&wantMask != wantMask {
		t.Errorf("replicaReadiness after masterClose: got %#x, want all bits of %#x", readiness, wantMask)
	}

	if n, err := term.ld.outputQueueWrite(ctx, usermem.BytesIOSequence([]byte("after close"))); !linuxerr.Equals(linuxerr.EIO, err) || n != 0 {
		t.Errorf("outputQueueWrite after masterClose: got (%d, %v), want (0, EIO)", n, err)
	}
	term.ld.outQueue.mu.Lock()
	gotOutWaitLen = term.ld.outQueue.waitBufLen
	gotOutReadLen = len(term.ld.outQueue.readBuf)
	term.ld.outQueue.mu.Unlock()
	if gotOutWaitLen != 0 || gotOutReadLen != 0 {
		t.Errorf("outQueue after masterClose write: got (%d, %d), want (0, 0) for (waitBufLen, len(readBuf))", gotOutWaitLen, gotOutReadLen)
	}

	if n, err := term.ld.inputQueueRead(ctx, usermem.BytesIOSequence(make([]byte, 16))); err != nil || n != 0 {
		t.Errorf("inputQueueRead after masterClose: got (%d, %v), want (0, nil)", n, err)
	}

	if !term.ld.isMasterClosed() {
		t.Errorf("isMasterClosed after masterClose: got false, want true")
	}
	if err := term.ld.replicaOpen(); !linuxerr.Equals(linuxerr.EIO, err) {
		t.Errorf("replicaOpen after masterClose: got %v, want EIO", err)
	}
	term.ld.termiosMu.RLock()
	gotNumReplicas := term.ld.numReplicas
	term.ld.termiosMu.RUnlock()
	if gotNumReplicas != 1 {
		t.Errorf("numReplicas after failed replicaOpen: got %d, want 1", gotNumReplicas)
	}
}
