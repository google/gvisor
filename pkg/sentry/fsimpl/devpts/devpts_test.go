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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
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
		ld.inputQueueRead(ctx, dst)
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
			opts:     fileSystemOpts{mode: 0600},
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
