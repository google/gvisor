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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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

// newIndexTestRoot creates a virtual devpts mount for allocator invariants.
func newIndexTestRoot(t *testing.T) (context.Context, vfs.VirtualDentry, *rootInode) {
	t.Helper()
	ctx := contexttest.Context(t)
	creds := auth.CredentialsFromContext(ctx)
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VFS.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(Name, &FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{Data: "newinstance"},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	vd := mntns.Root(ctx)
	t.Cleanup(func() {
		vd.DecRef(ctx)
		mntns.DecRef(ctx)
	})
	root := vd.Dentry().Impl().(*kernfs.Dentry).Inode().(*rootInode)
	return ctx, vd, root
}

func indexTestTerminal(t *testing.T, ctx context.Context, root *rootInode) *Terminal {
	t.Helper()
	term, err := root.allocateTerminal(ctx, auth.CredentialsFromContext(ctx))
	if err != nil {
		t.Fatalf("allocateTerminal: %v", err)
	}
	t.Cleanup(func() {
		root.mu.Lock()
		replica := root.replicas[term.n]
		live := replica != nil && replica.t == term
		root.mu.Unlock()
		if live {
			root.masterClose(ctx, term)
		}
	})
	return term
}

func indexTestExternal(t *testing.T, ctx context.Context, vd vfs.VirtualDentry) *ExternalReplica {
	t.Helper()
	er, err := AddExternalReplica(ctx, vd, auth.CredentialsFromContext(ctx), kernel.NewTTY(0, nil))
	if err != nil {
		t.Fatalf("AddExternalReplica: %v", err)
	}
	t.Cleanup(func() { er.Remove(ctx) })
	return er
}

func TestMixedInternalAndExternalIndexReservations(t *testing.T) {
	ctx, vd, root := newIndexTestRoot(t)
	first := indexTestTerminal(t, ctx, root)
	external := indexTestExternal(t, ctx, vd)
	if first.n != 0 || external.Index() != 1 {
		t.Fatalf("initial indices: internal=%d, external=%d", first.n, external.Index())
	}
	root.masterClose(ctx, first)
	reused := indexTestTerminal(t, ctx, root)
	next := indexTestTerminal(t, ctx, root)
	if reused.n != 0 || next.n != 2 {
		t.Errorf("mixed allocation reused=%d, next=%d; want 0,2", reused.n, next.n)
	}
	root.mu.Lock()
	owner := root.externals[external.n]
	refs := root.allocated[external.n]
	root.mu.Unlock()
	if owner != external || refs != 1 {
		t.Errorf("external reservation changed: owner=%p, refs=%d", owner, refs)
	}
}

func TestRepeatedExternalRemovePreservesReusedIndex(t *testing.T) {
	for _, externalReplacement := range []bool{false, true} {
		t.Run(map[bool]string{false: "internal", true: "external"}[externalReplacement], func(t *testing.T) {
			ctx, vd, root := newIndexTestRoot(t)
			old := indexTestExternal(t, ctx, vd)
			old.Remove(ctx)
			var index uint32
			if externalReplacement {
				current := indexTestExternal(t, ctx, vd)
				index = current.Index()
				device := current.tty.DeviceID()
				old.Remove(ctx)
				if current.tty.DeviceID() != device {
					t.Errorf("repeated Remove changed replacement device ID")
				}
				root.mu.Lock()
				live := root.externals[index] == current
				root.mu.Unlock()
				if !live {
					t.Errorf("repeated Remove deleted replacement")
				}
			} else {
				current := indexTestTerminal(t, ctx, root)
				index = current.n
				old.Remove(ctx)
				root.mu.Lock()
				live := root.replicas[index] != nil && root.replicas[index].t == current
				root.mu.Unlock()
				if !live {
					t.Errorf("repeated Remove deleted replacement")
				}
			}
			if index != 0 {
				t.Fatalf("replacement index=%d, want 0", index)
			}
			next := indexTestTerminal(t, ctx, root)
			if next.n != 1 {
				t.Errorf("next index=%d, want 1", next.n)
			}
		})
	}
}

func TestFreeIndexHeapRebuild(t *testing.T) {
	ctx, _, root := newIndexTestRoot(t)
	terms := make([]*Terminal, 8)
	for i := range terms {
		terms[i] = indexTestTerminal(t, ctx, root)
	}
	for _, i := range []int{6, 1, 4} {
		root.masterClose(ctx, terms[i])
	}
	root.mu.Lock()
	root.freeIndices = nil
	root.mu.Unlock()
	root.afterLoad(ctx)
	for _, want := range []uint32{1, 4, 6} {
		term := indexTestTerminal(t, ctx, root)
		if term.n != want {
			t.Errorf("rebuilt allocation=%d, want %d", term.n, want)
		}
	}
}
