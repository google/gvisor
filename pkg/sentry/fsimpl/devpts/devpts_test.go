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
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

func TestSimpleMasterToReplica(t *testing.T) {
	ld := newLineDiscipline(linux.DefaultReplicaTermios)
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
	ld := newLineDiscipline(termios)
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
