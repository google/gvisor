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

package tty

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

func TestSimpleMasterToSlave(t *testing.T) {
	ld := newLineDiscipline(linux.DefaultSlaveTermios)
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
