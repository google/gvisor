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

//go:build darwin && arm64
// +build darwin,arm64

package gvunix

import (
	"log"
	"os"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func TestSigactionNonzero(t *testing.T) {
	if libc_sigaction_trampoline_addr == 0 {
		t.Fatalf("expected nonzero libc_sigaction_trampoline_addr, but found 0")
	}
}

const inc = 343

var value int32

// TODO: Might need an addrOfHandler.

func handler() {
	atomic.AddInt32(&value, inc)
	log.Printf("hi!")
}

func TestSigaction(t *testing.T) {
	// Set the signal handler. The specific mask and flags aren't important --
	// they're just used for comparison later on.
	mask := SigactionMask{
		SIGHUP: true,
		SIGINT: true,
	}
	flags := SigactionFlags{
		NoDefer: true,
		Restart: true,
	}
	sa := SigactionOpts{
		Handler: reflect.ValueOf(handler).Pointer(),
		// Handler: funcPC(handler),
		Mask:  mask,
		Flags: flags,
	}
	oldSa, err := Sigaction(unix.SIGTERM, &sa)
	if err != nil {
		t.Fatalf("failed to set handler: %v", err)
	}
	t.Logf("oldSa: %+v", oldSa)
	defer func() {
		if _, err := Sigaction(unix.SIGTERM, &oldSa); err != nil {
			t.Fatalf("failed to cleanup signal handler: %v", err)
		}
	}()

	checkSa, err := Sigaction(unix.SIGTERM, nil)
	if err != nil {
		t.Fatalf("failed to check handler: %v", err)
	}
	t.Logf("checkSa: %+v", checkSa)

	// Generate the signal.
	oldValue := atomic.LoadInt32(&value)
	self, err := os.FindProcess(unix.Getpid())
	if err != nil {
		t.Fatalf("failed to find own process: %v", err)
	}
	if err := self.Signal(unix.SIGTERM); err != nil {
		t.Fatalf("failed to signal self: %v", err)
	}

	// Ensure value has changed.
	if got, want := atomic.LoadInt32(&value), oldValue+inc; got != want {
		t.Fatalf("got %d, but wanted %d", got, want)
	}

	// Read back the sigaction and make sure it's the same as what we set.
	readSa, err := Sigaction(unix.SIGTERM, nil)
	if err != nil {
		t.Fatalf("failed to read signal handler: %v", err)
	}
	if diff := cmp.Diff(sa, readSa); diff != "" {
		t.Fatalf("expected to read back sigaction, but got different value (-want, +got):\n%s", diff)
	}

	// TODO: Check function via runtime.FuncForPC.
}
