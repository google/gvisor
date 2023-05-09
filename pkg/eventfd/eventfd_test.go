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

package eventfd

import (
	"testing"
	"time"
)

func TestReadWrite(t *testing.T) {
	efd, err := Create()
	if err != nil {
		t.Fatalf("failed to Create(): %v", err)
	}
	defer efd.Close()

	// Make sure we can read actual values
	const want = 343
	if err := efd.Write(want); err != nil {
		t.Fatalf("failed to write value: %d", want)
	}

	got, err := efd.Read()
	if err != nil {
		t.Fatalf("failed to read value: %v", err)
	}
	if got != want {
		t.Fatalf("Read(): got %d, but wanted %d", got, want)
	}
}

func TestWait(t *testing.T) {
	efd, err := Create()
	if err != nil {
		t.Fatalf("failed to Create(): %v", err)
	}
	defer efd.Close()

	// There's no way to test with certainty that Wait() blocks indefinitely, but
	// as a best-effort we can wait a bit on it.
	errCh := make(chan error)
	go func() {
		errCh <- efd.Wait()
	}()
	select {
	case err := <-errCh:
		t.Fatalf("Wait() returned without a call to Notify(): %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	// Notify and check that Wait() returned.
	if err := efd.Notify(); err != nil {
		t.Fatalf("Notify() failed: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Read() failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Read() did not return after Notify()")
	}
}
