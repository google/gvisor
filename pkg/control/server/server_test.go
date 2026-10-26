// Copyright 2026 The gVisor Authors.
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

package server

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
)

type echo struct{}

// Echo returns its argument.
func (*echo) Echo(arg *string, ret *string) error {
	*ret = *arg
	return nil
}

// TestCallBeforeServing checks that a call made before the server starts
// serving waits for it instead of failing or hanging.
func TestCallBeforeServing(t *testing.T) {
	addr := fmt.Sprintf("\x00control-server-test.%d", rand.Int63())
	srv, err := Create(addr)
	if err != nil {
		t.Fatalf("Create(%q) failed: %v", addr, err)
	}
	srv.Register(&echo{})

	conn, err := unet.Connect(addr, false)
	if err != nil {
		t.Fatalf("Connect(%q) failed: %v", addr, err)
	}
	client := urpc.NewClient(conn)
	defer client.Close()
	arg, got := "hello", ""
	done := make(chan error, 1)
	go func() { done <- client.Call("echo.Echo", &arg, &got) }()
	select {
	case err := <-done:
		t.Fatalf("Call returned before the server started serving: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	srv.StartServing()
	defer srv.Stop(time.Second)
	if err := <-done; err != nil {
		t.Fatalf("Call failed: %v", err)
	}
	if got != arg {
		t.Errorf("Call returned %q, expected %q", got, arg)
	}
}
