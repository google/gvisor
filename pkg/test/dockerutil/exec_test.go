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

package dockerutil

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/docker/client"
)

func TestWaitExitStatusBeforeStart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pid      int
		exitCode int
	}{
		{name: "failure", pid: 123, exitCode: 1},
		{name: "success", pid: 123},
		{name: "failed_start", exitCode: 126},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1.43/exec/test/json" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if calls.Add(1) == 1 {
					// This is Docker's response between attach and process startup.
					// Exercise the real client's decoding of a null exit code.
					fmt.Fprint(w, `{"Running":false,"Pid":0,"ExitCode":null}`)
					return
				}
				fmt.Fprintf(w, `{"Running":false,"Pid":%d,"ExitCode":%d}`, tc.pid, tc.exitCode)
			}))
			defer server.Close()
			c, err := client.NewClientWithOpts(client.WithHost(server.URL), client.WithVersion("1.43"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			p := Process{container: &Container{client: c}, execid: "test"}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if got, err := p.WaitExitStatus(ctx); err != nil || got != tc.exitCode {
				t.Fatalf("WaitExitStatus() = %d, %v; want %d, nil", got, err, tc.exitCode)
			}
		})
	}
}
