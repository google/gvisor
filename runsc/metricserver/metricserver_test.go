// Copyright 2023 The gVisor Authors.
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

package metricserver

import (
	"context"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestShutdownWithActivePIDRequest(t *testing.T) {
	// Channels control the interleaving. Real HTTP I/O and mutex waits are
	// not synctest-durable, so this deadline only bounds failure and cleanup.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	m := &metricServer{shutdownDone: make(chan struct{})}
	handlerStarted := make(chan struct{})
	allowHandler := make(chan struct{})
	handlerDone := make(chan struct{})
	allowReturn := make(chan struct{})
	shutdownStarted := make(chan struct{})
	m.srv.RegisterOnShutdown(func() { close(shutdownStarted) })
	m.srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(handlerStarted)
		select {
		case <-allowHandler:
		case <-ctx.Done():
			return
		}
		logRequest(m.servePID)(w, req)
		close(handlerDone)
		select {
		case <-allowReturn:
		case <-ctx.Done():
		}
	})
	ts := httptest.NewUnstartedServer(nil)
	ts.Config = &m.srv
	ts.Start()
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		ts.Close()
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/runsc-metrics/pid", nil)
	if err != nil {
		t.Fatal(err)
	}
	wg.Go(func() {
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Errorf("PID request: %v", err)
			return
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("PID status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
		_ = resp.Body.Close()
	})
	wait := func(what string, ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatalf("waiting for %s: %v", what, ctx.Err())
		}
	}
	wait("request handler", handlerStarted)
	wg.Go(func() { m.shutdown(ctx) })
	wait("HTTP shutdown", shutdownStarted)
	close(allowHandler)
	wait("PID handler", handlerDone)
	select {
	case <-m.shutdownDone:
		t.Fatal("shutdown returned while the request handler was still active")
	default:
	}
	close(allowReturn)
	wait("shutdown completion", m.shutdownDone)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		t.Fatalf("shutdown required deadline cancellation: %v", err)
	}
}

type fakeFileInfo struct {
	fs.FileInfo

	modTime time.Time
	size    int64
	sys     any
}

func (f *fakeFileInfo) ModTime() time.Time { return f.modTime }

func (f *fakeFileInfo) Size() int64 { return f.size }

func (f *fakeFileInfo) Sys() any { return f.sys }

// TestSufficientlyEqualStats tests sufficientlyEqualStats.
func TestSufficientlyEqualStats(t *testing.T) {
	now := time.Now()
	twoHoursAgo := now.Add(-2 * time.Hour)
	for _, test := range []struct {
		name string
		a, b os.FileInfo
		want bool
	}{
		{
			name: "empty",
			a:    &fakeFileInfo{},
			b:    &fakeFileInfo{},
			want: true,
		},
		{
			name: "different modification time",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
			},
			b: &fakeFileInfo{
				modTime: now,
			},
			want: false,
		},
		{
			name: "different size",
			a: &fakeFileInfo{
				size: 1337,
			},
			b: &fakeFileInfo{
				size: 42,
			},
			want: false,
		},
		{
			name: "same mod time and size, not a syscall.Stat_t",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     struct{ foo string }{"bla"},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     struct{ foo int }{42},
			},
			want: true,
		},
		{
			name: "same mod time and size, only one is *syscall.Stat_t",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     &syscall.Stat_t{},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     struct{ foo string }{"blablabla"},
			},
			want: false,
		},
		{
			name: "same mod time and size, one is *syscall.Stat_t, other is syscall.Stat_t",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     &syscall.Stat_t{},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     syscall.Stat_t{},
			},
			want: false,
		},
		{
			name: "same mod time and size, two empty *syscall.Stat_t",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     &syscall.Stat_t{},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys:     &syscall.Stat_t{},
			},
			want: true,
		},
		{
			name: "same mod time and size, different *syscall.Stat_t.Dev",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Dev: 42,
				},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Dev: 43,
				},
			},
			want: false,
		},
		{
			name: "same mod time and size, different *syscall.Stat_t.Ino",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Ino: 42,
				},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Ino: 43,
				},
			},
			want: false,
		},
		{
			name: "same mod time and size, same *syscall.Stat_t.{Dev,Ino}",
			a: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Ino: 42,
					Dev: 44,
				},
			},
			b: &fakeFileInfo{
				modTime: twoHoursAgo,
				size:    1337,
				sys: &syscall.Stat_t{
					Ino: 42,
					Dev: 44,
				},
			},
			want: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := sufficientlyEqualStats(test.a, test.b)
			if got != test.want {
				t.Errorf("got equal=%t want %t", got, test.want)
			}
			gotReverse := sufficientlyEqualStats(test.b, test.a)
			if gotReverse != got {
				t.Errorf("sufficientlyEqualStats(a, b) = %v yet sufficientlyEqualStats(b, a) = %v", got, gotReverse)
			}
		})
	}
}
