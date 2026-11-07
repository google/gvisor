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

//go:build linux

package inotify_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func newInstance(b *testing.B) int {
	b.Helper()
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { syscall.Close(fd) })
	return fd
}

func newFile(b *testing.B, dir, name string) *os.File {
	b.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { f.Close() })
	return f
}

func BenchmarkInotifyInitClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK)
		if err != nil {
			b.Fatal(err)
		}
		if err := syscall.Close(fd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInotifyAddRemoveWatch(b *testing.B) {
	fd := newInstance(b)
	f := newFile(b, b.TempDir(), "watched")
	var event [16]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wd, err := syscall.InotifyAddWatch(fd, f.Name(), syscall.IN_ATTRIB)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := syscall.InotifyRmWatch(fd, uint32(wd)); err != nil {
			b.Fatal(err)
		}
		if n, err := syscall.Read(fd, event[:]); err != nil || n != len(event) {
			b.Fatalf("read IN_IGNORED: %d, %v", n, err)
		}
	}
}

// Each operation queues and reads 128 alternating, non-coalescible events.
func BenchmarkInotifyQueueBatch128(b *testing.B) {
	fd := newInstance(b)
	dir := b.TempDir()
	files := [2]*os.File{newFile(b, dir, "a"), newFile(b, dir, "b")}
	for _, f := range files {
		if _, err := syscall.InotifyAddWatch(fd, f.Name(), syscall.IN_ATTRIB); err != nil {
			b.Fatal(err)
		}
	}
	var events [128 * 16]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 128; j++ {
			if err := syscall.Fchmod(int(files[j%2].Fd()), 0600); err != nil {
				b.Fatal(err)
			}
		}
		if n, err := syscall.Read(fd, events[:]); err != nil || n != len(events) {
			b.Fatalf("read events: %d, %v", n, err)
		}
	}
}
