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
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

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
