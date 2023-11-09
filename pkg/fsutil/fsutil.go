// Copyright 2022 The gVisor Authors.
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

// Package fsutil contains filesystem utilities that can be shared between the
// sentry and other sandbox components.
package fsutil

import "golang.org/x/sys/unix"

// DirentHandler is a function that handles a dirent.
type DirentHandler func(ino uint64, off int64, ftype uint8, name string, reclen uint16)

// ForEachDirent retrieves all dirents from dirfd using getdents64(2) and
// invokes handleDirent on them.
func ForEachDirent(dirfd int, handleDirent DirentHandler) error {
	var direntsBuf [8192]byte
	for {
		n, err := unix.Getdents(dirfd, direntsBuf[:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}
		ParseDirents(direntsBuf[:n], handleDirent)
	}
}

// DirentNames retrieves all dirents from dirfd using getdents64(2) and returns
// all the recorded dirent names.
func DirentNames(dirfd int) ([]string, error) {
	var names []string
	err := ForEachDirent(dirfd, func(_ uint64, _ int64, _ uint8, name string, _ uint16) {
		names = append(names, name)
	})
	return names, err
}
