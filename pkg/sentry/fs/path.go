// Copyright 2018 Google LLC
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

package fs

// TrimTrailingSlashes trims any trailing slashes.
//
// The returned boolean indicates whether any changes were made.
//
//go:nosplit
func TrimTrailingSlashes(dir string) (trimmed string, changed bool) {
	// Trim the trailing slash, except for root.
	for len(dir) > 1 && dir[len(dir)-1] == '/' {
		dir = dir[:len(dir)-1]
		changed = true
	}
	return dir, changed
}

// SplitLast splits the given path into a directory and a file.
//
// The "absoluteness" of the path is preserved, but dir is always stripped of
// trailing slashes.
//
//go:nosplit
func SplitLast(path string) (dir, file string) {
	path, _ = TrimTrailingSlashes(path)
	if path == "" {
		return ".", "."
	} else if path == "/" {
		return "/", "."
	}

	var slash int // Last location of slash in path.
	for slash = len(path) - 1; slash >= 0 && path[slash] != '/'; slash-- {
	}
	switch {
	case slash < 0:
		return ".", path
	case slash == 0:
		// Directory of the form "/foo", or just "/". We need to
		// preserve the first slash here, since it indicates an
		// absolute path.
		return "/", path[1:]
	default:
		// Drop the trailing slash.
		dir, _ = TrimTrailingSlashes(path[:slash])
		return dir, path[slash+1:]
	}
}

// SplitFirst splits the given path into a first directory and the remainder.
//
// If remainder is empty, then the path is a single element.
//
//go:nosplit
func SplitFirst(path string) (current, remainder string) {
	path, _ = TrimTrailingSlashes(path)
	if path == "" {
		return ".", ""
	}

	var slash int // First location of slash in path.
	for slash = 0; slash < len(path) && path[slash] != '/'; slash++ {
	}
	switch {
	case slash >= len(path):
		return path, ""
	case slash == 0:
		// See above.
		return "/", path[1:]
	default:
		current = path[:slash]
		remainder = path[slash+1:]
		// Strip redundant slashes.
		for len(remainder) > 0 && remainder[0] == '/' {
			remainder = remainder[1:]
		}
		return current, remainder
	}
}
