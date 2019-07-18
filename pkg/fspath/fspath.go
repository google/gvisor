// Copyright 2019 The gVisor Authors.
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

// Package fspath provides efficient tools for working with file paths in
// Linux-compatible filesystem implementations.
package fspath

import (
	"strings"

	"gvisor.dev/gvisor/pkg/syserror"
)

const pathSep = '/'

// Parse parses a pathname as described by path_resolution(7).
func Parse(pathname string) (Path, error) {
	if len(pathname) == 0 {
		// "... POSIX decrees that an empty pathname must not be resolved
		// successfully. Linux returns ENOENT in this case." -
		// path_resolution(7)
		return Path{}, syserror.ENOENT
	}
	// Skip leading path separators.
	i := 0
	for pathname[i] == pathSep {
		i++
		if i == len(pathname) {
			// pathname consists entirely of path separators.
			return Path{
				Absolute: true,
				Dir:      true,
			}, nil
		}
	}
	// Skip trailing path separators. This is required by Iterator.Next. This
	// loop is guaranteed to terminate with j >= 0 because otherwise the
	// pathname would consist entirely of path separators, so we would have
	// returned above.
	j := len(pathname) - 1
	for pathname[j] == pathSep {
		j--
	}
	// Find the end of the first path component.
	firstEnd := i + 1
	for firstEnd != len(pathname) && pathname[firstEnd] != pathSep {
		firstEnd++
	}
	return Path{
		Begin: Iterator{
			partialPathname: pathname[i : j+1],
			end:             firstEnd - i,
		},
		Absolute: i != 0,
		Dir:      j != len(pathname)-1,
	}, nil
}

// Path contains the information contained in a pathname string.
//
// Path is copyable by value.
type Path struct {
	// Begin is an iterator to the first path component in the relative part of
	// the path.
	//
	// Path doesn't store information about path components after the first
	// since this would require allocation.
	Begin Iterator

	// If true, the path is absolute, such that lookup should begin at the
	// filesystem root. If false, the path is relative, such that where lookup
	// begins is unspecified.
	Absolute bool

	// If true, the pathname contains trailing path separators, so the last
	// path component must exist and resolve to a directory.
	Dir bool
}

// String returns a pathname string equivalent to p. Note that the returned
// string is not necessarily equal to the string p was parsed from; in
// particular, redundant path separators will not be present.
func (p Path) String() string {
	var b strings.Builder
	if p.Absolute {
		b.WriteByte(pathSep)
	}
	sep := false
	for pit := p.Begin; pit.Ok(); pit = pit.Next() {
		if sep {
			b.WriteByte(pathSep)
		}
		b.WriteString(pit.String())
		sep = true
	}
	// Don't return "//" for Parse("/").
	if p.Dir && p.Begin.Ok() {
		b.WriteByte(pathSep)
	}
	return b.String()
}

// An Iterator represents either a path component in a Path or a terminal
// iterator indicating that the end of the path has been reached.
//
// Iterator is immutable and copyable by value. The zero value of Iterator is
// valid, and represents a terminal iterator.
type Iterator struct {
	// partialPathname is a substring of the original pathname beginning at the
	// start of the represented path component and ending immediately after the
	// end of the last path component in the pathname. If partialPathname is
	// empty, the PathnameIterator is terminal.
	//
	// See TestParseIteratorPartialPathnames in fspath_test.go for a worked
	// example.
	partialPathname string

	// end is the offset into partialPathname of the first byte after the end
	// of the represented path component.
	end int
}

// Ok returns true if it is not terminal.
func (it Iterator) Ok() bool {
	return len(it.partialPathname) != 0
}

// String returns the path component represented by it.
//
// Preconditions: it.Ok().
func (it Iterator) String() string {
	return it.partialPathname[:it.end]
}

// Next returns an iterator to the path component after it. If it is the last
// component in the path, Next returns a terminal iterator.
//
// Preconditions: it.Ok().
func (it Iterator) Next() Iterator {
	if it.end == len(it.partialPathname) {
		// End of the path.
		return Iterator{}
	}
	// Skip path separators. Since Parse trims trailing path separators, if we
	// aren't at the end of the path, there is definitely another path
	// component.
	i := it.end + 1
	for {
		if it.partialPathname[i] != pathSep {
			break
		}
		i++
	}
	nextPartialPathname := it.partialPathname[i:]
	// Find the end of this path component.
	nextEnd := 1
	for nextEnd < len(nextPartialPathname) && nextPartialPathname[nextEnd] != pathSep {
		nextEnd++
	}
	return Iterator{
		partialPathname: nextPartialPathname,
		end:             nextEnd,
	}
}

// NextOk is equivalent to it.Next().Ok(), but is faster.
//
// Preconditions: it.Ok().
func (it Iterator) NextOk() bool {
	return it.end != len(it.partialPathname)
}
