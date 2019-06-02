// Copyright 2018 The gVisor Authors.
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

import (
	"sort"

	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
)

// DentAttr is the metadata of a directory entry. It is a subset of StableAttr.
//
// +stateify savable
type DentAttr struct {
	// Type is the InodeType of an Inode.
	Type InodeType

	// InodeID uniquely identifies an Inode on a device.
	InodeID uint64
}

// GenericDentAttr returns a generic DentAttr where:
//
// Type == nt
// InodeID == the inode id of a new inode on device.
func GenericDentAttr(nt InodeType, device *device.Device) DentAttr {
	return DentAttr{
		Type:    nt,
		InodeID: device.NextIno(),
	}
}

// DentrySerializer serializes a directory entry.
type DentrySerializer interface {
	// CopyOut serializes a directory entry based on its name and attributes.
	CopyOut(name string, attributes DentAttr) error

	// Written returns the number of bytes written.
	Written() int
}

// CollectEntriesSerializer copies DentAttrs to Entries. The order in
// which entries are encountered is preserved in Order.
type CollectEntriesSerializer struct {
	Entries map[string]DentAttr
	Order   []string
}

// CopyOut implements DentrySerializer.CopyOut.
func (c *CollectEntriesSerializer) CopyOut(name string, attr DentAttr) error {
	if c.Entries == nil {
		c.Entries = make(map[string]DentAttr)
	}
	c.Entries[name] = attr
	c.Order = append(c.Order, name)
	return nil
}

// Written implements DentrySerializer.Written.
func (c *CollectEntriesSerializer) Written() int {
	return len(c.Entries)
}

// DirCtx is used in FileOperations.IterateDir to emit directory entries. It is
// not thread-safe.
type DirCtx struct {
	// Serializer is used to serialize the node attributes.
	Serializer DentrySerializer

	// attrs are DentAttrs
	attrs map[string]DentAttr

	// DirCursor is the directory cursor.
	DirCursor *string
}

// DirEmit is called for each directory entry.
func (c *DirCtx) DirEmit(name string, attr DentAttr) error {
	if c.Serializer != nil {
		if err := c.Serializer.CopyOut(name, attr); err != nil {
			return err
		}
	}
	if c.attrs == nil {
		c.attrs = make(map[string]DentAttr)
	}
	c.attrs[name] = attr
	return nil
}

// DentAttrs returns a map of DentAttrs corresponding to the emitted directory
// entries.
func (c *DirCtx) DentAttrs() map[string]DentAttr {
	if c.attrs == nil {
		c.attrs = make(map[string]DentAttr)
	}
	return c.attrs
}

// GenericReaddir serializes DentAttrs based on a SortedDentryMap that must
// contain _all_ up-to-date DentAttrs under a directory. If ctx.DirCursor is
// not nil, it is updated to the name of the last DentAttr that was
// successfully serialized.
//
// Returns the number of entries serialized.
func GenericReaddir(ctx *DirCtx, s *SortedDentryMap) (int, error) {
	// Retrieve the next directory entries.
	var names []string
	var entries map[string]DentAttr
	if ctx.DirCursor != nil {
		names, entries = s.GetNext(*ctx.DirCursor)
	} else {
		names, entries = s.GetAll()
	}

	// Try to serialize each entry.
	var serialized int
	for _, name := range names {
		// Skip "" per POSIX. Skip "." and ".." which will be added by Dirent.Readdir.
		if name == "" || name == "." || name == ".." {
			continue
		}

		// Emit the directory entry.
		if err := ctx.DirEmit(name, entries[name]); err != nil {
			// Return potentially a partial serialized count.
			return serialized, err
		}

		// We successfully serialized this entry.
		serialized++

		// Update the cursor with the name of the entry last serialized.
		if ctx.DirCursor != nil {
			*ctx.DirCursor = name
		}
	}

	// Everything was serialized.
	return serialized, nil
}

// SortedDentryMap is a sorted map of names and fs.DentAttr entries.
//
// +stateify savable
type SortedDentryMap struct {
	// names is always kept in sorted-order.
	names []string

	// entries maps names to fs.DentAttrs.
	entries map[string]DentAttr
}

// NewSortedDentryMap maintains entries in name sorted order.
func NewSortedDentryMap(entries map[string]DentAttr) *SortedDentryMap {
	s := &SortedDentryMap{
		names:   make([]string, 0, len(entries)),
		entries: entries,
	}
	// Don't allow s.entries to be nil, because nil maps arn't Saveable.
	if s.entries == nil {
		s.entries = make(map[string]DentAttr)
	}

	// Collect names from entries and sort them.
	for name := range s.entries {
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	return s
}

// GetAll returns all names and entries in s. Callers should not modify the
// returned values.
func (s *SortedDentryMap) GetAll() ([]string, map[string]DentAttr) {
	return s.names, s.entries
}

// GetNext returns names after cursor in s and all entries.
func (s *SortedDentryMap) GetNext(cursor string) ([]string, map[string]DentAttr) {
	i := sort.SearchStrings(s.names, cursor)
	if i == len(s.names) {
		return nil, s.entries
	}

	// Return everything strictly after the cursor.
	if s.names[i] == cursor {
		i++
	}
	return s.names[i:], s.entries
}

// Add adds an entry with the given name to the map, preserving sort order.  If
// name already exists in the map, its entry will be overwritten.
func (s *SortedDentryMap) Add(name string, entry DentAttr) {
	if _, ok := s.entries[name]; !ok {
		// Map does not yet contain an entry with this name.  We must
		// insert it in s.names at the appropriate spot.
		i := sort.SearchStrings(s.names, name)
		s.names = append(s.names, "")
		copy(s.names[i+1:], s.names[i:])
		s.names[i] = name
	}
	s.entries[name] = entry
}

// Remove removes an entry with the given name from the map, preserving sort order.
func (s *SortedDentryMap) Remove(name string) {
	if _, ok := s.entries[name]; !ok {
		return
	}
	i := sort.SearchStrings(s.names, name)
	copy(s.names[i:], s.names[i+1:])
	s.names = s.names[:len(s.names)-1]
	delete(s.entries, name)
}

// Contains reports whether the map contains an entry with the given name.
func (s *SortedDentryMap) Contains(name string) bool {
	_, ok := s.entries[name]
	return ok
}
