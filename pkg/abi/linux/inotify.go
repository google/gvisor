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

package linux

// Inotify events observable by userspace. These directly correspond to
// filesystem operations and there may only be a single of them per inotify
// event read from an inotify fd.
const (
	// IN_ACCESS indicates a file was accessed.
	IN_ACCESS = 0x00000001
	// IN_MODIFY indicates a file was modified.
	IN_MODIFY = 0x00000002
	// IN_ATTRIB indicates a watch target's metadata changed.
	IN_ATTRIB = 0x00000004
	// IN_CLOSE_WRITE indicates a writable file was closed.
	IN_CLOSE_WRITE = 0x00000008
	// IN_CLOSE_NOWRITE indicates a non-writable file was closed.
	IN_CLOSE_NOWRITE = 0x00000010
	// IN_OPEN indicates a file was opened.
	IN_OPEN = 0x00000020
	// IN_MOVED_FROM indicates a file was moved from X.
	IN_MOVED_FROM = 0x00000040
	// IN_MOVED_TO indicates a file was moved to Y.
	IN_MOVED_TO = 0x00000080
	// IN_CREATE indicates a file was created in a watched directory.
	IN_CREATE = 0x00000100
	// IN_DELETE indicates a file was deleted in a watched directory.
	IN_DELETE = 0x00000200
	// IN_DELETE_SELF indicates a watch target itself was deleted.
	IN_DELETE_SELF = 0x00000400
	// IN_MOVE_SELF indicates a watch target itself was moved.
	IN_MOVE_SELF = 0x00000800
	// IN_ALL_EVENTS is a mask for all observable userspace events.
	IN_ALL_EVENTS = 0x00000fff
)

// Inotify control events. These may be present in their own events, or ORed
// with other observable events.
const (
	// IN_UNMOUNT indicates the backing filesystem was unmounted.
	IN_UNMOUNT = 0x00002000
	// IN_Q_OVERFLOW indicates the event queued overflowed.
	IN_Q_OVERFLOW = 0x00004000
	// IN_IGNORED indicates a watch was removed, either implicitly or through
	// inotify_rm_watch(2).
	IN_IGNORED = 0x00008000
	// IN_ISDIR indicates the subject of an event was a directory.
	IN_ISDIR = 0x40000000
)

// Feature flags for inotify_add_watch(2).
const (
	// IN_ONLYDIR indicates that a path should be watched only if it's a
	// directory.
	IN_ONLYDIR = 0x01000000
	// IN_DONT_FOLLOW indicates that the watch path shouldn't be resolved if
	// it's a symlink.
	IN_DONT_FOLLOW = 0x02000000
	// IN_EXCL_UNLINK indicates events to this watch from unlinked objects
	// should be filtered out.
	IN_EXCL_UNLINK = 0x04000000
	// IN_MASK_ADD indicates the provided mask should be ORed into any existing
	// watch on the provided path.
	IN_MASK_ADD = 0x20000000
	// IN_ONESHOT indicates the watch should be removed after one event.
	IN_ONESHOT = 0x80000000
)

// Feature flags for inotify_init1(2).
const (
	// IN_CLOEXEC is an alias for O_CLOEXEC. It indicates that the inotify
	// fd should be closed on exec(2) and friends.
	IN_CLOEXEC = 0x00080000
	// IN_NONBLOCK is an alias for O_NONBLOCK. It indicates I/O syscall on the
	// inotify fd should not block.
	IN_NONBLOCK = 0x00000800
)

// ALL_INOTIFY_BITS contains all the bits for all possible inotify events. It's
// defined in the Linux source at "include/linux/inotify.h".
const ALL_INOTIFY_BITS = IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE |
	IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE |
	IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT | IN_Q_OVERFLOW |
	IN_IGNORED | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_ADD |
	IN_ISDIR | IN_ONESHOT
