This package provides an implementation of the Linux virtual filesystem.

[TOC]

## Overview

-   An `fs.Dirent` caches an `fs.Inode` in memory at a path in the VFS, giving
    the `fs.Inode` a relative position with respect to other `fs.Inode`s.

-   If an `fs.Dirent` is referenced by two file descriptors, then those file
    descriptors are coherent with each other: they depend on the same
    `fs.Inode`.

-   A mount point is an `fs.Dirent` for which `fs.Dirent.mounted` is true. It
    exposes the root of a mounted filesystem.

-   The `fs.Inode` produced by a registered filesystem on mount(2) owns an
    `fs.MountedFilesystem` from which other `fs.Inode`s will be looked up. For a
    remote filesystem, the `fs.MountedFilesystem` owns the connection to that
    remote filesystem.

-   In general:

```
fs.Inode <------------------------------
|                                      |
|                                      |
produced by                            |
exactly one                            |
|                             responsible for the
|                             virtual identity of
v                                      |
fs.MountedFilesystem -------------------
```

Glossary:

-   VFS: virtual filesystem.

-   inode: a virtual file object holding a cached view of a file on a backing
    filesystem (includes metadata and page caches).

-   superblock: the virtual state of a mounted filesystem (e.g. the virtual
    inode number set).

-   mount namespace: a view of the mounts under a root (during path traversal,
    the VFS makes visible/follows the mount point that is in the current task's
    mount namespace).

## Save and restore

An application's hard dependencies on filesystem state can be broken down into
two categories:

-   The state necessary to execute a traversal on or view the *virtual*
    filesystem hierarchy, regardless of what files an application has open.

-   The state necessary to represent open files.

The first is always necessary to save and restore. An application may never have
any open file descriptors, but across save and restore it should see a coherent
view of any mount namespace. NOTE: Currently only one "initial"
mount namespace is supported.

The second is so that system calls across save and restore are coherent with
each other (e.g. so that unintended re-reads or overwrites do not occur).

Specifically this state is:

-   An `fs.MountManager` containing mount points.

-   A `kernel.FDMap` containing pointers to open files.

Anything else managed by the VFS that can be easily loaded into memory from a
filesystem is synced back to those filesystems and is not saved. Examples are
pages in page caches used for optimizations (i.e. readahead and writeback), and
directory entries used to accelerate path lookups.

### Mount points

Saving and restoring a mount point means saving and restoring:

-   The root of the mounted filesystem.

-   Mount flags, which control how the VFS interacts with the mounted
    filesystem.

-   Any relevant metadata about the mounted filesystem.

-   All `fs.Inode`s referenced by the application that reside under the mount
    point.

`fs.MountedFilesystem` is metadata about a filesystem that is mounted. It is
referenced by every `fs.Inode` loaded into memory under the mount point
including the `fs.Inode` of the mount point itself. The `fs.MountedFilesystem`
maps file objects on the filesystem to a virtualized `fs.Inode` number and vice
versa.

To restore all `fs.Inode`s under a given mount point, each `fs.Inode` leverages
its dependency on an `fs.MountedFilesystem`. Since the `fs.MountedFilesystem`
knows how an `fs.Inode` maps to a file object on a backing filesystem, this
mapping can be trivially consulted by each `fs.Inode` when the `fs.Inode` is
restored.

In detail, a mount point is saved in two steps:

-   First, after the kernel is paused but before state.Save, we walk all mount
    namespaces and install a mapping from `fs.Inode` numbers to file paths
    relative to the root of the mounted filesystem in each
    `fs.MountedFilesystem`. This is subsequently called the set of `fs.Inode`
    mappings.

-   Second, during state.Save, each `fs.MountedFilesystem` decides whether to
    save the set of `fs.Inode` mappings. In-memory filesystems, like tmpfs, have
    no need to save a set of `fs.Inode` mappings, since the `fs.Inode`s can be
    entirely encoded in state file. Each `fs.MountedFilesystem` also optionally
    saves the device name from when the filesystem was originally mounted. Each
    `fs.Inode` saves its virtual identifier and a reference to a
    `fs.MountedFilesystem`.

A mount point is restored in two steps:

-   First, before state.Load, all mount configurations are stored in a global
    `fs.RestoreEnvironment`. This tells us what mount points the user wants to
    restore and how to re-establish pointers to backing filesystems.

-   Second, during state.Load, each `fs.MountedFilesystem` optionally searches
    for a mount in the `fs.RestoreEnvironment` that matches its saved device
    name. The `fs.MountedFilesystem` then restablishes a pointer to the root of
    the mounted filesystem. For example, the mount specification provides the
    network connection for a mounted remote filesystem client to communicate
    with its remote file server. The `fs.MountedFilesystem` also trivially loads
    its set of `fs.Inode` mappings. When an `fs.Inode` is encountered, the
    `fs.Inode` loads its virtual identifier and its reference a
    `fs.MountedFilesystem`. It uses the `fs.MountedFilesystem` to obtain the
    root of the mounted filesystem and the `fs.Inode` mappings to obtain the
    relative file path to its data. With these, the `fs.Inode` re-establishes a
    pointer to its file object.

A mount point can trivially restore its `fs.Inode`s in parallel since
`fs.Inode`s have a restore dependency on their `fs.MountedFilesystem` and not on
each other.

### Open files

An `fs.File` references the following filesystem objects:

```go
fs.File -> fs.Dirent -> fs.Inode -> fs.MountedFilesystem
```

The `fs.Inode` is restored using its `fs.MountedFilesystem`. The
[Mount points](#mount-points) section above describes how this happens in
detail. The `fs.Dirent` restores its pointer to an `fs.Inode`, pointers to
parent and children `fs.Dirents`, and the basename of the file.

Otherwise an `fs.File` restores flags, an offset, and a unique identifier (only
used internally).

It may use the `fs.Inode`, which it indirectly holds a reference on through the
`fs.Dirent`, to restablish an open file handle on the backing filesystem (e.g.
to continue reading and writing).

## Overlay

The overlay implementation in the fs package takes Linux overlayfs as a frame of
reference but corrects for several POSIX consistency errors.

In Linux overlayfs, the `struct inode` used for reading and writing to the same
file may be different. This is because the `struct inode` is dissociated with
the process of copying up the file from the upper to the lower directory. Since
flock(2) and fcntl(2) locks, inotify(7) watches, page caches, and a file's
identity are all stored directly or indirectly off the `struct inode`, these
properties of the `struct inode` may be stale after the first modification. This
can lead to file locking bugs, missed inotify events, and inconsistent data in
shared memory mappings of files, to name a few problems.

The fs package maintains a single `fs.Inode` to represent a directory entry in
an overlay and defines operations on this `fs.Inode` which synchronize with the
copy up process. This achieves several things:

+   File locks, inotify watches, and the identity of the file need not be copied
    at all.

+   Memory mappings of files coordinate with the copy up process so that if a
    file in the lower directory is memory mapped, all references to it are
    invalidated, forcing the application to re-fault on memory mappings of the
    file under the upper directory.

The `fs.Inode` holds metadata about files in the upper and/or lower directories
via an `fs.overlayEntry`. The `fs.overlayEntry` implements the `fs.Mappable`
interface. It multiplexes between upper and lower directory memory mappings and
stores a copy of memory references so they can be transferred to the upper
directory `fs.Mappable` when the file is copied up.

The lower filesystem in an overlay may contain another (nested) overlay, but the
upper filesystem may not contain another overlay. In other words, nested
overlays form a tree structure that only allows branching in the lower
filesystem.

Caching decisions in the overlay are delegated to the upper filesystem, meaning
that the Keep and Revalidate methods on the overlay return the same values as
the upper filesystem. A small wrinkle is that the lower filesystem is not
allowed to return `true` from Revalidate, as the overlay can not reload inodes
from the lower filesystem. A lower filesystem that does return `true` from
Revalidate will trigger a panic.

The `fs.Inode` also holds a reference to a `fs.MountedFilesystem` that
normalizes across the mounted filesystem state of the upper and lower
directories.

When a file is copied from the lower to the upper directory, attempts to
interact with the file block until the copy completes. All copying synchronizes
with rename(2).

## Future Work

### Overlay

When a file is copied from a lower directory to an upper directory, several
locks are taken: the global renamuMu and the copyMu of the `fs.Inode` being
copied. This blocks operations on the file, including fault handling of memory
mappings. Performance could be improved by copying files into a temporary
directory that resides on the same filesystem as the upper directory and doing
an atomic rename, holding locks only during the rename operation.

Additionally files are copied up synchronously. For large files, this causes a
noticeable latency. Performance could be improved by pipelining copies at
non-overlapping file offsets.
