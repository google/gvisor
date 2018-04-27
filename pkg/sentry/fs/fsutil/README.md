This package provides utilities for implementing virtual filesystem objects.

[TOC]

## Page cache

`CachingInodeOperations` implements a page cache for files that cannot use the
host page cache. Normally these are files that store their data in a remote
filesystem. This also applies to files that are accessed on a platform that does
not support directly memory mapping host file descriptors (e.g. the ptrace
platform).

An `CachingInodeOperations` buffers regions of a single file into memory. It is
owned by an `fs.Inode`, the in-memory representation of a file (all open file
descriptors are backed by an `fs.Inode`). The `fs.Inode` provides operations for
reading memory into an `CachingInodeOperations`, to represent the contents of
the file in-memory, and for writing memory out, to relieve memory pressure on
the kernel and to synchronize in-memory changes to filesystems.

An `CachingInodeOperations` enables readable and/or writable memory access to
file content. Files can be mapped shared or private, see mmap(2). When a file is
mapped shared, changes to the file via write(2) and truncate(2) are reflected in
the shared memory region. Conversely, when the shared memory region is modified,
changes to the file are visible via read(2). Multiple shared mappings of the
same file are coherent with each other. This is consistent with Linux.

When a file is mapped private, updates to the mapped memory are not visible to
other memory mappings. Updates to the mapped memory are also not reflected in
the file content as seen by read(2). If the file is changed after a private
mapping is created, for instance by write(2), the change to the file may or may
not be reflected in the private mapping. This is consistent with Linux.

An `CachingInodeOperations` keeps track of ranges of memory that were modified
(or "dirtied"). When the file is explicitly synced via fsync(2), only the dirty
ranges are written out to the filesystem. Any error returned indicates a failure
to write all dirty memory of an `CachingInodeOperations` to the filesystem. In
this case the filesystem may be in an inconsistent state. The same operation can
be performed on the shared memory itself using msync(2). If neither fsync(2) nor
msync(2) is performed, then the dirty memory is written out in accordance with
the `CachingInodeOperations` eviction strategy (see below) and there is no
guarantee that memory will be written out successfully in full.

### Memory allocation and eviction

An `CachingInodeOperations` implements the following allocation and eviction
strategy:

-   Memory is allocated and brought up to date with the contents of a file when
    a region of mapped memory is accessed (or "faulted on").

-   Dirty memory is written out to filesystems when an fsync(2) or msync(2)
    operation is performed on a memory mapped file, for all memory mapped files
    when saved, and/or when there are no longer any memory mappings of a range
    of a file, see munmap(2). As the latter implies, in the absence of a panic
    or SIGKILL, dirty memory is written out for all memory mapped files when an
    application exits.

-   Memory is freed when there are no longer any memory mappings of a range of a
    file (e.g. when an application exits). This behavior is consistent with
    Linux for shared memory that has been locked via mlock(2).

Notably, memory is not allocated for read(2) or write(2) operations. This means
that reads and writes to the file are only accelerated by an
`CachingInodeOperations` if the file being read or written has been memory
mapped *and* if the shared memory has been accessed at the region being read or
written. This diverges from Linux which buffers memory into a page cache on
read(2) proactively (i.e. readahead) and delays writing it out to filesystems on
write(2) (i.e. writeback). The absence of these optimizations is not visible to
applications beyond less than optimal performance when repeatedly reading and/or
writing to same region of a file. See [Future Work](#future-work) for plans to
implement these optimizations.

Additionally, memory held by `CachingInodeOperationss` is currently unbounded in
size. An `CachingInodeOperations` does not write out dirty memory and free it
under system memory pressure. This can cause pathological memory usage.

When memory is written back, an `CachingInodeOperations` may write regions of
shared memory that were never modified. This is due to the strategy of
minimizing page faults (see below) and handling only a subset of memory write
faults. In the absence of an application or sentry crash, it is guaranteed that
if a region of shared memory was written to, it is written back to a filesystem.

### Life of a shared memory mapping

A file is memory mapped via mmap(2). For example, if `A` is an address, an
application may execute:

```
mmap(A, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
```

This creates a shared mapping of fd that reflects 4k of the contents of fd
starting at offset 0, accessible at address `A`. This in turn creates a virtual
memory area region ("vma") which indicates that [`A`, `A`+0x1000) is now a valid
address range for this application to access.

At this point, memory has not been allocated in the file's
`CachingInodeOperations`. It is also the case that the address range [`A`,
`A`+0x1000) has not been mapped on the host on behalf of the application. If the
application then tries to modify 8 bytes of the shared memory:

```
char buffer[] = "aaaaaaaa";
memcpy(A, buffer, 8);
```

The host then sends a `SIGSEGV` to the sentry because the address range [`A`,
`A`+8) is not mapped on the host. The `SIGSEGV` indicates that the memory was
accessed writable. The sentry looks up the vma associated with [`A`, `A`+8),
finds the file that was mapped and its `CachingInodeOperations`. It then calls
`CachingInodeOperations.MapInto` which allocates memory to back [`A`, `A`+8). It
may choose to allocate more memory (i.e. do "readahead") to minimize subsequent
faults.

Memory that is allocated comes from a host tmpfs file (see `filemem.FileMem`).
The host tmpfs file memory is brought up to date with the contents of the mapped
file on its filesystem. The region of the host tmpfs file that reflects the
mapped file is then mapped into the host address space of the application so
that subsequent memory accesses do not repeatedly generate a `SIGSEGV`.

The range that was allocated, including any extra memory allocation to minimize
faults, is marked dirty due to the write fault. This overcounts dirty memory if
the extra memory allocated is never modified.

To make the scenario more interesting, imagine that this application spawns
another process and maps the same file in the exact same way:

```
mmap(A, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
```

Imagine that this process then tries to modify the file again but with only 4
bytes:

```
char buffer[] = "bbbb";
memcpy(A, buffer, 4);
```

Since the first process has already mapped and accessed the same region of the
file writable, `CachingInodeOperations.MapInto` is called but re-maps the memory
that has already been allocated (because the host mapping can be invalidated at
any time) rather than allocating new memory. The address range [`A`, `A`+0x1000)
reflects the same cached view of the file as the first process sees. For
example, reading 8 bytes from the file from either process via read(2) starting
at offset 0 returns a consistent "bbbbaaaa".

When this process no longer needs the shared memory, it may do:

```
munmap(A, 0x1000);
```

At this point, the modified memory cached by the `CachingInodeOperations` is not
written back to the file because it is still in use by the first process that
mapped it. When the first process also does:

```
munmap(A, 0x1000);
```

Then the last memory mapping of the file at the range [0, 0x1000) is gone. The
file's `CachingInodeOperations` then starts writing back memory marked dirty to
the file on its filesystem. Once writing completes, regardless of whether it was
successful, the `CachingInodeOperations` frees the memory cached at the range
[0, 0x1000).

Subsequent read(2) or write(2) operations on the file go directly to the
filesystem since there no longer exists memory for it in its
`CachingInodeOperations`.

## Future Work

### Page cache

The sentry does not yet implement the readahead and writeback optimizations for
read(2) and write(2) respectively. To do so, on read(2) and/or write(2) the
sentry must ensure that memory is allocated in a page cache to read or write
into. However, the sentry cannot boundlessly allocate memory. If it did, the
host would eventually OOM-kill the sentry+application process. This means that
the sentry must implement a page cache memory allocation strategy that is
bounded by a global user or container imposed limit. When this limit is
approached, the sentry must decide from which page cache memory should be freed
so that it can allocate more memory. If it makes a poor decision, the sentry may
end up freeing and re-allocating memory to back regions of files that are
frequently used, nullifying the optimization (and in some cases causing worse
performance due to the overhead of memory allocation and general management).
This is a form of "cache thrashing".

In Linux, much research has been done to select and implement a lightweight but
optimal page cache eviction algorithm. Linux makes use of hardware page bits to
keep track of whether memory has been accessed. The sentry does not have direct
access to hardware. Implementing a similarly lightweight and optimal page cache
eviction algorithm will need to either introduce a kernel interface to obtain
these page bits or find a suitable alternative proxy for access events.

In Linux, readahead happens by default but is not always ideal. For instance,
for files that are not read sequentially, it would be more ideal to simply read
from only those regions of the file rather than to optimistically cache some
number of bytes ahead of the read (up to 2MB in Linux) if the bytes cached won't
be accessed. Linux implements the fadvise64(2) system call for applications to
specify that a range of a file will not be accessed sequentially. The advice bit
FADV_RANDOM turns off the readahead optimization for the given range in the
given file. However fadvise64 is rarely used by applications so Linux implements
a readahead backoff strategy if reads are not sequential. To ensure that
application performance is not degraded, the sentry must implement a similar
backoff strategy.
