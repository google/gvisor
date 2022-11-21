# Foreword

This document describes an on-going project to support FUSE filesystems within
the sentry. This is intended to become the final documentation for this
subsystem, and is therefore written in the past tense. However FUSE support is
currently incomplete and the document will be updated as things progress.

# FUSE: Filesystem in Userspace

The sentry supports dispatching filesystem operations to a FUSE server, allowing
FUSE filesystem to be used with a sandbox.

## Overview

FUSE has two main components:

1.  A client kernel driver (canonically `fuse.ko` in Linux), which forwards
    filesystem operations (usually initiated by syscalls) to the server.

2.  A server, which is a userspace daemon that implements the actual filesystem.

The sentry implements the client component, which allows a server daemon running
within the sandbox to implement a filesystem within the sandbox.

A FUSE filesystem is initialized with `mount(2)`, typically with the help of a
utility like `fusermount(1)`. Various mount options exist for establishing
ownership and access permissions on the filesystem, but the most important mount
option is a file descriptor used to establish communication between the client
and server.

The FUSE device FD is obtained by opening `/dev/fuse`. During regular operation,
the client and server use the FUSE protocol described in `fuse(4)` to service
filesystem operations. See the "Protocol" section below for more information
about this protocol. The core of the sentry support for FUSE is the client-side
implementation of this protocol.

## FUSE in the Sentry

The sentry's FUSE client has the following components:

-   An implementation of `/dev/fuse`.

-   A filesystem for mapping syscalls to FUSE ops. One point of contention may
    be the lack of inodes in the VFS layer. We can tentatively implement a
    kernfs-based filesystem to bridge the gap in APIs. The kernfs base
    functionality can serve the role of the Linux inode cache and, the
    filesystem can map syscalls to kernfs inode operations; see the
    `kernfs.Inode` interface.

The FUSE protocol lends itself well to marshaling with `go_marshal`. The various
request and response packets can be defined in the ABI package and converted to
and from the wire format using `go_marshal`.

### Design Goals

-   While filesystem performance is always important, the sentry's FUSE support
    is primarily concerned with compatibility, with performance as a secondary
    concern.

-   Avoiding deadlocks from a hung server daemon.

-   Consider the potential for denial of service from a malicious server daemon.
    Protecting itself from userspace is already a design goal for the sentry,
    but needs additional consideration for FUSE. Normally, an operating system
    doesn't rely on userspace to make progress with filesystem operations. Since
    this changes with FUSE, it opens up the possibility of creating a chain of
    dependencies controlled by userspace, which could affect an entire sandbox.
    For example: a FUSE op can block a syscall, which could be holding a
    subsystem lock, which can then block another task goroutine.

### Milestones

Below are some broad goals to aim for while implementing FUSE in the sentry.
Many FUSE ops can be grouped into broad categories of functionality, and most
ops can be implemented in parallel.

#### Minimal client that can mount a trivial FUSE filesystem.

-   Implement `/dev/fuse` - a character device used to establish an FD for
    communication between the sentry and the server daemon.

-   Implement basic FUSE ops like `FUSE_INIT`.

#### Read-only mount with basic file operations

-   Implement the majority of file, directory and file descriptor FUSE ops. For
    this milestone, we can skip uncommon or complex operations like mmap, mknod,
    file locking, poll, and extended attributes. We can stub these out along
    with any ops that modify the filesystem. The exact list of required ops are
    to be determined, but the goal is to mount a real filesystem as read-only,
    and be able to read contents from the filesystem in the sentry.

#### Full read-write support

-   Implement the remaining FUSE ops and decide if we can omit rarely used
    operations like ioctl.

### Design Details

#### Lifecycle for a FUSE Request

-   User invokes a syscall
-   Sentry prepares corresponding request
    -   If FUSE device is available
        -   Write the request in binary
    -   If FUSE device is full
        -   Kernel task blocked until available
-   Sentry notifies the readers of fuse device that it's ready for read
-   FUSE daemon reads the request and processes it
-   Sentry waits until a reply is written to the FUSE device
    -   but returns directly for async requests
-   FUSE daemon writes to the fuse device
-   Sentry processes the reply
    -   For sync requests, unblock blocked kernel task
    -   For async requests, execute pre-specified callback if any
-   Sentry returns the syscall to the user

#### Channels and Queues for Requests in Different Stages

`connection.initializedChan`

-   a channel that the requests issued before connection initialization blocks
    on.

`fd.queue`

-   a queue of requests that haven’t been read by the FUSE daemon yet.

`fd.completions`

-   a map of the requests that have been prepared but not yet received a
    response, including the ones on the `fd.queue`.

`fd.waitQueue`

-   a queue of waiters that is waiting for the fuse device fd to be available,
    such as the FUSE daemon.

`fd.fullQueueCh`

-   a channel that the kernel task will be blocked on when the fd is not
    available.

#### Basic I/O Implementation

Currently we have implemented basic functionalities of read and write for our
FUSE. We describe the design and ways to improve it here:

##### Basic FUSE Read

The VFS expects implementations of `vfs.FileDescriptionImpl.Read()` and
`vfs.FileDescriptionImpl.PRead()`. When a syscall is made, it will eventually
reach our implementation of those interface functions located at
`pkg/sentry/fsimpl/fuse/regular_file.go` for regular files.

After validation checks of the input, sentry sends `FUSE_READ` requests to the
FUSE daemon. The FUSE daemon returns data after the `fuse_out_header` as the
responses. For the first version, we create a copy in kernel memory of those
data. They are represented as a byte slice in the marshalled struct. This
happens as a common process for all the FUSE responses at this moment at
`pkg/sentry/fsimpl/fuse/dev.go:writeLocked()`. We then directly copy from this
intermediate buffer to the input buffer provided by the read syscall.

There is an extra requirement for FUSE: When mounting the FUSE fs, the mounter
or the FUSE daemon can specify a `max_read` or a `max_pages` parameter. They are
the upperbound of the bytes to read in each `FUSE_READ` request. We implemented
the code to handle the fragmented reads.

To improve the performance: ideally we should have buffer cache to copy those
data from the responses of FUSE daemon into, as is also the design of several
other existing file system implementations for sentry, instead of a single-use
temporary buffer. Directly mapping the memory of one process to another could
also boost the performance, but to keep them isolated, we did not choose to do
so.

##### Basic FUSE Write

The VFS invokes implementations of `vfs.FileDescriptionImpl.Write()` and
`vfs.FileDescriptionImpl.PWrite()` on the regular file descriptor of FUSE when a
user makes write(2) and pwrite(2) syscall.

For valid writes, sentry sends the bytes to write after a `FUSE_WRITE` header
(can be regarded as a request with 2 payloads) to the FUSE daemon. For the first
version, we allocate a buffer inside kernel memory to store the bytes from the
user, and copy directly from that buffer to the memory of FUSE daemon. This
happens at `pkg/sentry/fsimpl/fuse/dev.go:readLocked()`

The parameters `max_write` and `max_pages` restrict the number of bytes in one
`FUSE_WRITE`. There are code handling fragmented writes in current
implementation.

To have better performance: the extra copy created to store the bytes to write
can be replaced by the buffer cache as well.

# Appendix

## FUSE Protocol

The FUSE protocol is a request-response protocol. All requests are initiated by
the client. The wire-format for the protocol is raw C structs serialized to
memory.

All FUSE requests begin with the following request header:

```c
struct fuse_in_header {
  uint32_t len;       // Length of the request, including this header.
  uint32_t opcode;    // Requested operation.
  uint64_t unique;    // A unique identifier for this request.
  uint64_t nodeid;    // ID of the filesystem object being operated on.
  uint32_t uid;       // UID of the requesting process.
  uint32_t gid;       // GID of the requesting process.
  uint32_t pid;       // PID of the requesting process.
  uint32_t padding;
};
```

The request is then followed by a payload specific to the `opcode`.

All responses begin with this response header:

```c
struct fuse_out_header {
  uint32_t len;       // Length of the response, including this header.
  int32_t  error;     // Status of the request, 0 if success.
  uint64_t unique;    // The unique identifier from the corresponding request.
};
```

The response payload also depends on the request `opcode`. If `error != 0`, the
response payload must be empty.

### Operations

The following is a list of all FUSE operations used in `fuse_in_header.opcode`
as of Linux v4.4, and a brief description of their purpose. These are defined in
`uapi/linux/fuse.h`. Many of these have a corresponding request and response
payload struct; `fuse(4)` has details for some of these. We also note how these
operations map to the sentry virtual filesystem.

#### FUSE meta-operations

These operations are specific to FUSE and don't have a corresponding action in a
generic filesystem.

-   `FUSE_INIT`: This operation initializes a new FUSE filesystem, and is the
    first message sent by the client after mount. This is used for version and
    feature negotiation. This is related to `mount(2)`.
-   `FUSE_DESTROY`: Teardown a FUSE filesystem, related to `unmount(2)`.
-   `FUSE_INTERRUPT`: Interrupts an in-flight operation, specified by the
    `fuse_in_header.unique` value provided in the corresponding request header.
    The client can send at most one of these per request, and will enter an
    uninterruptible wait for a reply. The server is expected to reply promptly.
-   `FUSE_FORGET`: A hint to the server that server should evict the indicate
    node from any caches. This is wired up to `(struct
    super_operations).evict_inode` in Linux, which is in turned hooked as the
    inode cache shrinker which is typically triggered by system memory pressure.
-   `FUSE_BATCH_FORGET`: Batch version of `FUSE_FORGET`.

#### Filesystem Syscalls

These FUSE ops map directly to an equivalent filesystem syscall, or family of
syscalls. The relevant syscalls have a similar name to the operation, unless
otherwise noted.

Node creation:

-   `FUSE_MKNOD`
-   `FUSE_MKDIR`
-   `FUSE_CREATE`: This is equivalent to `open(2)` and `creat(2)`, which
    atomically creates and opens a node.

Node attributes and extended attributes:

-   `FUSE_GETATTR`
-   `FUSE_SETATTR`
-   `FUSE_SETXATTR`
-   `FUSE_GETXATTR`
-   `FUSE_LISTXATTR`
-   `FUSE_REMOVEXATTR`

Node link manipulation:

-   `FUSE_READLINK`
-   `FUSE_LINK`
-   `FUSE_SYMLINK`
-   `FUSE_UNLINK`

Directory operations:

-   `FUSE_RMDIR`
-   `FUSE_RENAME`
-   `FUSE_RENAME2`
-   `FUSE_OPENDIR`: `open(2)` for directories.
-   `FUSE_RELEASEDIR`: `close(2)` for directories.
-   `FUSE_READDIR`
-   `FUSE_READDIRPLUS`
-   `FUSE_FSYNCDIR`: `fsync(2)` for directories.
-   `FUSE_LOOKUP`: Establishes a unique identifier for a FS node. This is
    reminiscent of `VirtualFilesystem.GetDentryAt` in that it resolves a path
    component to a node. However the returned identifier is opaque to the
    client. The server must remember this mapping, as this is how the client
    will reference the node in the future.

File operations:

-   `FUSE_OPEN`: `open(2)` for files.
-   `FUSE_RELEASE`: `close(2)` for files.
-   `FUSE_FSYNC`
-   `FUSE_FALLOCATE`
-   `FUSE_SETUPMAPPING`: Creates a memory map on a file for `mmap(2)`.
-   `FUSE_REMOVEMAPPING`: Removes a memory map for `munmap(2)`.

File locking:

-   `FUSE_GETLK`
-   `FUSE_SETLK`
-   `FUSE_SETLKW`
-   `FUSE_COPY_FILE_RANGE`

File descriptor operations:

-   `FUSE_IOCTL`
-   `FUSE_POLL`
-   `FUSE_LSEEK`

Filesystem operations:

-   `FUSE_STATFS`

#### Permissions

-   `FUSE_ACCESS` is used to check if a node is accessible, as part of many
    syscall implementations. Maps to `vfs.FilesystemImpl.AccessAt` in the
    sentry.

#### I/O Operations

These ops are used to read and write file pages. They're used to implement both
I/O syscalls like `read(2)`, `write(2)` and `mmap(2)`.

-   `FUSE_READ`
-   `FUSE_WRITE`

#### Miscellaneous

-   `FUSE_FLUSH`: Used by the client to indicate when a file descriptor is
    closed. Distinct from `FUSE_FSYNC`, which corresponds to an `fsync(2)`
    syscall from the user. Maps to `vfs.FileDescriptorImpl.Release` in the
    sentry.
-   `FUSE_BMAP`: Old address space API for block defrag. Probably not needed.
-   `FUSE_NOTIFY_REPLY`: [TODO: what does this do?]

# References

-   [fuse(4) Linux manual page](https://www.man7.org/linux/man-pages/man4/fuse.4.html)
-   [Linux kernel FUSE documentation](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
-   [The reference implementation of the Linux FUSE (Filesystem in Userspace)
    interface](https://github.com/libfuse/libfuse)
-   [The kernel interface of FUSE](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/fuse.h)
