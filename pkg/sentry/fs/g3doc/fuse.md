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

The sentry's FUSE client targets VFS2 and has the following components:

-   An implementation of `/dev/fuse`.

-   A VFS2 filesystem for mapping syscalls to FUSE ops. Since we're targeting
    VFS2, one point of contention may be the lack of inodes in VFS2. We can
    tentatively implement a kernfs-based filesystem to bridge the gap in APIs.
    The kernfs base functionality can serve the role of the Linux inode cache
    and, the filesystem can map VFS2 syscalls to kernfs inode operations; see
    the `kernfs.Inode` interface.

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

-   Implement basic FUSE ops like `FUSE_INIT`, `FUSE_DESTROY`.

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

## Mounting a FUSE filesystem

1. Libfuse/fusermount:
In `fuse/mount.c`:
```
fd = open("/dev/fuse"); // Say fd == 4.
sys_mount("/dev/fuse", /fuse/mount/point", "fuse", MOUNT_FLAGS, "fd=4");

```

2. Kernel (client):

In linux, `sys_mount` -> `(struct fs_context_operations).get_tree` ->
`fill_super`. FUSE's `fill_super` is implemented in `fs/fuse/inode.c`.

FUSE's `fill_super` quques a `FUSE_INIT` op and returns, which completes
`sys_mount`.

3. Libfuse (server):

FS-specific handling of `FUSE_INIT` performs the equivalent of `fill_super` on
the server-side. `FUSE_INIT` returns, fully initializing the filesystem.

## Life of a filesystem syscall on a FUSE filesystem

Let's trace how filesystem syscall is handled by a FUSE filesystem mounted in a
sandbox. Let's say a FUSE filesystem is mounted on `/fuse` and looks like this:

```sh
$ ls /fuse
file1
```

A userspace application inside the sandbox issues a filesystem syscall:

```c
struct stat s;
stat("/fuse/file1", &s);
```

This is intercepted by the sentry and starts in the `stat(2)` syscall handler
`pkg/sentry/syscalls/linux/vfs2/filesystem.go:Stat()`, which then calls
`vfs.VirtualFilesystem.StatAt`.

The VFS layer resolves the path `/fuse/file1` to our FUSE mount, and calls
fusefs's implementation of `vfs.FilesystemImpl.StatAt`.

At a high level, all filesystem syscalls cause fusefs to queue a request, then
block the task goroutine until the server responds. In Linux, `stat(2)` maps to
`(struct inode_operations).getattr` which then maps to a `FUSE_GETATTR`
operation. The relevant FUSE request and response headers are:

```c
struct fuse_attr {
    uint64_t    ino;
    uint64_t    size;
    uint64_t    blocks;
    uint64_t    atime;
    uint64_t    mtime;
    uint64_t    ctime;
    uint32_t    atimensec;
    uint32_t    mtimensec;
    uint32_t    ctimensec;
    uint32_t    mode;
    uint32_t    nlink;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    rdev;
    uint32_t    blksize;
    uint32_t    padding;
};

struct fuse_getattr_in {
    uint32_t    getattr_flags;
    uint32_t    dummy;
    uint64_t    fh;
};

struct fuse_attr_out {
    uint64_t    attr_valid; /* Cache timeout for the attributes */
    uint32_t    attr_valid_nsec;
    uint32_t    dummy;
    struct fuse_attr attr;
};
```

The FUSE device instance is reponsible for holding a list of pending requests
for the service, and unblocking the request initiator on response. The FUSE
device implementation may look something like this:

`pkg/sentry/devices/fuse/fuse.go`:
```go
package fusedev

type OpID uint64

// Request represents a FUSE operation request that hasn't been sent to the
// server yet.
type Request struct {
    requestListEntry

    id OpID
    data []byte
}

// FutureResponse represents an in-flight request, that may or may not have
// completed yet. Convert it to a resolved Response by calling Resolve, but note
// that this may block.
type FutureResponse struct {
    ch <-chan struct{}
    hdr *linux.FuseOutHeader
    data []byte
}

func newFutureResponse() *FutureResponse {
    return &FutureResponse{
        ch: make(chan struct{})
    }
}

// Resolve blocks until the server responds to its corresponding request, then
// returns a resolved response.
func (r *FutureResponse) Resolve(t *kernel.Task) (*Response, error) {
    if err := t.Block(ch); err != nil {
        return nil, err
    }

    return &Response{
        hdr: *r.hdr
        data: r.data
    }
}

// Response represents an actual response from the server, including the
// response payload.
type Response struct {
    hdr linux.FuseOutHeader
    data []byte
}

func (r *Response) Error() error {
    if r.hdr.Error != 0 {
        mappedErr := ... // Map to some error in the syserror package.
        return mappedErr
    }
    return nil
}

func (r *Response) UnmarshalPayload(m marshal.Marshallable) {
    hdrLen := r.hdr.SizeBytes()
    haveDataLen := r.hdr.Len - hdrLen
    wantDataLen = m.SizeBytes()

    if haveDataLen < wantDataLen {
        return nil, ErrPayloadTooShort{wantDataLen, haveDataLen}
    }
    m.UnmarshalUnsafe(r.data[hdrLen:])
}

// Device implements vfs.Device for /dev/fuse.
type Device struct {
    nextOpID uint64

    queue requestList // Linked list of Requests.
    completions map[OpID]*FutureResponse

    readCursor uint64

    writeBuf [(*linux.FuseOutHeader)(nil).SizeBytes()]byte
    writeCursorFR *FutureResponse // The current FR being copied from server
    writeCursor uint64
}

func (d *Device) NewRequest(creds auth.Credentials, pid uint32, ino uint32, opcode linux.FuseOpcode, payload marshal.Marshallable) (Request, error) {
    hdrLen := (*linux.FuseInHeader)(nil).SizeBytes()
    hdr := linux.FuseInHeader{
        Len: hdrLen + payload.SizeBytes()
        Opcode: opcode,
        Unique: d.nextOpID,
        NodeID: ino,
        UID: creds.EffectiveKUID,
        GID: creds.EffectiveKGID,
        PID: pid,
    }
    d.nextOpID++

    buf := make([]byte, hdr.Len)
    hdr.MarshalUnsafe(buf[:hdrLen])
    payload.MarshalUnsafe(buf[hdrLen:])

    return Request{
        id: hdr.Unique,
        data: buf,
    }
}

func (d *Device) Queue(r *Request) *FutureResponse {
    d.queue.PushBack(r)
    fut := newFutureResponse()
    d.completions[r.id] = fut
    return fut
}

func (d *Device) Call(t *kernel.Task, r Request) (*Response, error) {
    fut := d.Queue(r)
    return fut.Resolve(t)
}
```

From the Device's perspective, a FUSE operation starts as a `Request`, which
then turns into a `FutureResponse` when it's sent to the server, which finally
becomes a `Response` after the server sends back the response.

Going back to fusefs, `vfs.FilesystemImpl.StatAt` is implemented by `kernfs` and
eventually calls `kernfs.Inode.Stat`. Fusefs' implementation of it may look
something like this:

`pkg/sentry/fsimpl/fuse/filesystem.go`:
```go
package fuse

// filesystem implements vfs.FilesystemImpl for fusefs.
type filesystem struct {
    // Inherit methods transforming vfs path-based filesystem operations to the
    // Inode interface.
    kernfs.Filesystem

    dev fusedev.Device
}

// inode implements kernfs.Inode.
type inode struct {
    fs *filesystem
    ino uint64
    ...
}

func (i *inode) Stat(ctx context.Context, fs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
    t := kernel.TaskFromContext(ctx)
    creds := auth.CredentialsFromContext(ctx)
    reqOpts := linux.FuseGetAttrIn{
        GetAttrFlags: opts.Flags
        ...
    }
    req, err := i.fs.dev.NewRequest(creds, uint32(t.ThreadID()), i.ino, linux.FUSE_GETATTR, &reqOpts)
    if err != nil {
        return linux.Statx{}, err
    }
    resp, err := i.fs.dev.Call(t, &req) // This blocks until server responds!
    if err != nil {
        // Error on the client side, maybe problems with queuing request or
        // sleep interrupted.
        return linux.Statx{}, err
    }
    if err := resp.Error(); err != nil {
        // Error from the server side.
        return linux.Statx{}, err
    }
    var attr linux.FuseAttr
    if err := resp.UnmarshalPayload(&attr); err != nil {
        return linux.Statx{}, err
    }
    return linux.Statx{
        ... // Construct from attr.
    }, err
}
```

This covers the client side of a FUSE FS syscall. What about the server side?
`fusedev.Device` also implements the `vfs.FileDesciptionImpl` interface, which
the server uses to pull requests out of `fusedev.Device.requestList` by calling
`fusedev.Device.Read`. Once the server is done, it sends back its response by
writing to the fuse FD, which calls `fusedev.Device.Write`. The FD
implementations may look something like this:

`pkg/sentry/devices/fuse/fuse.go`:
```go
func (d *Device) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
    req := d.requestList.Front()
    if req == nil {
        // Nothing to send, probably block the read until something becomes
        // available?
        return 0, syserr.ErrWouldBlock
    }

    if d.readCursor >= req.hdr.Len {
        // Cursor points past end of current request payload? Reset the cursor,
        // remove the front request and try again.
        d.readCursor = 0
        d.requestList.Remove(req)
        return d.Read(ctx, dst, opts)
    }

    n, err := dst.Copyout(ctx, req.data[d.readCursor:])
    d.readCursor += n

    if d.readCursor >= req.hdr.Len {
        // Fully done with this req, remove it from the queue.
        d.requestList.Remove(req)
        d.readCursor = 0
    }
    return n, err
}

func (d *Device) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
    var cn, n int64
    var err error
    hdrLen := (*linux.FuseOutHeader)(nil).SizeByte()

    for src.NumBytes() > 0 {
        if d.writeCursorFR != nil {
            // Already have common header, and we're now copying the payload.
            wantBytes := d.writeCursorFR.hdr.Len
            cn, err = src.CopyIn(ctx, d.writeCursorFR.data[d.writeCursor:wantBytes])
            if err != nil {
                break
            }
            n += cn
            d.writeCursor += cn
            if d.writeCursor == wantBytes {
                // Done reading this full response. Clean up and unblock the
                // initiator.
                close(d.writeCursorFR.ch)
                d.writeCursorFR = nil
                d.writeCursor = 0
            }
            continue // Check if we have more data in src.
        }

        // Don't have the full common response header yet.
        assert(d.writeCursor < hdrLen)
        wantBytes := hdrLen - d.writeCursor
        cn, err = src.CopyIn(ctx, d.writeBuf[d.writeCursor:wantBytes])
        if err != nil {
            break
        }
        n += cn
        d.writeCursor += cn
        if d.writeCursor == hdrLen {
            // Have full header. Use it to fetch the actual FutureResponse from
            // the device's completions map.
            var hdr linux.FuseOutHeader
            hdr.UnmarshalBytes(d.writeBuf)
            memset(d.writeBuf, 0)
            fut, ok := d.completions[hdr.Unique]
            if !ok {
                // ?? Server sent us a response for a request we never sent?
                return 0, ErrDontRecognizeOpID
            }
            delete(d.completions, hdr.Unique)
            fut.hdr = &hdr
            d.writeCursorFR = fut
            // Next iteration will now try read the complete request, if src has
            // any data remaining.
        }
    }

    return n, err
}

func (d *Device) Readiness(mask waiter.EventMask) waiter.EventMask {
    var ready waiter.EventMask
    ready |= waiter.EventOut // FD is always writable
    if !d.requestList.Empty() {
        // Have reqs available, FD is readable.
        ready |= waiter.EventIn
    }
    return ready & mask
}
```

# References

-   [fuse(4) Linux manual page](https://www.man7.org/linux/man-pages/man4/fuse.4.html)
-   [Linux kernel FUSE documentation](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
-   [The reference implementation of the Linux FUSE (Filesystem in Userspace)
    interface](https://github.com/libfuse/libfuse)
-   [The kernel interface of FUSE](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/fuse.h)
