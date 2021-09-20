# Replacing 9P

NOTE: LISAFS is **NOT** production ready. There are still some security concerns
that must be resolved first.

## Background

The Linux filesystem model consists of the following key aspects (modulo mounts,
which are outside the scope of this discussion):

-   A `struct inode` represents a "filesystem object", such as a directory or a
    regular file. "Filesystem object" is most precisely defined by the practical
    properties of an inode, such as an immutable type (regular file, directory,
    symbolic link, etc.) and its independence from the path originally used to
    obtain it.

-   A `struct dentry` represents a node in a filesystem tree. Semantically, each
    dentry is immutably associated with an inode representing the filesystem
    object at that position. (Linux implements optimizations involving reuse of
    unreferenced dentries, which allows their associated inodes to change, but
    this is outside the scope of this discussion.)

-   A `struct file` represents an open file description (hereafter FD) and is
    needed to perform I/O. Each FD is immutably associated with the dentry
    through which it was opened.

The current gVisor virtual filesystem implementation (hereafter VFS1) closely
imitates the Linux design:

-   `struct inode` => `fs.Inode`

-   `struct dentry` => `fs.Dirent`

-   `struct file` => `fs.File`

gVisor accesses most external filesystems through a variant of the 9P2000.L
protocol, including extensions for performance (`walkgetattr`) and for features
not supported by vanilla 9P2000.L (`flushf`, `lconnect`). The 9P protocol family
is inode-based; 9P fids represent a file (equivalently "file system object"),
and the protocol is structured around alternatively obtaining fids to represent
files (with `walk` and, in gVisor, `walkgetattr`) and performing operations on
those fids.

In the sections below, a **shared** filesystem is a filesystem that is *mutably*
accessible by multiple concurrent clients, such that a **non-shared** filesystem
is a filesystem that is either read-only or accessible by only a single client.

## Problems

### Serialization of Path Component RPCs

Broadly speaking, VFS1 traverses each path component in a pathname, alternating
between verifying that each traversed dentry represents an inode that represents
a searchable directory and moving to the next dentry in the path.

In the context of a remote filesystem, the structure of this traversal means
that - modulo caching - a path involving N components requires at least N-1
*sequential* RPCs to obtain metadata for intermediate directories, incurring
significant latency. (In vanilla 9P2000.L, 2(N-1) RPCs are required: N-1 `walk`
and N-1 `getattr`. We added the `walkgetattr` RPC to reduce this overhead.) On
non-shared filesystems, this overhead is primarily significant during
application startup; caching mitigates much of this overhead at steady state. On
shared filesystems, where correct caching requires revalidation (requiring RPCs
for each revalidated directory anyway), this overhead is consistently ruinous.

### Inefficient RPCs

9P is not exceptionally economical with RPCs in general. In addition to the
issue described above:

-   Opening an existing file in 9P involves at least 2 RPCs: `walk` to produce
    an unopened fid representing the file, and `lopen` to open the fid.

-   Creating a file also involves at least 2 RPCs: `walk` to produce an unopened
    fid representing the parent directory, and `lcreate` to create the file and
    convert the fid to an open fid representing the created file. In practice,
    both the Linux and gVisor 9P clients expect to have an unopened fid for the
    created file (necessitating an additional `walk`), as well as attributes for
    the created file (necessitating an additional `getattr`), for a total of 4
    RPCs. (In a shared filesystem, where whether a file already exists can
    change between RPCs, a correct implementation of `open(O_CREAT)` would have
    to alternate between these two paths (plus `clunk`ing the temporary fid
    between alternations, since the nature of the `fid` differs between the two
    paths). Neither Linux nor gVisor implement the required alternation, so
    `open(O_CREAT)` without `O_EXCL` can spuriously fail with `EEXIST` on both.)

-   Closing (`clunk`ing) a fid requires an RPC. VFS1 issues this RPC
    asynchronously in an attempt to reduce critical path latency, but scheduling
    overhead makes this not clearly advantageous in practice.

-   `read` and `readdir` can return partial reads without a way to indicate EOF,
    necessitating an additional final read to detect EOF.

-   Operations that affect filesystem state do not consistently return updated
    filesystem state. In gVisor, the client implementation attempts to handle
    this by tracking what it thinks updated state "should" be; this is complex,
    and especially brittle for timestamps (which are often not arbitrarily
    settable). In Linux, the client implemtation invalidates cached metadata
    whenever it performs such an operation, and reloads it when a dentry
    corresponding to an inode with no valid cached metadata is revalidated; this
    is simple, but necessitates an additional `getattr`.

### Dentry/Inode Ambiguity

As noted above, 9P's documentation tends to imply that unopened fids represent
an inode. In practice, most filesystem APIs present very limited interfaces for
working with inodes at best, such that the interpretation of unopened fids
varies:

-   Linux's 9P client associates unopened fids with (dentry, uid) pairs. When
    caching is enabled, it also associates each inode with the first fid opened
    writably that references that inode, in order to support page cache
    writeback.

-   gVisor's 9P client associates unopened fids with inodes, and also caches
    opened fids in inodes in a manner similar to Linux.

-   The runsc fsgofer associates unopened fids with both "dentries" (host
    filesystem paths) and "inodes" (host file descriptors); which is used
    depends on the operation invoked on the fid.

For non-shared filesystems, this confusion has resulted in correctness issues
that are (in gVisor) currently handled by a number of coarse-grained locks that
serialize renames with all other filesystem operations. For shared filesystems,
this means inconsistent behavior in the presence of concurrent mutation.

## Design

Almost all Linux filesystem syscalls describe filesystem resources in one of two
ways:

-   Path-based: A filesystem position is described by a combination of a
    starting position and a sequence of path components relative to that
    position, where the starting position is one of:

    -   The VFS root (defined by mount namespace and chroot), for absolute paths

    -   The VFS position of an existing FD, for relative paths passed to `*at`
        syscalls (e.g. `statat`)

    -   The current working directory, for relative paths passed to non-`*at`
        syscalls and `*at` syscalls with `AT_FDCWD`

-   File-description-based: A filesystem object is described by an existing FD,
    passed to a `f*` syscall (e.g. `fstat`).

Many of our issues with 9P arise from its (and VFS') interposition of a model
based on inodes between the filesystem syscall API and filesystem
implementations. We propose to replace 9P with a protocol that does not feature
inodes at all, and instead closely follows the filesystem syscall API by
featuring only path-based and FD-based operations, with minimal deviations as
necessary to ameliorate deficiencies in the syscall interface (see below). This
approach addresses the issues described above:

-   Even on shared filesystems, most application filesystem syscalls are
    translated to a single RPC (possibly excepting special cases described
    below), which is a logical lower bound.

-   The behavior of application syscalls on shared filesystems is
    straightforwardly predictable: path-based syscalls are translated to
    path-based RPCs, which will re-lookup the file at that path, and FD-based
    syscalls are translated to FD-based RPCs, which use an existing open file
    without performing another lookup. (This is at least true on gofers that
    proxy the host local filesystem; other filesystems that lack support for
    e.g. certain operations on FDs may have different behavior, but this
    divergence is at least still predictable and inherent to the underlying
    filesystem implementation.)

Note that this approach is only feasible in gVisor's next-generation virtual
filesystem (VFS2), which does not assume the existence of inodes and allows the
remote filesystem client to translate whole path-based syscalls into RPCs. Thus
one of the unavoidable tradeoffs associated with such a protocol vs. 9P is the
inability to construct a Linux client that is performance-competitive with
gVisor.

### File Permissions

Many filesystem operations are side-effectual, such that file permissions must
be checked before such operations take effect. The simplest approach to file
permission checking is for the sentry to obtain permissions from the remote
filesystem, then apply permission checks in the sentry before performing the
application-requested operation. However, this requires an additional RPC per
application syscall (which can't be mitigated by caching on shared filesystems).
Alternatively, we may delegate file permission checking to gofers. In general,
file permission checks depend on the following properties of the accessor:

-   Filesystem UID/GID

-   Supplementary GIDs

-   Effective capabilities in the accessor's user namespace (i.e. the accessor's
    effective capability set)

-   All UIDs and GIDs mapped in the accessor's user namespace (which determine
    if the accessor's capabilities apply to accessed files)

We may choose to delay implementation of file permission checking delegation,
although this is potentially costly since it doubles the number of required RPCs
for most operations on shared filesystems. We may also consider compromise
options, such as only delegating file permission checks for accessors in the
root user namespace.

### Symbolic Links

gVisor usually interprets symbolic link targets in its VFS rather than on the
filesystem containing the symbolic link; thus e.g. a symlink to
"/proc/self/maps" on a remote filesystem resolves to said file in the sentry's
procfs rather than the host's. This implies that:

-   Remote filesystem servers that proxy filesystems supporting symlinks must
    check if each path component is a symlink during path traversal.

-   Absolute symlinks require that the sentry restart the operation at its
    contextual VFS root (which is task-specific and may not be on a remote
    filesystem at all), so if a remote filesystem server encounters an absolute
    symlink during path traversal on behalf of a path-based operation, it must
    terminate path traversal and return the symlink target.

-   Relative symlinks begin target resolution in the parent directory of the
    symlink, so in theory most relative symlinks can be handled automatically
    during the path traversal that encounters the symlink, provided that said
    traversal is supplied with the number of remaining symlinks before `ELOOP`.
    However, the new path traversed by the symlink target may cross VFS mount
    boundaries, such that it's only safe for remote filesystem servers to
    speculatively follow relative symlinks for side-effect-free operations such
    as `stat` (where the sentry can simply ignore results that are inapplicable
    due to crossing mount boundaries). We may choose to delay implementation of
    this feature, at the cost of an additional RPC per relative symlink (note
    that even if the symlink target crosses a mount boundary, the sentry will
    need to `stat` the path to the mount boundary to confirm that each traversed
    component is an accessible directory); until it is implemented, relative
    symlinks may be handled like absolute symlinks, by terminating path
    traversal and returning the symlink target.

The possibility of symlinks (and the possibility of a compromised sentry) means
that the sentry may issue RPCs with paths that, in the absence of symlinks,
would traverse beyond the root of the remote filesystem. For example, the sentry
may issue an RPC with a path like "/foo/../..", on the premise that if "/foo" is
a symlink then the resulting path may be elsewhere on the remote filesystem. To
handle this, path traversal must also track its current depth below the remote
filesystem root, and terminate path traversal if it would ascend beyond this
point.

### Path Traversal

Since path-based VFS operations will translate to path-based RPCs, filesystem
servers will need to handle path traversal. From the perspective of a given
filesystem implementation in the server, there are two basic approaches to path
traversal:

-   Inode-walk: For each path component, obtain a handle to the underlying
    filesystem object (e.g. with `open(O_PATH)`), check if that object is a
    symlink (as described above) and that that object is accessible by the
    caller (e.g. with `fstat()`), then continue to the next path component (e.g.
    with `openat()`). This ensures that the checked filesystem object is the one
    used to obtain the next object in the traversal, which is intuitively
    appealing. However, while this approach works for host local filesystems, it
    requires features that are not widely supported by other filesystems.

-   Path-walk: For each path component, use a path-based operation to determine
    if the filesystem object currently referred to by that path component is a
    symlink / is accessible. This is highly portable, but suffers from quadratic
    behavior (at the level of the underlying filesystem implementation, the
    first path component will be traversed a number of times equal to the number
    of path components in the path).

The implementation should support either option by delegating path traversal to
filesystem implementations within the server (like VFS and the remote filesystem
protocol itself), as inode-walking is still safe, efficient, amenable to FD
caching, and implementable on non-shared host local filesystems (a sufficiently
common case as to be worth considering in the design).

Both approaches are susceptible to race conditions that may permit sandboxed
filesystem escapes:

-   Under inode-walk, a malicious application may cause a directory to be moved
    (with `rename`) during path traversal, such that the filesystem
    implementation incorrectly determines whether subsequent inodes are located
    in paths that should be visible to sandboxed applications.

-   Under path-walk, a malicious application may cause a non-symlink file to be
    replaced with a symlink during path traversal, such that following path
    operations will incorrectly follow the symlink.

Both race conditions can, to some extent, be mitigated in filesystem server
implementations by synchronizing path traversal with the hazardous operations in
question. However, shared filesystems are frequently used to share data between
sandboxed and unsandboxed applications in a controlled way, and in some cases a
malicious sandboxed application may be able to take advantage of a hazardous
filesystem operation performed by an unsandboxed application. In some cases,
filesystem features may be available to ensure safety even in such cases (e.g.
[the new openat2() syscall](https://man7.org/linux/man-pages/man2/openat2.2.html)),
but it is not clear how to solve this problem in general. (Note that this issue
is not specific to our design; rather, it is a fundamental limitation of
filesystem sandboxing.)

### Filesystem Multiplexing

A given sentry may need to access multiple distinct remote filesystems (e.g.
different volumes for a given container). In many cases, there is no advantage
to serving these filesystems from distinct filesystem servers, or accessing them
through distinct connections (factors such as maximum RPC concurrency should be
based on available host resources). Therefore, the protocol should support
multiplexing of distinct filesystem trees within a single session. 9P supports
this by allowing multiple calls to the `attach` RPC to produce fids representing
distinct filesystem trees, but this is somewhat clunky; we propose a much
simpler mechanism wherein each message that conveys a path also conveys a
numeric filesystem ID that identifies a filesystem tree.

## Alternatives Considered

### Additional Extensions to 9P

There are at least three conceptual aspects to 9P:

-   Wire format: messages with a 4-byte little-endian size prefix, strings with
    a 2-byte little-endian size prefix, etc. Whether the wire format is worth
    retaining is unclear; in particular, it's unclear that the 9P wire format
    has a significant advantage over protobufs, which are substantially easier
    to extend. Note that the official Go protobuf implementation is widely known
    to suffer from a significant number of performance deficiencies, so if we
    choose to switch to protobuf, we may need to use an alternative toolchain
    such as `gogo/protobuf` (which is also widely used in the Go ecosystem, e.g.
    by Kubernetes).

-   Filesystem model: fids, qids, etc. Discarding this is one of the motivations
    for this proposal.

-   RPCs: Twalk, Tlopen, etc. In addition to previously-described
    inefficiencies, most of these are dependent on the filesystem model and
    therefore must be discarded.

### FUSE

The FUSE (Filesystem in Userspace) protocol is frequently used to provide
arbitrary userspace filesystem implementations to a host Linux kernel.
Unfortunately, FUSE is also inode-based, and therefore doesn't address any of
the problems we have with 9P.

### virtio-fs

virtio-fs is an ongoing project aimed at improving Linux VM filesystem
performance when accessing Linux host filesystems (vs. virtio-9p). In brief, it
is based on:

-   Using a FUSE client in the guest that communicates over virtio with a FUSE
    server in the host.

-   Using DAX to map the host page cache into the guest.

-   Using a file metadata table in shared memory to avoid VM exits for metadata
    updates.

None of these improvements seem applicable to gVisor:

-   As explained above, FUSE is still inode-based, so it is still susceptible to
    most of the problems we have with 9P.

-   Our use of host file descriptors already allows us to leverage the host page
    cache for file contents.

-   Our need for shared filesystem coherence is usually based on a user
    requirement that an out-of-sandbox filesystem mutation is guaranteed to be
    visible by all subsequent observations from within the sandbox, or vice
    versa; it's not clear that this can be guaranteed without a synchronous
    signaling mechanism like an RPC.
