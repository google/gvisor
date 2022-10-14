# LInux SAndbox FileSystem (LISAFS) Protocol

## Overview

LISAFS stands for Linux Sandbox File System. It is a protocol that can be used
by sandboxed (untrusted) applications to communicate with a trusted RPC server.
The untrusted client can make RPCs to perform file system operations on the
server.

### Inspiration

LISAFS was mainly inspired by gVisor’s need for such a protocol. Historically,
gVisor used a custom extension of the 9P2000.L protocol to talk to gofer
processes. 9P proved to be chatty in certain situations, inducing a lot of RPCs.
The overhead associated with a round trip to the server seemed to be
deteriorating performance. LISAFS aims to be more economical.

## Background

This protocol aims to safely expose filesystem resources over a connection
between an untrusted client and a trusted server. Usually these filesystem
resources are exposed by path-based APIs (e.g. Linux’s path based syscalls).
However, such path based operations are susceptible to symlink-based attacks.
Because path based operations require re-walking to the file on the server; a
malicious client might be able to trick the server into walking on a malicious
symlink on the path.

Hence, LISAFS focuses on providing an API which is file-descriptor based (e.g.
Linux’s FD-based syscalls). LISAFS provides various FD abstractions over the
protocol which can be opened by the client and used to perform filesystem
operations. Filesystem operations happen **on** these FD abstractions. Because
of that, these FD abstractions on the server do not need to perform rewalks.
They can simply reuse the host FD or whatever resource is attached to that file.
RPCs in lisafs are operations on these FD abstractions.

## Concepts

### Server

A LISAFS server is an agent that serves one file system tree that may be
accessed/mutated via RPCs by LISAFS clients. The server is a trusted process.
For security reasons, the server must assume that the client can be potentially
compromised and act maliciously.

#### Concurrency

The server must execute file system operations under appropriate concurrency
constraints to prevent a malicious client from tricking the server into walking
on hazardous symlinks and escaping the filesystem tree being served. To provide
such concurrency guarantees for each node in the file system tree, the server
must maintain the file system tree in memory with synchronization primitives for
each node. Server must provide the following concurrency guarantees:

-   None: Provides no guarantees; any operation could be concurrently happening
    on this node. This can be provided to operations that don’t require touching
    the file system tree at all.
-   Read: Guarantees to be exclusive of any write operation on this node or
    global operation. But this may be executed concurrently with other read
    operations occurring on this node.
-   Write: Guarantees to be exclusive of any read or write operation occurring
    on this node or any global operation.
-   Global: Guarantees to be exclusive of any read, write or global operation
    across all nodes.

Some things that follow:

-   Read guarantee on a node `A` also guarantees that the client can not
    invalidate any node on the path from root to `A`. To invalidate a node, the
    client must delete it. To delete any intermediate node (directory) up until
    `A`, the client must first delete all children of that directory including
    `A`, which is impossible because that requires a write guarantee on `A`.
-   If there are two clients accessing independent file system *subtrees* from
    the same server, it might be beneficial to configure them to use different
    server objects (maybe in the same agent process itself) to avoid unnecessary
    synchronization overheads caused by server-wide locking.

### Client

A LISAFS client is an untrusted process which can potentially be malicious. The
client is considered to be running alongside an untrusted workload in a sandbox
environment. As part of defense in depth strategy, it is assumed that the
sandbox environment can be compromised due to security vulnerabilities. And so
the client should be treated as a potentially malicious entity. The client is
immutably associated with a server and a file system tree on the server that it
can access.

### Connection

A connection is a session established between a client and a server. The
connection can only be started using the socket communicator (see below). See
“Setup & Configuration” section to see how the initial communicator can be set
up.

#### File Descriptor

Linux provides file system resources via either path-based syscalls or FD-based
syscalls. LISAFS attempts to emulate Linux's FD-based file system syscalls.
Path-based syscalls are slower because they have to rewalk the host kernel’s
dentry tree and they are also susceptible to symlink based attacks. So LISAFS
provides various FD abstractions to perform various file system operations –
very similar to the FD-based syscalls. Each FD abstraction is identified by an
FDID. FDIDs are local to the connection they belong to. An FDID is defined by a
uint64 integer. The server implementation does not have to keep track of free
FDIDs to reuse – which requires additional memory. Instead the server can
naively increment a counter to eternity to generate new FDIDs. uint64 is large
enough.

### Communicator

A communicator is a communication pathway between the server and client. The
client can send messages on a communicator and expect a response from the server
on that communicator. A connection starts off with just 1 socket communicator.
The client can request to create more communicators by making certain RPCs over
existing communicators. The server may choose to deny additional communicators
after some arbitrary limit has been reached.

A communicator may also be capable of sending open file descriptors to the peer
endpoint. This can be done with SCM_RIGHTS ancillary messages over a socket.
Hence forth, this is called “donating an FD”. FD donation of course is an
inter-process mechanism and can not be done if the client and server are on
different hosts. But donating FDs enables clients to make staggering
optimizations for IO-intensive workloads and avoid a lot of RPC round-trips and
buffer management overheads. The usage of the donated FDs can be monitored using
seccomp filters around the client.

Each communicator has a header which contains metadata. The communicator header
format is immutable. To enhance/update a communicator header, a new communicator
must be created which uses the new header. A new RPC must be introduced that
sets up such a communicator. The communicator header may optionally contain the
payload length (the size of the message in bytes). The client/server may use
this information to do more efficient buffer management and limit the number of
message bytes to read. However, this information is redundant. The size of the
message in bytes is either predetermined or can be inferred while deserializing.
See “Wire Format” section for more details. If the payload length in header and
the message's manifest size disagree, the message size can be used (or an error
can be returned).

#### Socket Communicator

A socket communicator uses a unix domain socket pair. The client and server own
one end each. The header looks like this:

```
type sockHeader struct {
    payloadLen uint32
    message    uint16
    _          uint16 // Need to make struct packed.
}
```

The socket communicator is only capable of making synchronous RPCs. It can not
be used to make multiple RPCs concurrently. One client thread should acquire
this socket communicator, send a request to the server, block until the response
is received and only then release it. An alternative approach would be to add a
RPC tag in the header and release the communicator after sending a request. The
response from the server would contain the same tag and the client can do
book-keeping and pass the response to the appropriate thread. That would allow
for asynchronous RPCs. If need be, an asynchronous socket communicator can be
introduced as a new communicator.

#### Flipcall Channel Communicator

The channel communicator is inspired from gVisor’s flipcall package
(`pkg/flipcall`) which “implements a protocol providing Fast Local Interprocess
Procedure Calls between mutually-distrusting processes”. In this communicator,
both ends (server and client) own a flipcall endpoint. Flipcall endpoints can
“switch” to the other endpoint synchronously and yield control, hence enabling
synchronous RPCs. For this reason, channel communicators can not accommodate
asynchronous RPCs.

This communicator uses a shared memory region between both flipcall endpoints
into which messages are written. Accessing the memory region is faster than
communicating over a socket which involves making a syscall and passing a buffer
to the kernel which is copied over to the other process. Due to the memory
region being shared between mutually-distrusting processes, the server must be
cautious that a malicious client might concurrently corrupt the memory while the
server is reading it.

The header looks like this:

```
type channelHeader struct {
    // flipcall header
    connState uint32
    dataLen   uint32
    reserved  uint64
    // channel header
    message   uint16
    numFDs    uint8
    _         uint8 // Need to make struct packed.
}
```

#### RPC Overhead

Making an RPC is associated with some RPC overhead which is independent of the
RPC itself. The socket and channel communicator both suffer from scheduling
overhead. The host kernel has to schedule the server’s communicator thread
before the server can process the request. Similarly, after the server responds,
the client’s receiving thread needs to be scheduled again. Using FUTEX_SWAP in
flipcall reduces this overhead. There may be other overheads associated with the
exact mechanism of making the switch.

### Control FD

A control FD is an FD abstraction which is used to perform certain file
operations on a file. It can only be created by performing `Walk` operations
from a directory Control FD. The Walk operation returns a Control FD for each
path component to the client. The Control FD is then immutably associated with
that file node. The client can then use it to perform operations on the
associated file. It is a rather unusual concept. It is not an inode, because
multiple control FDs are allowed to exist on the same file. It is not a file
descriptor because it is not tied to any access mode, i.e. a control FD can
change the underlying host FD’s access mode based on the operation being
performed.

A control FD can modify or traverse the filesystem tree. For example, it
supports operations like Mkdir, Walk, Unlink and Rename. A control FD is the
most fundamental FD abstraction, which can be used to create other FD
abstractions as detailed below.

### Open FD

An Open FD represents an open file descriptor on the protocol. It resonates
closely with a Linux file descriptor. It is associated with the access mode it
was opened with. Its operations are not allowed to modify or traverse the
filesystem tree. It can only be created by performing `Open` operations on a
Control FD (more details later in “RPC Methods” section). An Open FD is also
immutably associated with the Control FD it was opened on.

### Bound Socket FD

A Bound Socket FD represents a `socket(2)` FD on the protocol which has been
`bind(2)`-ed. Operations like `Listen` and `Accept` can be performed on such FDs
to accept connections from the host and donate the accepted FDs to the client.
It can only be created by performing `Bind` operation on a Control FD (more
details later in “RPC Methods” section). A Bound Socket FD is also immutably
associated with a Control FD on the bound socket file.

## Setup & Configuration

The sandbox configuration should define the servers and their sandboxed clients.
The client:server relationship can be many:1. The configuration must also define
the path in the server at which each client is mounted. The mount path is
defined via trusted configuration, as opposed to being defined by an RPC from a
potentially compromised client.

The sandbox owner should use this configuration to create `socketpair(2)`s for
each client/server combination. The sandbox owner should then start the sandbox
process (which contains the clients) and the server processes. The sandbox owner
should then donate the socket FDs and their configuration appropriately. The
server should have information about each socket FD’s corresponding client –
what path the client is mounted on, what kinds of RPCs are permissible. The
server can then spawn threads running the socket communicator that block on
reading from these sockets.

For example, gVisor’s runsc, which is an OCI compatible runtime, passes the OCI
runtime spec to its gofer. It additionally passes one end of all the
`socketpair(2)`s to the gofer. The gofer then reads all the mount points from
the runtime spec and uses the sockets to start connections serving those mount
paths.

## RPC Methods

-   All RPC methods must be non-blocking on the server.
-   RPC methods were designed to minimize the number of roundtrips between
    client and server to reduce RPC overhead (see section “RPC Overhead” above)
    incurred by the client.
-   The request and response message structs are defined in this package by the
    names defined below.
-   Each RPC is defined by a Message ID (MID). When the server receives a MID,
    it should read the Request struct associated with that MID. Similarly the
    client should read the Response struct associated with that MID.
-   MID is a uint16 integer. The first 256 MIDs [0,255] are reserved for
    standard LISAFS protocol. Proprietary extensions of LISAFS can use the
    remainder of the available range.

MID | Message      | Request         | Response                                                           | Description
--- | ------------ | --------------- | ------------------------------------------------------------------ | -----------
0   | Error        | N/A             | ErrorResp                                                          | Returned from server to indicate error while handling RPC. If Error is returned, the failed RPC should have no side effects. Any intermediate changes made should be rolled back. This is a response-only message. ErrorResp.errno should be interpreted as a Linux error code.
1   | Mount        |                 | MountResp                                                          | Mount establishes a connection. MountResp.root is a Control FD for the mountpoint, which becomes the root for this connection. The location of the connection’s mountpoint on the server is predetermined as per sandbox configuration. Clients can not request to mount the connection at a certain path, unlike mount(2). MountResp.maxMessageSize dictates the maximum message size the server can tolerate across all communicators. This limit does not include the communicator’s header size. MountResp.supportedMs contains all the MIDs that the server supports. Clients can use this information for checking feature support. The server must provide a read concurrency guarantee on the root node during this operation.
2   | Channel      |                 | ChannelResp<br><br>Donates: \[dataFD, fdSock\]                     | Channel sets up a new communicator based on a shared memory region between the client and server. dataFD is the host FD for the shared memory file. fdSock is a host socket FD that the server will use to donate FDs over this channel. ChannelResp’s dataOffset and dataLength describe the shared memory file region owned by this channel. No concurrency guarantees are needed. ENOMEM is returned to indicate that the server hit the max channels limit.
3   | FStat        | StatReq         | [struct statx](https://man7.org/linux/man-pages/man2/statx.2.html) | Fstat is analogous to fstat(2). It returns struct statx for the file represented by StatReq.fd. FStat may be called on a Control FD or Open FD. The server must provide a read concurrency guarantee on the file node during this operation.
4   | SetStat      | SetStatReq      | SetStatResp                                                        | SetStat does not correspond to any particular syscall. It serves the purpose of fchmod(2), fchown(2), ftruncate(2) and futimesat(2) in one message. This enables client-side optimizations where the client is able to change multiple attributes in 1 RPC. It must be called on Control FDs only. One instance where this is helpful is in overlayfs implementation which requires changing multiple attributes at the same time. The failure of setting one attribute does not terminate the entire operation. SetStatResp.failureMask should be interpreted as stx\_mask and indicates all attributes that failed to be modified. In case failureMask != 0, SetStatResp.failiureErrno indicates any one of the failure errnos. The server must provide a write concurrency guarantee on the file node during this operation.
5   | Walk         | WalkReq         | WalkResp                                                           | Walk walks multiple path components described by WalkReq.path starting from Control FD WalkReq.dirFD. The walk must terminate if a path component is a symlink or a path component does not exist and return all the inodes walked so far. The reason for premature termination of walk is indicated via WalkResp.status. Symlinks can not be walked on the server. The client must Readlink the symlink and rewalk its target + the remaining path. The server must provide a read concurrency guarantee on the directory node being walked and should protect against renames during the entire walk.
6   | WalkStat     | WalkReq         | WalkStatResp                                                       | WalkStat is similar to Walk, except that it only returns the statx results for the path components. It does not return a Control FD for each path component. Additionally, if the first element of WalkReq.path is an empty string, WalkStat also returns the statx results for WalkReq.dirFD. This is useful in scenarios where the client already has the Control FDs for a path but just needs statx results to revalidate its state. The server must provide a read concurrency guarantee on the directory node being walked and should protect against renames during the entire walk.
7   | OpenAt       | OpenAtReq       | OpenAtResp<br><br>Optionally donates: \[openHostFD\]               | OpenAt is analogous to openat(2). It creates an Open FD on the Control FD OpenAtReq.fd using OpenAtReq.flags. The server may donate a host FD opened with the same flags. The client can directly make syscalls on this FD, instead of making RPCs as an optimization. The server must provide a read concurrency guarantee on the file node during this operation.
8   | OpenCreateAt | OpenCreateAtReq | OpenCreateAtResp<br><br>Optionally donates: \[openHostFD\]         | OpenCreateAt is analogous to openat(2) with flags that include O\_CREAT
9   | Close        | CloseReq        |                                                                    | Close is analogous to calling close(2) on multiple FDs. CloseReq.fds accepts an array of FDIDs. The server drops the client’s reference on the FD and stops tracking it. Future calls to the same FDID will return EBADF. However, this may not necessarily release the FD’s resources as other references might be held as per reference model. No concurrency guarantees are needed.
10  | FSync        | FsyncReq        |                                                                    | FSync is analogous to calling fsync(2) on multiple FDs. FsyncReq.fds accepts an array of FDIDs. The errors from syncing the FDs are ignored. The server must provide a read concurrency guarantee on the file node during this operation.
11  | PWrite       | PWriteReq       | PWriteResp                                                         | PWrite is analogous to pwrite(2). PWriteReq.fd must be an Open FD. Fields in PWriteReq are similar to pwrite(2) arguments. PWriteResp.count is the number of bytes written to the file. The server must provide a write concurrency guarantee on the file node during this operation.
12  | PRead        | PReadReq        | PReadResp                                                          | PRead is analogous to pread(2). PReadReq.fd must be an Open FD. Fields in PReadReq are similar to pread(2) arguments. PReadResp contains a buffer with the bytes read. The server must provide a read concurrency guarantee on the file node during this operation.
13  | MkdirAt      | MkdirAtReq      | MkdirAtResp                                                        | MkdirAt is analogous to mkdirat(2). It additionally allows the client to set the UID and GID for the newly created directory. MkdirAtReq.dirFD must be a Control FD for the directory inside which the new directory named MkdirAtReq.name will be created. It returns the new directory’s Inode. The server must provide a write concurrency guarantee on the directory node during this operation.
14  | MknodAt      | MknodAtReq      | MknodAtResp                                                        | MknodAt is analogous to mknodat(2). It additionally allows the client to set the UID and GID for the newly created file. MknodAtReq.dirFD must be a Control FD for the directory inside which the new file named MknodAtReq.name will be created. It returns the new file’s Inode. The server must provide a write concurrency guarantee on the directory node during this operation.
15  | SymlinkAt    | SymlinkAtReq    | SymlinkAtResp                                                      | SymlinkAt is analogous to symlinkat(2). It additionally allows the client to set the UID and GID for the newly created symlink. SymlinkAtReq.dirFD must be a Control FD for the directory inside which the new symlink named SymlinkAtReq.name is created. The symlink file contains SymlinkAtReq.target. It returns the new symlink’s Inode. The server must provide a write concurrency guarantee on the directory node during this operation.
16  | LinkAt       | LinkAtReq       | LinkAtResp                                                         | LinkAt is analogous to linkat(2) except it does not accept any flags. In Linux, AT\_SYMLINK\_FOLLOW can be specified in flags but following symlinks on the server is not allowed in lisafs. LinkAtReq.dirFD must be a Control FD for the directory inside which the hard link named LinkAtReq.name is created. This hard link is an existing file identified by LinkAtReq.target. It returns the link’s Inode. The server must provide a write concurrency guarantee on the directory node during this operation.
17  | FStatFS      | FStatFSReq      | StatFS                                                             | FStatFS is analogous to fstatfs(2). It returns information about the mounted file system in which FStatFSReq.fd is located. FStatFSReq.fd must be a Control FD. The server must provide a read concurrency guarantee on the file node during this operation.
18  | FAllocate    | FAllocateReq    |                                                                    | FAllocate is analogous to fallocate(2). Fields in FAllocateReq correspond to arguments of fallocate(2). FAllocateReq.fd must be an Open FD. The server must provide a write concurrency guarantee on the file node during this operation.
19  | ReadLinkAt   | ReadLinkAtReq   | ReadLinkAtResp                                                     | ReadLinkAt is analogous to readlinkat(2) except, it does not perform any path traversal. ReadLinkAtReq.fd must be a Control FD on a symlink file. It returns the contents of the symbolic link. The server must provide a read concurrency guarantee on the file node during this operation.
20  | Flush        | FlushReq        |                                                                    | Flush may be called before Close on an Open FD. It cleans up the file state. Its behavior is implementation specific. The server must provide a read concurrency guarantee on the file node during this operation.
21  | Connect      | ConnectReq      | Donates: \[sockFD\]                                                | Connect is analogous to calling socket(2) and then connect(2) on that socket FD. The socket FD is created using socket(AF\_UNIX, ConnectReq.sockType, 0). ConnectReq.fd must be a Control FD on a socket file that is connect(2)-ed to. On success, the socket FD is donated. The server must provide a read concurrency guarantee on the file node during this operation.
22  | UnlinkAt     | UnlinkAtReq     |                                                                    | UnlinkAt is analogous to unlinkat(2). Fields in UnlinkAtReq are similar to unlinkat(2) arguments. UnlinkAtReq.dirFD must be a Control FD for the directory inside which the child named UnlinkAtReq.name is to be unlinked. The server must provide a write concurrency guarantee on the directory and to-be-deleted file node during this operation.
23  | RenameAt     | RenameAtReq     |                                                                    | RenameAt is analogous to renameat(2). Fields in RenameAtReq are similar to renameat(2) arguments. RenameAtReq.oldDir and RenameAtReq.newDir must be Control FDs on the old directory and new directory respectively. The file named RenameAtReq.oldName inside old directory is renamed into new directory with the name RenameAtReq.newName. The server must provide global concurrency guarantee during this operation.
24  | Getdents64   | Getdents64Req   | Getdents64Resp                                                     | Getdents64 is analogous to getdents64(2). Fields in Getdents64Req are similar to getdents64(2) arguments. Getdents64Req.dirFD should be a Open FD on a directory. It returns an array of directory entries (Dirent). Each dirent also contains the dev\_t for the entry inode. This operation advances the open directory FD’s offset. The server must provide a read concurrency guarantee on the file node during this operation.
25  | FGetXattr    | FGetXattrReq    | FGetXattrResp                                                      | FGetXattr is analogous to fgetxattr(2). Fields in FGetXattrReq are similar to fgetxattr(2) arguments. It must be invoked on a Control FD. The server must provide a read concurrency guarantee on the file node during this operation.
26  | FSetXattr    | FSetXattrReq    |                                                                    | FSetXattr is analogous to fsetxattr(2). Fields in FSetXattrReq are similar to fsetxattr(2) arguments. It must be invoked on a Control FD. The server must provide a write concurrency guarantee on the file node during this operation.
27  | FListXattr   | FListXattrReq   | FListXattrResp                                                     | FListXattr is analogous to flistxattr(2). Fields in FListXattrReq are similar to flistxattr(2) arguments. It must be invoked on a Control FD. The server must provide a read concurrency guarantee on the file node during this operation.
28  | FRemoveXattr | FRemoveXattrReq |                                                                    | FRemoveXattr is analogous to fremovexattr(2). Fields in FRemoveXattrReq are similar to fremovexattr(2) arguments. It must be invoked on a Control FD. The server must provide a write concurrency guarantee on the file node during this operation.
29  | BindAt       | BindAtReq       | BindAtResp<br>Donates: \[sockFD\]                                  | BindAt is analogous to calling socket(2) and then bind(2) on that socket FD with a path. The path which is binded to is the host path of the directory represented by the control FD BindAtReq.DirFD + ‘/’ + BindAtReq.Name. The socket FD is created using socket(AF\_UNIX, BindAtReq.sockType, 0). It additionally allows the client to set the UID and GID for the newly created socket. On success, the socket FD is donated to the client. The client may use this donated socket FD to poll for notifications. The client may listen(2) and accept(2) from the FD if syscall filters permit. There are other RPCs to perform those operations. On success a Bound Socket FD is also returned along with an Inode for the newly created socket file. The server must provide a write concurrency guarantee on the directory node during this operation.
30  | Listen       | ListenReq       |                                                                    | Listen is analogous to calling listen(2) on the host socket FD represented by the Bound Socket FD ListenReq.fd with backlog ListenReq.backlog. The server must provide a read concurrency guarantee on the socket node during this operation.
31  | Accept       | AcceptReq       | AcceptResp<br>Donates: \[connFD\]                                  | Accept is analogous to calling accept(2) on the host socket FD represented by the Bound Socket FD AcceptReq.fd. On success, Accept donates the connection FD which was accepted and also returns the peer address as a string in AcceptResp.peerAddr. The server may choose to protect the peer address by returning an empty string. Accept must not block. The server must provide a read concurrency guarantee on the socket node during this operation.

### Chunking

Some IO based RPCs like PRead and PWrite may be limited by the maximum message
size limit imposed by the connection (see Mount RPC). If more data is required
to be read/written than one Read/Write RPC can accommodate, then the client
should introduce logic to read/write in chunks and provide synchronization as
required. The optimal chunk size should utilize the entire message size limit.

## Wire Format

LISAFS manually serializes and deserializes data structures to and from the
wire. This is simple and fast. 9P has successfully implemented and used such a
technique without issues for many years now.

Each message has the following format: `[Communicator Header][Message bytes]`
The structs representing various messages and headers are of two kinds:

-   Statically sized: The size and composition of such a struct can be
    determined at compile time. For example, `lisafs.Inode` has a static size.
    These structs are serialized onto the wire exactly how Golang would
    represent them in memory. This kind of serialization was inspired by
    gVisor’s go_marshal library. go_marshal autogenerates Golang code to
    serialize and deserialize statically sized structs using Golang’s unsafe
    package. The generated code just performs a memmove(3) from the struct’s
    memory address to the wire, or the other way round. This method avoids
    runtime reflection, which is slow. An alternative is to generate
    field-by-field serialization implementations, which is also slower than a
    memmove(3).
-   Dynamically sized: The size of such a struct can only be determined at
    runtime. This usually means that the struct contains a string or an array.
    Such structs use field-by-field serialization and deserialization
    implementations, just like 9P does. The dynamic fields like strings and
    arrays are preceded by some metadata indicating their size. For example,
    `lisafs.SizedString` is a dynamically sized struct.
