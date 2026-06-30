# FUSE

[TOC]

gVisor supports [FUSE](Filesystem in Userspace), allowing userspace programs to
serve filesystems inside a sandbox. There are two modes of operation:

*   **In-sandbox FUSE**: A FUSE daemon runs inside the sandbox and communicates
    with the gVisor kernel via `/dev/fuse`. This is the standard FUSE model.
*   **External FUSE server**: A FUSE server runs on the host, outside the
    sandbox, and communicates with gVisor over a socketpair passed into the
    sandbox as a host file descriptor. This is useful when the filesystem
    implementation must access resources that are not available inside the
    sandbox.

## External FUSE Server

The external FUSE server feature allows a host-side process to serve a FUSE
filesystem into a gVisor sandbox. The host process and the sandbox communicate
over a Unix socketpair using the standard FUSE protocol. This approach avoids
the performance penalty incurred by context switching through the I/O proxy
mechansim that's otherwise used to expose host filesystems.

### How It Works

1.  The host creates a Unix socketpair (`SOCK_SEQPACKET`).
2.  One end of the socketpair is passed into the sandbox using the `--pass-fd`
    flag on `runsc run` or `runsc create`.
3.  The other end is given to a FUSE server process running on the host.
4.  Inside the sandbox, the application mounts a FUSE filesystem using the
    passed file descriptor.
5.  All FUSE operations (read, write, lookup, etc.) are forwarded over the
    socketpair to the host FUSE server, which performs the actual I/O.

### Setup

#### 1. Create the socketpair and start the FUSE server

The host process creates a socketpair and starts the FUSE server with one end:

```bash
# Example: create a socketpair and pass FD 4 to the FUSE server.
# The FUSE server reads FUSE requests from its FD and responds with
# the standard FUSE protocol (FUSEHeaderIn/Out framing).
./my_fuse_server --fd=4 --backing-dir=/data/shared
```

The FUSE server must implement the FUSE kernel protocol: it reads
`FUSEHeaderIn`-framed requests and writes `FUSEHeaderOut`-framed responses. At
minimum, it should handle `FUSE_INIT`, `FUSE_GETATTR`, `FUSE_LOOKUP`,
`FUSE_OPEN`, `FUSE_READ`, `FUSE_RELEASE`, and `FUSE_ACCESS`. Additional opcodes
like `FUSE_WRITE`, `FUSE_FLUSH`, `FUSE_STATFS`, and `FUSE_CREATE` can be added
as needed.

#### 2. Pass the FD into the sandbox

Use the `--pass-fd` flag to map the host-side socketpair FD into the sandbox:

```bash
runsc run \
  --pass-fd=3:100 \
  --bundle=/path/to/bundle \
  my-container
```

The format is `--pass-fd=HOST_FD:GUEST_FD`. In this example, host FD 3 becomes
FD 100 inside the sandbox. The `--pass-fd` flag can be specified multiple times
to pass additional file descriptors.

#### 3. Mount the FUSE filesystem inside the container

Inside the sandbox, the application mounts a FUSE filesystem referencing the
passed FD:

```c
// Mount using the passed file descriptor.
mount("fuse", "/mnt/shared", "fuse", MS_NODEV | MS_NOSUID,
      "fd=100,user_id=0,group_id=0,rootmode=40000");
```

Or equivalently from a shell:

```bash
mount -t fuse fuse /mnt/shared -o fd=100,user_id=0,group_id=0,rootmode=40000
```

The mount options are:

*   `fd=N`: The file descriptor number inside the sandbox.
*   `user_id=UID`: The UID that owns the mount.
*   `group_id=GID`: The GID that owns the mount.
*   `rootmode=MODE`: The permission mode of the root inode (octal). Use `40000`
    for a directory.

### Example: End-to-End with a Socketpair

Here is a complete example in Go that sets up the host side:

```go
// Create a socketpair for FUSE communication.
fds, _ := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)

// fds[0] goes into the sandbox, fds[1] goes to the FUSE server.
sandboxFile := os.NewFile(uintptr(fds[0]), "fuse-sandbox")
serverFD := fds[1]

// Start the FUSE server on the host with the server-side FD.
go myFuseServer.Serve(serverFD, "/data/backing")

// Launch the sandbox with the FD passed in.
cmd := exec.Command("runsc", "run",
    "--pass-fd=3:100",      // host FD 3 → guest FD 100
    "--bundle="+bundleDir,
    containerID,
)
cmd.ExtraFiles = []*os.File{sandboxFile}  // FD 3 in the child process
cmd.Run()
```

### Limitations

*   **No /dev/fuse**: The external path does not use `/dev/fuse`. The
    application mounts FUSE using the passed socketpair FD directly.
*   **FUSE protocol only**: The host server must implement the raw FUSE kernel
    protocol. Higher-level FUSE libraries (e.g., libfuse) typically expect
    `/dev/fuse` and may not work directly over a socketpair without adaptation.

## In-Sandbox FUSE

gVisor also supports the standard FUSE model where both the FUSE daemon and the
application run inside the sandbox. The daemon opens `/dev/fuse`, and the
application mounts a FUSE filesystem using the resulting file descriptor. This
works the same as FUSE on a regular Linux system, with the gVisor kernel
handling the FUSE protocol internally.

[FUSE]: https://www.kernel.org/doc/html/latest/filesystems/fuse.html
