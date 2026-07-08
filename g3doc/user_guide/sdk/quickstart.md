# Quickstart

> [!WARNING] **EXPERIMENTAL:** The APIs and tools described here are
> experimental and are **not meant for production use**.

This guide shows you how to get started with the gVisor Go SDK to run commands
inside a sandboxed environment.

## Prerequisites

1.  **gVisor (runsc) Installed**: You must have `runsc` installed and available
    in your `PATH`. See the [Installation Guide](/docs/user_guide/install/) for
    details.
2.  **Go Environment**: Ensure you have Go installed (version 1.16+
    recommended).

## Example

Here is a complete example of creating a sandbox, executing a command (`uname
-a`), and cleaning up the sandbox resources.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "gvisor.dev/gvisor/sandboxexec/sandbox"
)

func main() {
    ctx := context.Background()

    // Initialize a new sandbox.
    // Note: WithNetworking(true) requires running as root.
    // For this quickstart, we disable networking to allow running as non-root.
    sb, err := sandbox.New(ctx, sandbox.WithNetworking(false))
    if err != nil {
        log.Fatalf("Failed to create sandbox: %v", err)
    }
    defer func() {
        if err := sb.Close(ctx); err != nil {
            log.Fatalf("Failed to close sandbox: %v", err)
        }
    }()

    // Execute a command inside the sandbox.
    stdout, stderr, err := sb.Exec(ctx, "uname", "-a")
    if err != nil {
        log.Fatalf("Exec failed: %v, stderr: %s", err, stderr)
    }

    fmt.Printf("Stdout: %s", stdout)
}
```

## Running the Example

1.  Save the code above as `main.go`.
2.  Initialize a Go module:

    ```bash
    go mod init gvisor-quickstart
    ```

3.  Add the dependency (replace with the actual public import path when
    available):

    ```bash
    go get gvisor.dev/gvisor/sandboxexec/sandbox
    ```

4.  Run the application:

    ```bash
    go run main.go
    ```

You should see output similar to:

```
Stdout: Linux  5.15.0-gvisor
```

This indicates the command successfully ran inside the gVisor sandbox, which
emulates a Linux kernel.

--------------------------------------------------------------------------------

For detailed API documentation, see the [API Reference](/docs/sdk/go/).
