# gVisor SandboxExec - Go Example: Document Processor

This directory contains a complete, runnable command-line example showing how to
use the **gVisor Go SandboxExec bindings** (`sandbox`) to safely process
untrusted documents and data files inside an isolated sandbox.

--------------------------------------------------------------------------------

## 1. Overview

[gVisor](https://gvisor.dev) provides secure application isolation by
intercepting Linux system calls in user space. The SandboxExec Go API gives you
a simple, programmatic way to spawn lightweight, secure sandboxes directly from
Go applications.

--------------------------------------------------------------------------------

## 2. How the Go Binding Works

The Go `sandbox` package builds an Open Container Initiative (OCI) bundle on the
fly and runs it with `runsc` in detached mode. To learn more about OCI bundles
or internal runtime architecture, visit the
[gVisor Architecture Guide](https://gvisor.dev/docs/architecture_guide/).

--------------------------------------------------------------------------------

## 3. Features Demonstrated

The `doc_processor.go` CLI demonstrates key gVisor Go binding features:

*   **Context-Driven Lifecycles**: Hard execution limits via
    `context.WithTimeout`.
*   **Filesystem Isolation**: Read-only input mounts (`/input`), writable output
    mounts (`/output`), and ephemeral scratch spaces (`/tmp`).
*   **Default Network Isolation**: `NetworkModeNone` prevents untrusted data
    from exfiltrating over the network.
*   **Snapshot Pre-Warming**: Saves initialized rootfs states with
    `RootfsTarSnapshot` and restores them instantly using `WithSnapshot`.

--------------------------------------------------------------------------------

## 4. Prerequisites

1.  **Install `runsc`**: Follow the official
    [gVisor Installation Guide](https://gvisor.dev/docs/user_guide/install/).
2.  **Set `RUNSC_PATH`**: Point `RUNSC_PATH` to your `runsc` binary:

    ```bash
    export RUNSC_PATH=/path/to/runsc
    ```

--------------------------------------------------------------------------------

## 5. Installing the Go Package

### In Standalone Go Projects

To use the gVisor SandboxExec package in your own Go application:

```bash
go get gvisor.dev/gvisor/sandboxexec/sandbox@go
```

Then import the package in your code:

```go
import "gvisor.dev/gvisor/sandboxexec/sandbox"
```

### In the gVisor Source Tree (Bazel)

If developing directly within the
[gVisor repository](https://github.com/google/gvisor), add the dependency to
your `BUILD` file:

```python
go_binary(
    name = "doc_processor",
    srcs = ["doc_processor.go"],
    deps = [
        "//sandboxexec/sandbox",
    ],
)
```

--------------------------------------------------------------------------------

## 6. Building and Running the Example

```bash
# Build the binary
go build -o doc_processor doc_processor.go

# Run the binary
./doc_processor -help
```

--------------------------------------------------------------------------------

## 7. CLI Flags & Recipes

### CLI Flags

| Flag             | Description                          | Default            |
| :--------------- | :----------------------------------- | :----------------- |
| `-input`         | Host directory mounted read-only at  | None               |
:                  : `/input`                             :                    :
| `-output`        | Host directory mounted read-write at | None               |
:                  : `/output`                            :                    :
| `-cmd`           | Shell command to execute inside      | Batch uppercase tr |
:                  : sandbox                              :                    :
| `-timeout`       | Maximum execution timeout (e.g.,     | `10s`              |
:                  : `5s`, `30s`)                         :                    :
| `-network`       | Network mode: `none` (default),      | `none`             |
:                  : `host`, or `sandbox`                 :                    :
| `-working-dir`   | Container working directory          | `/`                |
| `-snapshot-dir`  | Storage directory for pre-warmed     | None               |
:                  : snapshots                            :                    :
| `-warm-snapshot` | Pre-warms templates to               | `false`            |
:                  : `-snapshot-dir` and exits            :                    :

--------------------------------------------------------------------------------

### Example Recipes

#### 1. Safely Transform Untrusted Documents

Mount an untrusted input directory as read-only and collect processed artifacts
in a separate output directory:

```bash
mkdir -p ./docs ./results
echo "hello untrusted world" > ./docs/document.txt

# Run default batch conversion in an isolated sandbox
./doc_processor -input ./docs -output ./results

cat ./results/document.txt
# Output: HELLO UNTRUSTED WORLD
```

#### 2. Run a Custom Transformation Pipeline

Specify a custom shell pipeline with the `-cmd` flag:

```bash
./doc_processor \
  -input ./docs \
  -output ./results \
  -cmd "awk '{print toupper(\$0)}' /input/document.txt > /output/formatted.txt"

cat ./results/formatted.txt
```

#### 3. Enforce Execution Timeouts Against Runaway Tasks

Protect your system against infinite loops or regex DoS by setting a hard
timeout:

```bash
# Automatically terminates after 2 seconds
./doc_processor -cmd "sleep 30" -timeout 2s
```

#### 4. Verify Network Isolation (Prevent Data Exfiltration)

By default (`-network none`), untrusted processes cannot reach external
networks:

```bash
# Fails because outbound network connectivity is blocked
./doc_processor -cmd "curl -I https://google.com"
```

#### 5. Pre-warm Template Snapshots for Instant Reuse

Save an initialized environment snapshot and restore it in subsequent runs:

```bash
mkdir -p ./snap_storage

# Step 1: Pre-warm base templates and save snapshot
./doc_processor -snapshot-dir ./snap_storage -warm-snapshot

# Step 2: Run processing using the pre-warmed snapshot
./doc_processor \
  -snapshot-dir ./snap_storage \
  -output ./results \
  -cmd "cat /opt/templates/header.txt > /output/report.txt"

cat ./results/report.txt
```
