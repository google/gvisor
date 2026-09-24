# gVisor SandboxExec - Python Example: Safe Code Runner

This directory contains a complete, runnable command-line example showing how to
use the **gVisor Python SandboxExec bindings** (`gvisor`) to safely run
untrusted scripts and code snippets in an isolated sandbox.

--------------------------------------------------------------------------------

## 1. Overview

[gVisor](https://gvisor.dev) is an application kernel and OCI runtime (`runsc`)
that provides strong workload isolation by intercepting system calls in user
space.

--------------------------------------------------------------------------------

## 2. How the Python Binding Works Under the Hood

The `gvisor` Python package creates a standard Open Container Initiative (OCI)
bundle (`config.json` and `rootfs/`) and invokes `runsc` which uses the OCI
bundle to execute commands inside the sandbox. We'll walk through how to install
`runsc` in the Prerequisites section.

--------------------------------------------------------------------------------

## 3. gVisor Features Demonstrated in this Example

The `safe_runner.py` CLI script showcases the primary capabilities of the Python
SandboxExec API:

1.  **Context-Managed Lifecycle (`Sandbox`)**: Automatic sandbox creation and
    guaranteed cleanup of container processes and runtime directories via
    Python's `with` statement.
2.  **Filesystem Isolation (`Mount`)**:
    *   `Mount.bind(..., readonly=True)`: Mounts host scripts or dependencies as
        read-only so the sandbox cannot modify them.
    *   `Mount.bind(..., readonly=False)`: Mounts a designated host directory to
        safely collect generated outputs.
    *   `Mount.tmpfs("/tmp")`: Allocates an isolated, ephemeral in-memory
        scratch space.
    *   `Mount.proc("/proc")`: Provides an isolated process filesystem view.
3.  **Network Isolation (`NetworkMode`)**:
    *   `NetworkMode.NONE` (`"none"`, default): Disables network access
        completely to prevent untrusted code from exfiltrating data or reaching
        network services. Compatible with rootless/non-root execution.
    *   `NetworkMode.HOST` (`"host"`): Shares the host network namespace,
        allowing outbound and inbound connectivity in rootless environments.
    *   `NetworkMode.SANDBOX` (`"sandbox"`): Runs a dedicated gVisor netstack in
        an isolated network namespace (requires host root UID 0).
4.  **Execution Timeouts (`timeout=...`)**: Prevents infinite loops or
    denial-of-service by enforcing strict per-command execution time limits.
5.  **Environment & Working Directory Control**: Allows configuring default or
    per-command working directories and environment variables.

--------------------------------------------------------------------------------

## 4. Prerequisites

To run sandboxes, install the `runsc` binary and point the Python bindings to
it.

### Installing `runsc`

1.  **Install `runsc`**: Follow the
    [gVisor installation guide](https://gvisor.dev/docs/user_guide/install/).

2.  **Set `RUNSC_PATH`**: Point the `RUNSC_PATH` environment variable to your
    `runsc` executable:

    ```bash
    export RUNSC_PATH=/path/to/runsc
    ```

    The `gvisor` package requires `RUNSC_PATH` to find and run `runsc`.

--------------------------------------------------------------------------------

## 5. Installing the Python Package

### Option A: From PyPI

```bash
pip install gvisor
```

### Option B: Building from Source (Local Wheel)

```bash
# from sandboxexec/sandbox/python
python3 -m build
pip install dist/gvisor-*.whl
```

--------------------------------------------------------------------------------

## 6. CLI Usage & Recipes

`safe_runner.py` provides a simple command-line interface for executing code
safely.

### CLI Flags

| Flag                  | Description                               | Default |
| :-------------------- | :---------------------------------------- | :------ |
| `-c`, `--code`        | Inline Python or shell code to execute    | None    |
| `-s`, `--script`      | Path to a host script file to execute     | None    |
| `-o`, `--output-dir`  | Host directory to mount read-write for    | None    |
:                       : output files (`/output`)                  :         :
| `-t`, `--timeout`     | Maximum execution time in seconds         | `5.0`   |
| `-n`, `--network`     | Sandbox network mode (`none`, `host`,     | `none`  |
:                       : `sandbox`)                                :         :
| `-w`, `--working-dir` | Initial container working directory       | `/`     |
| `-e`, `--env`         | Environment variables in `KEY=VAL` format | None    |

--------------------------------------------------------------------------------

### Example Recipes

#### 1. Run an Inline Code Snippet

```bash
python3 safe_runner.py --code "print('Hello from inside gVisor!')"
```

#### 2. Run a Script File Safely

```bash
# Create a sample script
echo "import os; print('Running in PID namespace, PID:', os.getpid())" > sample.py

# Execute in sandbox
python3 safe_runner.py --script sample.py
```

#### 3. Capture Output Artifacts

```bash
mkdir -p ./results

# Run a script that writes to /output
python3 safe_runner.py \
  --code "with open('/output/result.txt', 'w') as f: f.write('Processed successfully\n')" \
  --output-dir ./results

cat ./results/result.txt
```

#### 4. Guard Against Runaway Code with Timeouts

```bash
# Terminated automatically after 2 seconds
python3 safe_runner.py --code "import time; time.sleep(10)" --timeout 2
```

#### 5. Verify Default Network Isolation

```bash
# Fails because networking is disabled by default (NetworkMode.NONE)
python3 safe_runner.py --code "import urllib.request; urllib.request.urlopen('https://google.com')"
```

#### 6. Enable Outbound Network Access in Rootless Environments

```bash
# Outbound connectivity works via host network sharing (NetworkMode.HOST)
python3 safe_runner.py \
  --code "import urllib.request; print(urllib.request.urlopen('https://google.com').status)" \
  --network host
```
