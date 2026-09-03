# Quickstart

> [!WARNING] **EXPERIMENTAL:** The APIs and tools described here are
> experimental and are **not meant for production use**.

This guide shows you how to get started with the gVisor Python SDK to run
commands inside a sandboxed environment.

## Prerequisites

1.  **gVisor (runsc) Installed**: You must have `runsc` installed and available
    in your `PATH`. See the [Installation Guide](/docs/user_guide/install/) for
    details.
2.  **Python Environment**: Ensure you have Python 3.9 or higher installed.

## Installation

Install the `gvisor` package using `pip`:

```bash
pip install gvisor
```

## Example

Here is a minimalist runnable example demonstrating sandbox initialization and
command execution (`uname -a`) using context manager syntax:

```python
from gvisor import Sandbox

with Sandbox() as sb:
    stdout, stderr = sb.exec("uname", "-a")
    print(f"Stdout: {stdout.strip()}")
```

## Running the Example

1.  Save the code above as `main.py`.
2.  Run the application:

    ```bash
    python3 main.py
    ```

You should see output similar to:

```
Stdout: Linux  5.15.0-gvisor
```

This indicates the command successfully ran inside the gVisor sandbox, which
emulates a Linux kernel.

For more examples and advanced usage patterns, see the
[complete CLI recipes](https://github.com/google/gvisor/tree/master/examples/sandboxexec/python).

--------------------------------------------------------------------------------

For detailed API documentation, see the [API Reference](/docs/sdk/python/).
