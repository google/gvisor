# gVisor Python Bindings

Python bindings for [gVisor](https://github.com/google/gvisor).

## Overview

gVisor is an application kernel, written in Go, that implements a substantial
portion of the Linux system surface. It includes an Open Container Initiative
(OCI) runtime called `runsc` that provides an isolation boundary between the
application and the host kernel. The `runsc` runtime delivers strong sandbox
isolation while still allowing applications to behave as they would under
standard runtimes.

These Python bindings provide a programmable interface to interact with gVisor.

## Installation

```bash
pip install gvisor
```

The bindings run sandboxes with `runsc`. Install it by following the
[gVisor installation guide](https://gvisor.dev/docs/user_guide/install/). The
package uses the `runsc` on your `PATH`, or the binary set in `RUNSC_PATH`.

## Quickstart

```python
from gvisor import Mount, NetworkMode, Sandbox

with Sandbox(
    network=NetworkMode.NONE,
    mounts=[Mount.tmpfs("/tmp")],
) as sb:
    stdout, _ = sb.exec("uname", "-a")
    print(stdout)

    stdout, _ = sb.exec("sh", "-c", "echo hi > /tmp/out && cat /tmp/out")
    print(stdout)
```

## Documentation

*   [Quickstart](https://gvisor.dev/docs/sdk/python/quickstart/)
*   [API reference](https://gvisor.dev/docs/sdk/python/)
*   [Examples](https://github.com/google/gvisor/tree/master/examples/sandboxexec/python)

## License

Apache License 2.0
