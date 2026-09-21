# API Reference

> [!WARNING] **EXPERIMENTAL:** The APIs and tools described here are
> experimental and are **not meant for production use**.

The gVisor Python SDK (package `gvisor`) provides a simple API for creating
gVisor sandboxes and executing commands inside them.

To use the SDK, you must have `runsc` installed on your system. Refer to the
[Installation Guide](/docs/user_guide/install/) for instructions.

## Import

The public API is re-exported at the top level of the `gvisor` package, so
import the classes you need directly:

```python
from gvisor import Sandbox, Mount, MountType, NetworkMode, Error
```

They are also available through the `gvisor.sandbox` module:

```python
from gvisor import sandbox

sb = sandbox.Sandbox()
```

## Classes

### Sandbox

Represents a running gVisor sandbox. Recommended to use the "with" statement to
ensure proper cleanup. Otherwise, ensure that `close()` is called at the end of
the sandbox lifecycle to clean up sandbox processes.

```python
class Sandbox
```

#### \_\_init\_\_

```python
def __init__(self, runtime_dir: Optional[str] = None, sandbox_id: Optional[str] = None, network: Union[NetworkMode, str] = NetworkMode.NONE, env: Optional[Union[List[str], Dict[str, str]]] = None, mounts: Optional[Sequence[Union[Mount, Dict[str, Any]]]] = None, working_dir: str = "/")
```

Initializes and starts a new sandbox.

**Parameters:**

*   `runtime_dir`: Custom runtime directory where bundle and state files are
    written. If not set, a temporary directory is created.
*   `sandbox_id`: Specific sandbox ID. If not set, a unique ID is generated
    automatically.
*   `network`: The networking mode for runsc ('none', 'sandbox', 'host', or
    NetworkMode enum). Defaults to NetworkMode.NONE ('none').
*   `env`: Optional environment variables for the sandbox container.
*   `mounts`: Optional sequence of Mount objects or dicts defining mounts.
*   `working_dir`: The initial working directory inside the sandbox. Relative
    paths are normalized relative to container root ('/'). Defaults to "/".

**Raises:**

*   `Error`: If sandbox creation fails.
*   `ValueError`: If an invalid network mode, working_dir, mount, or environment
    variable format is provided.
*   `TypeError`: If env, mounts, or network has an invalid type.

#### id

```python
@property
def id(self) -> str
```

Returns the sandbox ID.

#### bundle_dir

```python
@property
def bundle_dir(self) -> str
```

Returns the path to the OCI bundle directory.

#### exec

```python
def exec(self, cmd: str, *args: str, env: Optional[Union[List[str], Dict[str, str]]] = None, cwd: Optional[str] = None, timeout: Optional[float] = None) -> Tuple[str, str]
```

Runs the given command inside the running sandbox.

**Parameters:**

*   `cmd`: The command to run.
*   `*args`: Arguments to the command.
*   `env`: Optional environment variables for this command execution.
*   `cwd`: Optional working directory for this command execution. Relative paths
    are normalized relative to container root ('/').
*   `timeout`: Timeout in seconds.

**Returns:**

*   `Tuple[str, str]`: A tuple of (stdout, stderr) strings.

**Raises:**

*   `Error`: If the command execution fails or times out.
*   `ValueError`: If environment variable formatting or cwd is invalid.
*   `TypeError`: If env or cwd has an invalid type.

#### close

```python
def close(self)
```

Kills the sandbox processes and cleans up directories.

### Mount

Represents a mount configuration inside the sandbox.

```python
@dataclasses.dataclass(frozen=True)
class Mount
```

**Attributes:**

*   `destination`: Destination path inside the sandbox.
*   `source`: Source path on the host (for bind mounts) or mount source
    identifier.
*   `type`: Mount type ('bind', 'tmpfs', 'proc').
*   `readonly`: Whether the mount is read-only (applies to bind mounts).

#### bind

```python
@classmethod
def bind(cls, source: str, destination: str, readonly: bool = False) -> Mount
```

Creates a host bind mount.

#### tmpfs

```python
@classmethod
def tmpfs(cls, destination: str) -> Mount
```

Creates an in-memory tmpfs mount.

#### proc

```python
@classmethod
def proc(cls, destination: str) -> Mount
```

Creates an isolated procfs mount.

### MountType

Type of mount point inside the sandbox.

```python
class MountType(str, enum.Enum)
```

**Values:**

*   `BIND`: `"bind"`
*   `TMPFS`: `"tmpfs"`
*   `PROC`: `"proc"`

### NetworkMode

Network isolation mode for the sandbox.

```python
class NetworkMode(str, enum.Enum)
```

**Values:**

*   `NONE`: `"none"`
*   `HOST`: `"host"`
*   `SANDBOX`: `"sandbox"`

### Error

Base exception for Sandbox operations.

```python
class Error(Exception)
```

--------------------------------------------------------------------------------

For a practical example, see the [Quickstart](/docs/sdk/python/quickstart/).
