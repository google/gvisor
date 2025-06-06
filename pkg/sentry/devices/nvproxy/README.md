# nvproxy

The `nvproxy` package is a core component of gVisor that enables support for
NVIDIA GPUs, allowing sandboxed applications to perform GPU-accelerated
computations. This is achieved by intercepting and forwarding NVIDIA driver
calls from the sandboxed application to the host's NVIDIA driver.

## How it Works

The `nvproxy` driver operates by implementing virtual character devices within
the gVisor sandbox that mimic actual NVIDIA device files (like `/dev/nvidiactl`,
`/dev/nvidia-uvm` and `/dev/nvidia#`). When an application inside the sandbox
opens and interacts with these devices, nvproxy intercepts the `ioctl` and
`mmap` system calls. These calls, which are typically used for communication
with the NVIDIA driver, are then forwarded to the actual host NVIDIA driver
after necessary translations.

This proxying mechanism allows gVisor to maintain a strong security boundary
while still providing applications with access to the powerful computational
capabilities of the GPU. All other system calls from the application continue to
be handled by the gVisor Sentry.

For more information about gVisor GPU support, see the
[user guide](https://gvisor.dev/docs/user_guide/gpu/).

## Adding Support for New Driver Versions

The `nvproxy` package is sensitive to changes in the NVIDIA driver's Application
Binary Interface (ABI), which can occur between driver releases. This mainly
happens when `ioctl(2)` structs are modified. To manage this, `nvproxy` is
designed to support multiple driver versions explicitly.

This is accomplished using a sparse version tree defined in
[version.go](version.go). This tree doesn't list every NVIDIA driver release;
instead, it only contains the specific versions required to model the ABI's
evolution across all supported versions.

The tree's structure mimics the commit history of
[NVIDIA kernel driver repo](https://github.com/NVIDIA/open-gpu-kernel-modules),
including releases from both the `master` branch and separate development
branches. This is critical because ABI changes introduced in a parent version
affect all subsequent child versions. An accurate tree allows `nvproxy` to
correctly compose the final ABI for any given version.

At runtime, `nvproxy` performs the following steps:

1.  Reads the host's NVIDIA driver version.
2.  Finds the corresponding version in its tree.
3.  Traverses the tree from the root to that version's node, applying all ABI
    modifications along the path.

Here is the step-by-step process for adding support for a new driver version.

### Step 1: Place the New Version in the Tree

First, determine the new version's correct position in `nvproxy`'s version tree.

1.  Find the parent commit: Go to the
    [NVIDIA driver releases page](https://github.com/NVIDIA/open-gpu-kernel-modules/releases)
    and find the commit hash for your target version. Traverse the commit
    history upwards (following parent links) until you find a version that
    already exists in `nvproxy`'s version tree.
2.  Insert the new version: Add the new version to the tree under its identified
    parent.
3.  Mimic the branch structure: If the new version was created on a separate
    development branch (i.e., not `master`), you must replicate that branch
    structure in the `nvproxy` tree. If the branch point is a version `nvproxy`
    doesn't officially support, add it as an "unqualified" node (a version
    without a checksum or official support) to maintain structural integrity.

### Step 2: Calculate the Driver Checksum

The version tree requires a SHA256 checksum of the official NVIDIA driver
installer (`.runfile`) for verification. You can calculate this using the
provided tool:

```bash
bazel run tools/gpu:main checksum -- --version=<DRIVER_VERSION>
```

### Step 3: Account for ABI Changes

Use our `nvidia_driver_differ` tool to detect changes to proxied ABI structs
between the parent and the new version. The tool analyzes the NVIDIA kernel
driver source code and outputs the impacted structs.

```bash
bazel run tools/nvidia_driver_differ:run_differ -- --base <PARENT_VERSION> --next <NEW_VERSION>
```

-   `<PARENT_VERSION>` is the version of the parent node in nvproxy's version
    tree.
-   `<NEW_VERSION>` is the version you are adding.

Warning: This tool is for assistance and does not guarantee completeness. You
must still perform manual verification and testing. GPU tests are run against
all supported driver versions during Buildkite presubmits.

To verify changes in nvproxy, you can run the `nvproxy_driver_parity_test` test,
which compares `nvproxy`'s struct definitions with driver struct definitions:

```bash
bazel test pkg/sentry/devices/nvproxy:nvproxy_driver_parity_test
```

#### Handling Intermediate Versions

It is crucial to introduce ABI changes at the exact version they appear in the
driver source, even if `nvproxy` doesn't officially support that intermediate
version. When you identify an ABI struct change, go to its source code in
[NVIDIA kernel driver repo](https://github.com/NVIDIA/open-gpu-kernel-modules)
and see which commit introduced the change (using
[Blame view](https://docs.github.com/en/repositories/working-with-files/using-files/viewing-and-understanding-files#viewing-the-line-by-line-revision-history-for-a-file)).

For example, imagine `nvproxy` supports version `[A]` and you want to add
support for `[C]`. However, an ABI change that affects `nvproxy` was introduced
in an intermediate version `B`.

**Incorrect**: \
Do not apply the changes from `B` directly into `[C]`.

**Correct**: \
Create an intermediate, unqualified node for `B` that contains the necessary
code changes. The new node for `[C]` can then inherit these changes from `B`.
This ensures the version history is accurate.

This approach is essential for long-term maintainability. If you later need to
support another version `[D]` that also branched from `B`, it can accurately
inherit the same changes.

```
[A] -> B -> [C]
        \
         -> [D]
```

### Step 4: Add Support for New or Modified Ioctls

After running the `nvidia_driver_differ` tool, you may need to add or update
`ioctl` command handlers. To do this correctly, you must find the `ioctl`'s
implementation in the NVIDIA kernel driver source code to understand its
function and data structures.

The implementation details depend on the `ioctl` type:

-   Frontend Ioctls (`/dev/nvidiactl` or `/dev/nvidia#`):
    -   For top level commands, see documentation in `frontendFD.Ioctl()` in
        [frontend.go](frontend.go).
    -   For sub-commands of `NV_ESC_RM_ALLOC` (allocation classes): See
        documentation in `rmAlloc()` in [frontend.go](frontend.go).
    -   For sub-commands of `NV_ESC_RM_CONTROL` (control commands): See
        documentation in `rmControl()` in [frontend.go](frontend.go).
-   UVM Ioctls (`/dev/nvidia-uvm`): These require manual implementation by
    studying the kernel driver source and replicating the logic within nvproxy.

#### Handling File Descriptors and Pointers

A critical responsibility of `nvproxy` is to translate file descriptors (FDs)
and pointers within ioctl data structures.

-   File Descriptors: FDs used by the sandboxed application are local to the
    gVisor Sentry's FD table. They must be translated to the corresponding host
    FDs before being passed to the host driver.
-   Pointers: Pointers in `ioctl` structs are virtual addresses within the
    sandboxed application's memory space. These are invalid on the host. The
    structs containing them must be copied from the application's memory into
    the Sentry's memory. The host `ioctl` call must then be made using a pointer
    to this Sentry-managed memory.

#### Simple Ioctls

If an `ioctl` data structure contains neither pointers nor FDs and has no
special `mmap` semantics, it requires no translation and is considered "simple".
Helper utilities exist in nvproxy to proxy these simple ioctls directly, which
you should use whenever possible. Majority of ioctls proxied today are simple.
