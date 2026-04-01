# Rootless

## What are Rootless Containers?

Rootless containers allow unprivileged users to run and manage containers
without needing root permissions. To qualify as a true rootless setup, the
entire process chain—the daemon, the container runtime, and the container
itself—must operate completely without root privileges.

Simply allowing non-root users access to the Docker socket by adding them to the
`docker` group, or using `dockerd --userns-remap`, does not qualify, as the
underlying daemon still relies on root.

### Motivation

*   **Security:** Creates a significantly more secure environment.
*   **Multi-user Friendly:** Useful for shared machines.
*   **Portability:** Less potential for conflicts with system configuration, as
    rootless containers rely less on host-level access.

## The Core Mechanism: User Namespaces

Rootless containers rely heavily on user namespaces (`user_namespaces(7)`) to
emulate the fake privileges (like `CAP_SYS_ADMIN` and `CAP_SETUID`) needed to
create containers.

A user namespace allows a process to have a normal, unprivileged User ID (UID)
outside the container, while simultaneously possessing UID 0 (`root`) inside the
container namespace.

## 3 Ways to Run Rootless Containers in gVisor

Depending on your tooling and environment constraints, `runsc` supports three
primary methods for executing rootless containers.

### Method 1: `runsc --rootless` (The Built-in Way)

This method is optimized for ease of use directly via the command line.

When you pass the `--rootless` flag, `runsc` re-executes itself in a new user
namespace where the caller’s user is mapped directly to root. Because it does
not rely on external `setuid` binaries, only the caller’s UID is mapped, and
mapping any other user is not supported. `runsc` then proceeds to run on
standard "rootful" code paths.

**Limitations:**

*   The `create` command is not supported. Using `runsc create` is the common
    case. The `--rootless` flag is mainly only suitable for `runsc do`.
*   Save/restore functionality is not supported.
*   gVisor's Netstack is not supported, meaning you have to use the host network
    for external connectivity.
*   Configuration errors related to cgroups are ignored.

### Method 2: Caller-Configured Userns (Docker / Podman)

This is the standard approach used by higher-level container engines like Docker
and Podman when running rootless.

*   These engines use tools like `rootlesskit` to do the user namespace
    initiation before handing off to `runsc`.
*   `runsc` is invoked with UID=0 already established inside the new user
    namespace.
*   Unlike the `--rootless` flag, this method supports mapping multiple UIDs by
    utilizing subuids from `/etc/subuid`.
*   To achieve multi-user mapping, it requires the use of `SETUID` binaries on
    the host, such as `newuidmap(1)`.
*   **Networking:** Unsharing the network namespace is critical here to protect
    abstract UNIX sockets on the host. Netstack can be used by utilizing TAP
    devices alongside a usermode network stack like Slirp.

### Method 3: True `runsc` Rootless Mode

This is a less commonly used, native execution path. You invoke `runsc` with a
non-root user and explicitly specify the user namespace mappings within the OCI
`config.json` specification.

*   `runsc` has specific rootless code paths to handle this configuration.
*   Like `rootlesskit`, `runsc` will attempt to invoke `SETUID` binaries like
    `newuidmap(1)` to set up the multi-user namespace mappings.
*   This method currently lacks support for network namespacing.

## Advanced: Running in Strict, Unprivileged Environments (No `setuid`)

If you are running `runsc` inside a nested container or an environment where
`setuid` binaries (like `newuidmap(1)`) are stripped or unavailable, then you
are more restricted in what UID/GID mappings you can specify.

To bypass `newuidmap`, the runtime must fall back to a strictly unprivileged
**Single-UID Mapping**.

### The Linux Kernel Constraints

The Linux kernel allows an entirely unprivileged process to manually map
UIDs/GIDs by writing directly to `/proc/[pid]/uid_map` and
`/proc/[pid]/gid_map`, but only if it strictly follows these rules:

1.  **Size of 1:** The mapping size must be exactly `1`.
2.  **Identity Match:** The host ID being mapped must exactly match the
    Effective UID/GID of the process writing the file.
3.  **Deny Setgroups:** Before writing to `gid_map`, the unprivileged process
    must disable the `setgroups` system call by writing `"deny"` to
    `/proc/[pid]/setgroups`.

### Configuring the OCI Spec

To trigger this fallback, you must use OCI `config.json` that requests exactly
one mapped UID/GID:

```json
{
  "process": {
    "user": {
      "uid": 0,
      "gid": 0
    }
  },
  "linux": {
    "namespaces": [
      {
        "type": "user"
      }
    ],
    "uidMappings": [
      {
        "containerID": 0,
        "hostID": <current-euid>,
        "size": 1
      }
    ],
    "gidMappings": [
      {
        "containerID": 0,
        "hostID": <current-egid>,
        "size": 1
      }
    ]
  }
}
```

### Storage Caveats

Because you only have a single valid UID inside this flattened namespace, you
cannot extract standard Linux container images (like Ubuntu) that contain files
owned by various system UIDs (`bin`, `daemon`, `postgres`).

To work around this, configure your higher-level engine to ignore `chown` errors
during image extraction. In Podman, this is done by setting
`ignore_chown_errors = "true"` in `storage.conf`.
