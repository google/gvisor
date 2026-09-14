# Bubblewrap (bwrap) Personality

[TOC]

gVisor provides a Bubblewrap (`bwrap`) command-line personality for `runsc`. The
goal is to simplify configurations by allowing users to use a `bwrap` alias and
familiar flags to quickly start a secure gVisor sandbox without manually
creating OCI configuration files.

## Getting Started

You can run an application using the `bwrap` command-line personality by
invoking `runsc bwrap`:

```bash
runsc bwrap --ro-bind / / --tmpfs /tmp --unshare-net --hostname gvisor-sentry -- /bin/sh
```

Alternatively, if `runsc` is symlinked as `bwrap` in your `$PATH`, you can
invoke it directly:

```bash
ln -s /usr/local/bin/runsc /usr/local/bin/bwrap
bwrap --ro-bind / / --tmpfs /tmp -- /bin/sh
```

## Supported Flags & OCI Mapping

gVisor translates `bwrap` flags directly into OCI specification settings
(`spec.Mounts`, `spec.Linux.Namespaces`, `spec.Process.Env`, etc.). Below is the
reference of supported flags and their behavior.

### Filesystem & Mount Operations

| Flag        | Arguments      | Description & OCI Mapping                     |
| :---------- | :------------- | :-------------------------------------------- |
| `--bind`    | `<SRC> <DEST>` | Bind mounts `SRC` to `DEST` with options      |
:             :                : `rbind, rprivate, nosuid, nodev` (if root     :
:             :                : `/`).                                         :
| `--ro-bind` | `<SRC> <DEST>` | Read-only bind mounts `SRC` to `DEST`. Sets   |
:             :                : `spec.Root.Readonly = true` if `DEST` is `/`. :
| `--tmpfs`   | `<DEST>`       | Mounts a fresh `tmpfs` filesystem at `DEST`.  |
| `--proc`    | `<DEST>`       | Mounts a new `procfs` filesystem at `DEST`.   |

> **NOTE:** If no root mount (`/`) is specified via `--bind` or `--ro-bind`,
> gVisor automatically initializes a `tmpfs` root filesystem at `/` and mounts
> standard system directories (`/proc`, `/sys`, `/dev`, `/dev/pts`,
> `/sys/fs/cgroup`, and `/tmp`).

### Namespace & Isolation Controls

| Flag               | Arguments | Description & OCI Mapping   |
| :----------------- | :-------- | :-------------------------- |
| `--unshare-user`   | None      | Creates a new Linux User    |
:                    :           : Namespace                   :
:                    :           : (`specs.UserNamespace`) and :
:                    :           : configures host UID/GID     :
:                    :           : mappings. Implied           :
:                    :           : automatically if running as :
:                    :           : non-root.                   :
| `--unshare-net`    | None      | Creates a new Linux Network |
:                    :           : Namespace                   :
:                    :           : (`specs.NetworkNamespace`). :
| `--share-net`      | None      | Explicitly shares the host  |
:                    :           : network namespace.          :
| `--unshare-all`    | None      | Unshares all default        |
:                    :           : namespaces (enables         :
:                    :           : `--unshare-user` and        :
:                    :           : `--unshare-net`).           :
| `--unshare-ipc`    | None      | Compatible no-op flag       |
:                    :           : (gVisor inherently          :
:                    :           : virtualizes and isolates    :
:                    :           : IPC by default).            :
| `--unshare-pid`    | None      | Compatible no-op flag       |
:                    :           : (gVisor inherently          :
:                    :           : virtualizes and isolates    :
:                    :           : PID by default).            :
| `--unshare-uts`    | None      | Compatible no-op flag       |
:                    :           : (gVisor inherently          :
:                    :           : virtualizes and isolates    :
:                    :           : UTS by default).            :
| `--unshare-cgroup` | None      | Compatible no-op flag       |
:                    :           : (gVisor inherently          :
:                    :           : virtualizes and isolates    :
:                    :           : cgroups by default).        :

### Process & Identity Settings

| Flag         | Arguments | Description & OCI Mapping  |
| :----------- | :-------- | :------------------------- |
| `--chdir`    | `<DIR>`   | Sets the initial working   |
:              :           : directory inside the       :
:              :           : container                  :
:              :           : (`spec.Process.Cwd`).      :
| `--hostname` | `<NAME>`  | Sets the container         |
:              :           : hostname                   :
:              :           : (`spec.Hostname`).         :
| `--uid`      | `<UID>`   | Custom UID in the sandbox  |
:              :           : (`spec.Process.User.UID`). :
:              :           : Requires `--unshare-user`. :
| `--gid`      | `<GID>`   | Custom GID in the sandbox  |
:              :           : (`spec.Process.User.GID`). :
:              :           : Requires `--unshare-user`. :

### Environment Variables

| Flag         | Arguments       | Description & OCI Mapping                   |
| :----------- | :-------------- | :------------------------------------------ |
| `--setenv`   | `<VAR> <VALUE>` | Sets an environment variable `VAR=VALUE` in |
:              :                 : `spec.Process.Env`.                         :
| `--unsetenv` | `<VAR>`         | Removes any matching `VAR` from             |
:              :                 : `spec.Process.Env`.                         :
| `--clearenv` | None            | Clears all environment variables in         |
:              :                 : `spec.Process.Env` except `PWD=<cwd>`.      :

## Unsupported Flags

If you don't see a `bwrap` flag listed above, it is not supported right now :)
but we are trying our best to support all of them.
