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
sudo runsc bwrap --ro-bind / / --tmpfs /tmp --unshare-net --hostname gvisor-sentry -- /bin/sh
```

Alternatively, if `runsc` is symlinked as `bwrap` in your `$PATH`, you can
invoke it directly:

```bash
ln -s /usr/local/bin/runsc /usr/local/bin/bwrap
sudo bwrap --ro-bind / / --tmpfs /tmp -- /bin/sh
```

## Supported Flags & OCI Mapping

gVisor translates `bwrap` flags into OCI specification settings (`spec.Mounts`,
`spec.Process.Env`, `spec.Process.Capabilities`, etc.) and, where no
specification field fits, into `runsc` global flags such as `--network`. Below
is the reference of supported flags and their behavior.

The last column of each table calls out anything that behaves unlike native
`bwrap`. A dash there means you can carry the flag over from a `bwrap` command
line unchanged.

### Filesystem & Mount Operations

| Flag        | Arguments      | Description & OCI   | Difference from `bwrap` |
:             :                : Mapping             :                         :
| :---------- | :------------- | :------------------ | :---------------------- |
| `--bind`    | `<SRC> <DEST>` | Bind mounts `SRC`   | —                       |
:             :                : to `DEST`. When     :                         :
:             :                : `SRC` is the host   :                         :
:             :                : root (`/`) and      :                         :
:             :                : `DEST` is not, the  :                         :
:             :                : mount also gets     :                         :
:             :                : `rbind, rprivate,   :                         :
:             :                : nosuid, nodev`.     :                         :
| `--ro-bind` | `<SRC> <DEST>` | Read-only bind      | —                       |
:             :                : mounts `SRC` to     :                         :
:             :                : `DEST`. Sets        :                         :
:             :                : `spec.Root.Readonly :                         :
:             :                : = true` if `DEST`   :                         :
:             :                : is `/`.             :                         :
| `--tmpfs`   | `<DEST>`       | Mounts a fresh      | —                       |
:             :                : `tmpfs` filesystem  :                         :
:             :                : at `DEST`.          :                         :
| `--proc`    | `<DEST>`       | Mounts a new        | `/proc` is mounted in   |
:             :                : `procfs` filesystem : every sandbox whether   :
:             :                : at `DEST`.          : or not you pass the     :
:             :                : Repeating the same  : flag.                   :
:             :                : `DEST` on one       :                         :
:             :                : command line is a   :                         :
:             :                : no-op.              :                         :

> **NOTE:** A mount whose `DEST` is `/` becomes the sandbox root filesystem.
> Only its source and its read-only bit carry over, so the `rbind, rprivate,
> nosuid, nodev` options above do not apply to `--bind / /`.

> **NOTE:** `SRC` must exist on the host. A missing source aborts the run with
> `Can't find source path` before the sandbox starts.

> **NOTE:** Every sandbox gets `/proc`, `/sys`, `/dev`, `/dev/pts`,
> `/sys/fs/cgroup`, and `/tmp`, all backed by gVisor's own implementations of
> those filesystems. These defaults are applied first and the command line is
> layered on top of them, so a mount you ask for at one of those paths wins. If
> no root mount (`/`) is specified via `--bind` or `--ro-bind`, gVisor
> initializes a fresh `tmpfs` root filesystem at `/`.

### Namespace & Isolation Controls

Native `bwrap` builds a sandbox by unsharing namespaces from the host kernel, so
each `--unshare-*` flag decides whether the application keeps using a host
namespace or gets a fresh one. gVisor works differently: the Sentry is a kernel,
and the application always runs inside it. The Sentry implements its own process
tree, mount table, hostname, System V IPC, and cgroup hierarchy for every
sandbox, whatever the command line says. The application never holds a handle on
a host namespace, and no flag can give it one.

The flags below therefore do not choose between "host namespace" and "new
namespace". They configure either the host-side sandbox process or the Sentry
subsystem that backs an already-isolated resource.

Networking is the one subsystem whose backing can be the host, and even then the
application does not join the host network namespace. Every socket call goes to
the Sentry. Under `--network=none` the sandbox has no networking at all: the
Sentry brings up a loopback interface and nothing else. Under `--network=host`
the Sentry makes the call on the host through `hostinet`. What changes is how
the Sentry serves the call on the application's behalf, never whether the
application itself sits in a host namespace.

| Flag               | Arguments | Behavior in gVisor      | Difference from   |
:                    :           :                         : `bwrap`           :
| :----------------- | :-------- | :---------------------- | :---------------- |
| `--unshare-user`   | None      | Host-side only. Runs    | Nothing implies   |
:                    :           : the sandbox processes   : this flag. Omit   :
:                    :           : (Sentry and Gofer) in a : it and the        :
:                    :           : new Linux user          : specification     :
:                    :           : namespace               : carries no        :
:                    :           : (`specs.UserNamespace`) : namespaces at     :
:                    :           : with UID/GID mappings   : all, and the      :
:                    :           : back to the invoking    : command runs as   :
:                    :           : user, which is what     : UID/GID 0 in      :
:                    :           : allows rootless         : gVisor's own user :
:                    :           : execution.              : namespace.        :
| `--unshare-net`    | None      | Disables networking     | —                 |
:                    :           : entirely                :                   :
:                    :           : (`--network=none`). The :                   :
:                    :           : sandbox gets a loopback :                   :
:                    :           : interface and no host   :                   :
:                    :           : connectivity.           :                   :
| `--unshare-all`    | None      | Implies                 | Only those two    |
:                    :           : `--unshare-user` and    : parts do          :
:                    :           : `--unshare-net`.        : anything. Every   :
:                    :           :                         : other namespace   :
:                    :           :                         : it would unshare  :
:                    :           :                         : under native      :
:                    :           :                         : `bwrap` is        :
:                    :           :                         : already isolated. :
| `--unshare-ipc`    | None      | The Sentry always       | No-op. The        |
:                    :           : implements its own      : isolation is      :
:                    :           : System V IPC and POSIX  : already there, so :
:                    :           : message queues.         : the flag has      :
:                    :           :                         : nothing left to   :
:                    :           :                         : do.               :
| `--unshare-pid`    | None      | The Sentry always runs  | No-op, as above.  |
:                    :           : the command in its own  :                   :
:                    :           : process tree; host PIDs :                   :
:                    :           : are never visible.      :                   :
| `--unshare-uts`    | None      | The Sentry always owns  | No-op, as above.  |
:                    :           : the sandbox hostname;   :                   :
:                    :           : use `--hostname` to set :                   :
:                    :           : it.                     :                   :
| `--unshare-cgroup` | None      | The Sentry always       | No-op, as above.  |
:                    :           : presents its own        :                   :
:                    :           : `cgroupfs` at           :                   :
:                    :           : `/sys/fs/cgroup`.       :                   :

> **NOTE:** Without `--unshare-net` the sandbox runs with `runsc
> --network=host`, which forwards the application's socket calls to host
> sockets.

> **NOTE:** The no-op flags exist so that current `bwrap` command lines keep
> working. They are no-ops because gVisor already provides at least the
> isolation they ask for, never because the isolation is missing.

### Process & Identity Settings

| Flag         | Arguments | Description & OCI Mapping  | Difference     |
:              :           :                            : from `bwrap`   :
| :----------- | :-------- | :------------------------- | :------------- |
| `--chdir`    | `<DIR>`   | Sets the initial working   | `DIR` is a     |
:              :           : directory                  : host path,     :
:              :           : (`spec.Process.Cwd`).      : translated to  :
:              :           :                            : the sandbox    :
:              :           :                            : path through   :
:              :           :                            : the bind       :
:              :           :                            : mounts, so     :
:              :           :                            : `--bind        :
:              :           :                            : /home/me/work  :
:              :           :                            : /work --chdir  :
:              :           :                            : /home/me/work` :
:              :           :                            : starts in      :
:              :           :                            : `/work`. A     :
:              :           :                            : path under no  :
:              :           :                            : bind mount     :
:              :           :                            : source leaves  :
:              :           :                            : the working    :
:              :           :                            : directory at   :
:              :           :                            : `/`.           :
| `--hostname` | `<NAME>`  | Sets the hostname the      | —              |
:              :           : Sentry reports inside the  :                :
:              :           : sandbox (`spec.Hostname`). :                :
| `--uid`      | `<UID>`   | Custom UID in the sandbox  | —              |
:              :           : (`spec.Process.User.UID`). :                :
:              :           : Requires `--unshare-user`. :                :
| `--gid`      | `<GID>`   | Custom GID in the sandbox  | —              |
:              :           : (`spec.Process.User.GID`). :                :
:              :           : Requires `--unshare-user`. :                :
| `--argv0`    | `<VALUE>` | Runs the program named by  | —              |
:              :           : the command but passes     :                :
:              :           : `VALUE` as its `argv[0]`.  :                :
:              :           : May appear at most once,   :                :
:              :           : and rejects an empty       :                :
:              :           : value.                     :                :

> **NOTE:** Without `--uid` and `--gid`, the sandbox UID depends on
> `--unshare-user`. With it, the command runs as the UID/GID that invoked
> `runsc`, or as the `SUDO_UID`/`SUDO_GID` owner under `sudo`. Without it, the
> command runs as UID/GID 0. That is root as gVisor's kernel sees it, and it
> says nothing about the privileges the sandbox holds on the host.

### Process Lifetime & Terminal

| Flag                | Arguments | Behavior in gVisor | Difference from       |
:                     :           :                    : `bwrap`               :
| :------------------ | :-------- | :----------------- | :-------------------- |
| `--new-session`     | None      | No-op. The flag    | No-op. The protection |
:                     :           : exists to block    : it asks for is        :
:                     :           : `TIOCSTI` input    : already in place.     :
:                     :           : injection into the :                       :
:                     :           : host terminal, and :                       :
:                     :           : the Sentry leaves  :                       :
:                     :           : `TIOCSTI`          :                       :
:                     :           : unimplemented.     :                       :
| `--die-with-parent` | None      | No-op. The sandbox | Accepted and ignored. |
:                     :           : init process is a  : Nothing signals the   :
:                     :           : placeholder and    : command when          :
:                     :           : the command runs   : `runsc`'s parent      :
:                     :           : as an exec inside  : dies.                 :
:                     :           : it, so there is no :                       :
:                     :           : parent-child       :                       :
:                     :           : relationship for   :                       :
:                     :           : `PR_SET_PDEATHSIG` :                       :
:                     :           : to act on.         :                       :

> **WARNING:** `--die-with-parent` carries no cleanup guarantee here. `runsc`
> tears the sandbox down when it exits normally, but a `runsc` killed with
> `SIGKILL` leaves the sandbox running.

### Capabilities

By default the command holds every capability, in all five sets. Use
`--cap-drop` to narrow that down.

| Flag         | Arguments | Description & OCI Mapping    | Difference from    |
:              :           :                              : `bwrap`            :
| :----------- | :-------- | :--------------------------- | :----------------- |
| `--cap-drop` | `<CAP>`   | Removes `CAP` from all five  | —                  |
:              :           : capability sets in           :                    :
:              :           : `spec.Process.Capabilities`. :                    :
:              :           : The keyword `ALL` clears     :                    :
:              :           : every set. Names are         :                    :
:              :           : case-insensitive and the     :                    :
:              :           : `CAP_` prefix is optional.   :                    :
| `--cap-add`  | `<CAP>`   | Adds `CAP` back to all five  | `CAP_NET_RAW` is   |
:              :           : capability sets. The keyword : not restored,      :
:              :           : `ALL` restores the full set. : because raw        :
:              :           :                              : sockets are        :
:              :           :                              : disabled by        :
:              :           :                              : default; see note. :

Capability operations apply in command-line order, so `--cap-drop ALL --cap-add
NET_ADMIN` leaves the sandbox with exactly one capability.

> **NOTE:** gVisor's kernel enforces these capabilities inside the sandbox. They
> grant no privilege on the host: the Sentry never passes a capability through
> to a host syscall.

> **NOTE:** `CAP_NET_RAW` is the one exception to the table. `runsc` strips it
> from every set whenever raw sockets are disabled, and they are disabled by
> default, so `--cap-add NET_RAW` has no effect unless you also pass `runsc
> --net-raw`.

### Environment Variables

The sandbox inherits the host environment, and the personality adds nothing of
its own to it.

| Flag         | Arguments       | Description & OCI   | Difference from |
:              :                 : Mapping             : `bwrap`         :
| :----------- | :-------------- | :------------------ | :-------------- |
| `--setenv`   | `<VAR> <VALUE>` | Appends `VAR=VALUE` | —               |
:              :                 : to                  :                 :
:              :                 : `spec.Process.Env`. :                 :
| `--unsetenv` | `<VAR>`         | Removes an entry    | —               |
:              :                 : for `VAR` from      :                 :
:              :                 : `spec.Process.Env`. :                 :
| `--clearenv` | None            | Clears the          | —               |
:              :                 : environment except  :                 :
:              :                 : `PWD=<cwd>`, and    :                 :
:              :                 : discards any        :                 :
:              :                 : earlier             :                 :
:              :                 : `--unsetenv`.       :                 :

> **NOTE:** One combination does not carry over. Native `bwrap` applies
> `--setenv` and `--unsetenv` in command-line order, while this personality
> collects every `--setenv` first and resolves `--unsetenv` afterwards. That is
> only observable when a single command line both sets and unsets the same
> variable, so don't rely on the order of the two in that case. Every other
> combination behaves as it does under native `bwrap`, `--clearenv` included: it
> takes effect where it appears, wiping what comes before it and keeping what
> comes after.
