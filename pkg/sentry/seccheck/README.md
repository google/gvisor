# Introduction

This package provides a remote interface to observe behavior of the application
running inside the sandbox. It was built with runtime monitoring in mind, e.g.
threat detection, but it can be used for other purposes as well. It allows a
process running outside the sandbox to receive a stream of trace data
asynchronously. This process can watch actions performed by the application,
generate alerts when something unexpected occurs, log these actions, etc.

First, let's go over a few concepts before we get into the details.

## Concepts

-   **Points:** these are discrete places (or points) in the code where
    instrumentation was added. Each point has a unique name and schema. They can
    be individually enabled/disabled. For example, `container/start` is a point
    that is fired when a new container starts.
-   **Point fields:** each point may contain fields that carry point data. For
    example, `container/start` has a `id` field with the container ID that is
    getting started.
-   **Optional fields:** each point may also have optional fields. By default
    these fields are not collected and they can be manually set to be collected
    when the point is configured. These fields are normally more expensive to
    collect and/or large, e.g. resolve path to FD, or data for read/write.
-   **Context fields:** these are fields generally available to most events, but
    are disabled by default. Like optional fields, they can be set to be
    collected when the point is configured. Context field data comes from
    context where the point is being fired, for example PID, UID/GID, container
    ID are fields available to most trace points.
-   **Sink:** sinks are trace point consumers. Each sink is identified by a name
    and may handle trace points differently. Later we'll describe in more
    detailed what sinks are available in the system and how to use them.
-   **Session:** trace session is a set of points that are enabled with their
    corresponding configuration. A trace session also has a list of sinks that
    will receive the trace points. A session is identified by a unique name.
    Once a session is deleted, all points belonging to the session are disabled
    and the sinks destroyed.

If you're interested in exploring further, there are more details in the
[design doc](https://docs.google.com/document/d/1RQQKzeFpO-zOoBHZLA-tr5Ed_bvAOLDqgGgKhqUff2A/edit).

# Points

Every trance point in the system is identified by a unique name. The naming
convention is to scope the point with a main component followed by its name to
avoid conflicts. Here are a few examples:

-   `sentry/signal_delivered`
-   `container/start`
-   `syscall/openat/enter`

> Note: the syscall trace point contains an extra level to separate the
> enter/exit points.

Most of the trace points are in the `syscall` component. They come in 2 flavors:
raw, schematized. Raw syscalls include all syscalls in the system and contain
the 6 arguments for the given syscall. Schematized trace points exist for many
syscalls, but not all. They provide fields that are specific to the syscalls and
fetch more information than is available from the raw syscall arguments. For
example, here is the schema for the open syscall:

```proto
message Open {
  gvisor.common.ContextData context_data = 1;
  Exit exit = 2;
  uint64 sysno = 3;
  int64 fd = 4;
  string fd_path = 5;
  string pathname = 6;
  uint32 flags = 7;
  uint32 mode = 8;
}
```

As you can see, some fields are in both raw and schematized points, like `fd`
which is also `arg1` in the raw syscall, but here it has a name and correct
type. It also has fields like `pathname` that are not available in the raw
syscall event. In addition, `fd_path` is an optional field that can take the
`fd` and translate it into a full path for convenience. In some cases, the same
schema can be shared by many syscalls. In this example, `message Open` is used
for `open(2)`, `openat(2)` and `creat(2)` syscalls. The `sysno` field can be
used to distinguish between them. The schema for all syscall trace points can be
found
[here](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/syscall.proto).

Other components that exist today are:

*   **sentry:** trace points fired from within gVisor's kernel
    ([schema](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/sentry.proto)).
*   **container:** container related events
    ([schema](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/container.proto)).

The following command lists all trace points available in the system:

```shell
$ runsc trace metadata
POINTS (973)
Name: container/start, optional fields: [env], context fields: [time|thread_id|task_start_time|group_id|thread_group_start_time|container_id|credentials|cwd|process_name]
Name: sentry/clone, optional fields: [], context fields: [time|thread_id|task_start_time|group_id|thread_group_start_time|container_id|credentials|cwd|process_name]
Name: syscall/accept/enter, optional fields: [fd_path], context fields: [time|thread_id|task_start_time|group_id|thread_group_start_time|container_id|credentials|cwd|process_name]
...
```

> Note: the output format for `trace metadata` may change without notice.

The list above also includes what optional and context fields are available for
each trace point. Optional fields schema is part of the trace point proto, like
`fd_path` we saw above. Context fields are set in `context_data` field of all
points and is defined in
[gvisor.common.ContextData](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/common.proto;bpv=1;bpt=1;l=77?gsn=ContextData&gs=kythe%3A%2F%2Fgithub.com%2Fgoogle%2Fgvisor%3Flang%3Dprotobuf%3Fpath%3Dpkg%2Fsentry%2Fseccheck%2Fpoints%2Fcommon.proto%234.2).

# Sinks

Sinks receive enabled trace points and do something useful with them. They are
identified by a unique name. The same `runsc trace metadata` command used above
also lists all sinks:

```shell
$ runsc trace metadata
...
SINKS (2)
Name: remote
Name: null

```

> Note: the output format for `trace metadata` may change without notice.

## Remote

The remote sink serializes the trace point into protobuf and sends it to a
separate process. For threat detection, external monitoring processes can
receive connections from remote sinks and be sent a stream of trace points that
are occurring in the system. This sink connects to a remote process via Unix
domain socket and expects the remote process to be listening for new
connections. If you're interested in creating a monitoring process that
communicates with the remote sink, [this document](sinks/remote/README.md) has
more details.

The remote sink has many properties that can be configured when it's created
(more on how to configure sinks below):

*   `endpoint` (mandatory): Unix domain socket address to connect.
*   `retries`: number of attempts to write the trace point before dropping it in
    case the remote process is not responding. Note that a high number of
    retries can significantly delay application execution.
*   `backoff`: initial backoff time after the first failed attempt. This value
    doubles with every failed attempt, up to the max.
*   `backoff_max`: max duration to wait between retries.

## Null

The null sink does nothing with the trace points and it's used for testing.
Syscall tests enable all trace points, with all optional and context fields to
ensure there is no crash with them enabled.

## Strace (not implemented)

The strace sink has not been implemented yet. It's meant to replace the strace
mechanism that exists in the Sentry to simplify the code and add more trace
points to it.

> Note: It requires more than one trace session to be supported.

# Sessions

Trace sessions scope a set of trace points with their corresponding
configuration and a set of sinks that receive the points. Sessions can be
created at sandbox initialization time or during runtime. Creating sessions at
init time guarantees that no trace points are missed, which is important for
threat detection. It is configured using the `--pod-init-config` flag (more on
it below). To manage sessions during runtime, `runsc trace create|delete|list`
is used to manipulate trace sessions. Here are few examples assuming there is a
running container with ID=cont123 using Docker:

```shell
$ sudo runsc --root /run/docker/runtime-runc/moby trace create --config session.json cont123
$ sudo runsc --root /run/docker/runtime-runc/moby trace list cont123
SESSIONS (1)
"Default"
        Sink: "remote", dropped: 0

$ sudo runsc --root /var/run/docker/runtime-runc/moby trace delete --name Default cont123
$ sudo runsc --root /var/run/docker/runtime-runc/moby trace list cont123
SESSIONS (0)
```

> Note: There is a current limitation that only a single session can exist in
> the system and it must be called `Default`. This restriction can be lifted in
> the future when more than one session is needed.

## Config

The event session can be defined using JSON for the `runsc trace create`
command. The session definition has 3 main parts:

1.  `name`: name of the session being created. Only `Default` for now.
1.  `points`: array of points being enabled in the session. Each point has:
    1.  `name`: name of trace point being enabled.
    1.  `optional_fields`: array of optional fields to include with the trace
        point.
    1.  `context_fields`: array of context fields to include with the trace
        point.
1.  `sinks`: array of sinks that will process the trace points.
    1.  `name`: name of the sink.
    1.  `config`: sink specific configuration.
    1.  `ignore_setup_error`: ignores failure to configure the sink. In the
        remote sink case, for example, it doesn't fail container startup if the
        remote process cannot be reached.

The session configuration above can also be used with the `--pod-init-config`
flag under the `"trace_session"` JSON object. There is a full example
[here](https://cs.opensource.google/gvisor/gvisor/+/master:examples/seccheck/pod_init.json)

> Note: For convenience, the `--pod-init-config` file can also be used with
> `runsc trace create` command. The portions of the Pod init config file that
> are not related to the session configuration are ignored.

# Full Example

Here, we're going to explore a how to use runtime monitoring end to end. Under
the `examples` directory there is an implementation of the monitoring process
that accepts connections from remote sinks and prints out all the trace points
it receives.

First, let's start the monitoring process and leave it running:

```shell
$ bazel run examples/seccheck:server_cc
Socket address /tmp/gvisor_events.sock
```

The server is now listening on the socket at `/tmp/gvisor_events.sock` for new
gVisor sandboxes to connect. Now let's create a session configuration file with
some trace points enabled and the remote sink using the socket address from
above:

```shell
$ cat <<EOF >session.json
{
  "trace_session": {
    "name": "Default",
    "points": [
      {
        "name": "sentry/clone"
      },
      {
        "name": "syscall/fork/enter",
        "context_fields": [
          "group_id",
          "process_name"
        ]
      },
      {
        "name": "syscall/fork/exit",
        "context_fields": [
          "group_id",
          "process_name"
        ]
      },
      {
        "name": "syscall/execve/enter",
        "context_fields": [
          "group_id",
          "process_name"
        ]
      },
      {
        "name": "syscall/sysno/35/enter",
        "context_fields": [
          "group_id",
          "process_name"
        ]
      },
      {
        "name": "syscall/sysno/35/exit"
      }
    ],
    "sinks": [
      {
        "name": "remote",
        "config": {
          "endpoint": "/tmp/gvisor_events.sock"
        }
      }
    ]
  }
}
EOF
```

Now, we're ready to start a container and watch it send traces to the monitoring
process. The container we're going to create simply loops every 5 seconds and
writes something to stdout. While the container is running, we're going to call
`runsc trace` command to create a trace session.

```shell
# Start the container and copy the container ID for future reference.
$ docker run --rm --runtime=runsc -d bash -c "while true; do echo looping; sleep 5; done"
dee0da1eafc6b15abffeed1abc6ca968c6d816252ae334435de6f3871fb05e61

$ CID=dee0da1eafc6b15abffeed1abc6ca968c6d816252ae334435de6f3871fb05e61

# Create new trace session in the container above.
$ sudo runsc --root /var/run/docker/runtime-runc/moby trace create --config session.json ${CID?}
Trace session "Default" created.
```

In the terminal where you are running the monitoring process, you'll start
seeing messages like this:

```
Connection accepted
E Fork context_data      { thread_group_id: 1 process_name: "bash" } sysno: 57
CloneInfo => created_thread_id:      110 created_thread_group_id: 110 created_thread_start_time_ns: 1660249219204031676
X Fork context_data      { thread_group_id: 1 process_name: "bash" } exit { result: 110 } sysno: 57
E Execve context_data    { thread_group_id: 110 process_name: "bash" } sysno: 59 pathname: "/bin/sleep" argv: "sleep" argv: "5"
E Syscall context_data   { thread_group_id: 110 process_name: "sleep" } sysno: 35 arg1: 139785970818200 arg2: 139785970818200
X Syscall context_data   { thread_group_id: 110 process_name: "sleep" } exit { } sysno: 35 arg1: 139785970818200 arg2: 139785970818200
```

The first message in the log is a notification that a new sandbox connected to
the monitoring process. The `E` and `X` in front of the syscall traces denotes
whether the trace belongs to an `E`nter or e`X`it syscall trace. The first
syscall trace shows a call to `fork(2)` from a process with `group_thread_id`
(or PID) equal to 1 and the process name is `bash`. In other words, this is the
init process of the container, running `bash`, and calling fork to execute
`sleep 5`. The next trace is from `sentry/clone` and informs that the forked
process has PID=110. Then, `X Fork` indicates that `fork(2)` syscall returned to
the parent. The child continues and executes `execve(2)` to call `sleep` as can
be seen from the `pathname` and `argv` fields. Note that at this moment, the PID
is 110 (child) but the process name is still `bash` because it hasn't executed
`sleep` yet. After `execve(2)` is called the process name changes to `sleep` as
expected. Next, it shows the `nanosleep(2)` raw syscalls, which have `sysno`=35
(referred to as `syscall/sysno/35` in the configuration file), one for enter
with the exit trace happening 5 seconds later.

Let's list all trace sessions that are active in the sandbox:

```shell
$ sudo runsc --root /var/run/docker/runtime-runc/moby trace list ${CID?}
SESSIONS (1)
"Default"
        Sink: "remote", dropped: 0
```

It shows the `Default` session created above, using the `remote` sink and no
trace points have been dropped. Once we're done, the trace session can be
deleted with the command below:

```shell
$ sudo runsc --root /var/run/docker/runtime-runc/moby trace delete --name
Default ${CID?} Trace session "Default" deleted.
```

In the monitoring process you should see a message `Connection closed` to inform
that the sandbox has disconnected.

If you want to set up `runsc` to connect to the monitoring process automatically
before the application starts running, you can set the `--pod-init-config` flag
to the configuration file created above. Here's an example:

```shell
$ sudo runsc --install --runtime=runsc-trace -- --pod-init-config=$PWD/session.json
```
