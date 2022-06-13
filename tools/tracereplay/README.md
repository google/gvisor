# What is it?

The `tracereplay` tool can save `runsc trace` sessions to a file, and later
replay the same sequence of messages. This can be used to run tests that rely on
the messages without the need to setup runsc, configure trace sessions, and run
specific workloads.

# How to use it?

The `tracereplay save` command starts a server that listens to new connections
from runsc and creates a trace file for each runsc instance that connects to it.
The command below starts a server on listening on `/tmp/gvisor_events.sock` and
writes trace files to `/tmp/trace` directory:

```shell
$ tracereplay save --endpoint=/tmp/gvisor_events.sock --out=/tmp/trace
```

When you execute runsc configured with a trace session using the `remote` sink
connecting to `/tmp/gvisor_events.sock`, all messages will be saved to a file
under `/tmp/trace`. For example, if you run the following commands, runsc will
connect to the server above and all trace points triggered by the workload will
be stored in the save file:

```shell
$ cat > /tmp/pod_init.json <<EOL
{
  "trace_session": {
    "name": "Default",
    "points": [
      {
        "name": "container/start"
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
EOL
$ runsc --rootless --network=none --pod-init-config=/tmp/pod_init.json do /bin/true
```

You should see the following output from `tracereplay save`:

```
New client connected, writing to: "/tmp/trace/client-0001"
Closing client, wrote 1 messages to "/tmp/trace/client-0001"
```

You can then use the `tracereplay replay` command to replay the exact same
messages anytime and as many times as you want. Here is an example using the
file created above:

```shell
$ tracereplay replay --endpoint=/tmp/gvisor_events.sock --in=/tmp/trace/client-0001
Handshake completed
Replaying message: 1
Done
```

If you want to see the messages that are stored in the file, you can setup the
example server provided in `examples/seccheck:server_cc` and replay the save
file using the same command above. Here is the output you would get:

```shell
$ bazel run examples/seccheck:server_cc
Socket address /tmp/gvisor_events.sock
Connection accepted
Start => id:     "runsc-865139" cwd: "/home/fvoznika" args: "/bin/true"
Connection closed
```
