# Introduction

The remote sink implements a protocol that allows remote processes to monitor
actions being taken inside the sandbox. This document provides information
required to implement a monitoring process that consumes trace points. The
remote sink uses a Unix-domain socket (UDS) for communication. It opens a new
connection and sends a stream of trace points being triggered inside the sandbox
to the monitoring process. The monitoring process is expected to have already
created the UDS and be listening for new connections. This allows for a single
process to monitor all sandboxes in the machine, for better resource usage, and
simplifies lifecycle management. When a new sandbox starts, it creates a new
connection. And when a sandbox exits, the connection is terminated.

# Security Considerations

It’s important to note that in gVisor’s Threat Model, the Sentry is not trusted.
In order to ensure a secure posture, we assume the worst and consider that the
Sentry has been exploited. With that in mind, the monitoring process must
validate and never trust input received from the Sentry because it can be
controlled by a malicious user. All fields must have hard coded size limits.
Each sandbox uses a dedicated socket to prevent a malicious container from
corrupting or DoS’ing other sandboxes communication.

Simplicity in the protocol is paramount to keep the code easy to audit and
secure. For this reason we chose to use UDS type `SOCK_SEQPACKET` to delimitate
message boundaries. Also, each message contains a header and the payload uses
[Protocol Buffers](https://developers.google.com/protocol-buffers) which is safe
to deserialize using standard libraries.

# Protocol

Upon a new connection, there is a handshake message to ensure that both sides
can communicate with each other. The handshake contract is detailed
[here](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/common.proto;drc=e06df74a657e01008194f905f2795d43dd5a825e;bpv=1;bpt=1;l=63?gsn=Handshake&gs=kythe%3A%2F%2Fgithub.com%2Fgoogle%2Fgvisor%3Flang%3Dprotobuf%3Fpath%3Dpkg%2Fsentry%2Fseccheck%2Fpoints%2Fcommon.proto%234.0).

This is the only time that the monitoring process writes to the socket. From
this point on, it only reads a stream of trace points generated from the Sentry.
Each message contain a header that describes the message being sent and a few
more control fields, e.g. number of messages dropped. There is a full
description of the header
[here](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/sinks/remote/wire/wire.go).

The payload can be deserialized based on the message type indicated in the
header, Each message type corresponds to a protobuf type defined in one of
[these files](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/points/).

# Compatibility

It’s important that updates to gVisor do not break compatibility with trace
consumers. They may not understand new events, or new event fields, but should
continue to work with the old event schema.

*   **New message/trace point:** new messages and trace points can be added
    freely. The monitoring process will fail when it tries to deserialize an
    unknown proto type. They should ignore this error.
*   **New field to event:** as long as proto updating rules are followed, the
    monitoring process will be able to deserialize the event, ignoring new
    fields.
*   **Changes to existing fields:** these are rare given that syscall arguments
    don’t change. But if this is necessary, it should be handled as a deletion
    of the old field and addition of the new one. It may break event consumers
    that are relying on the old field being set, but at least the event can be
    deserialized and other fields will be correct. If possible, populate both
    fields until consumers have migrated over.
*   **Message header change:** similar to proto, header changes can only be
    additional. Existing fields cannot change offsets. Header size can be used
    to determine what portions of the header are available.
*   **Change in wire format:** it requires changing protocol version. This will
    be detected and handled during the handshake. If one of the side decide that
    it cannot talk to the other side, the communication will terminate.

# Examples

If you're looking to create a new monitoring process, you can use any of the
examples provided as a starting point. As a picture is worth a thousand words,
the same applies for code examples:

1.  **Go:**
    [pkg/sentry/seccheck/sinks/remote/server/server.go](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/sentry/seccheck/sinks/remote/server/server.go)
1.  **C++:**
    [examples/seccheck/README.md](../../../../../examples/seccheck/README.md)

# Testing

Apart from using `runsc` directly to test that your code works, you can use a
tool that we created to save and replay trace sessions in full without the need
for complex setup. Just run `runsc` once to capture the trace files you need for
the test, then just replay from the file as often as needed. See
[tracereplay](../../../../../tools/tracereplay/README.md) for more details.
