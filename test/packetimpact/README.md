# Packetimpact

## What is packetimpact?

Packetimpact is a tool for platform-independent network testing. It is heavily
inspired by [packetdrill](https://github.com/google/packetdrill). It creates two
network namespaces. One is for the test bench, which operates the test. The
other is for the device-under-test (DUT), which is the software being tested.
The test bench communicates over the network with the DUT to check correctness
of the network.

### Goals

Packetimpact aims to provide:

*   A **multi-platform** solution that can test both Linux and gVisor.
*   **Conciseness** on par with packetdrill scripts.
*   **Control-flow** like for loops, conditionals, and variables.
*   **Flexibility** to specify every byte in a packet or use multiple sockets.

## How to run packetimpact tests?

Run a test, e.g. `fin_wait2_timeout`, against Linux:

```bash
$ bazel test //test/packetimpact/tests:fin_wait2_timeout_native_test
```

Run the same test, but against gVisor:

```bash
$ bazel test //test/packetimpact/tests:fin_wait2_timeout_netstack_test
```

## When to use packetimpact?

There are a few ways to write networking tests for gVisor currently:

*   [Go unit tests](https://github.com/google/gvisor/tree/master/pkg/tcpip)
*   [syscall tests](https://github.com/google/gvisor/tree/master/test/syscalls/linux)
*   [packetdrill tests](https://github.com/google/gvisor/tree/master/test/packetdrill)
*   packetimpact tests

The right choice depends on the needs of the test.

Feature        | Go unit test | syscall test | packetdrill | packetimpact
-------------- | ------------ | ------------ | ----------- | ------------
Multi-platform | no           | **YES**      | **YES**     | **YES**
Concise        | no           | somewhat     | somewhat    | **VERY**
Control-flow   | **YES**      | **YES**      | no          | **YES**
Flexible       | **VERY**     | no           | somewhat    | **VERY**

### Go unit tests

If the test depends on the internals of gVisor and doesn't need to run on Linux
or other platforms for comparison purposes, a Go unit test can be appropriate.
They can observe internals of gVisor networking. The downside is that they are
**not concise** and **not multi-platform**. If you require insight on gVisor
internals, this is the right choice.

### Syscall tests

Syscall tests are **multi-platform** but cannot examine the internals of gVisor
networking. They are **concise**. They can use **control-flow** structures like
conditionals, for loops, and variables. However, they are limited to only what
the POSIX interface provides so they are **not flexible**. For example, you
would have difficulty writing a syscall test that intentionally sends a bad IP
checksum. Or if you did write that test with raw sockets, it would be very
**verbose** to write a test that intentionally send wrong checksums, wrong
protocols, wrong sequence numbers, etc.

### Packetdrill tests

Packetdrill tests are **multi-platform** and can run against both Linux and
gVisor. They are **concise** and use a special packetdrill scripting language.
They are **more flexible** than a syscall test in that they can send packets
that a syscall test would have difficulty sending, like a packet with a
calcuated ACK number. But they are also somewhat limimted in flexibiilty in that
they can't do tests with multiple sockets. They have **no control-flow** ability
like variables or conditionals. For example, it isn't possible to send a packet
that depends on the window size of a previous packet because the packetdrill
language can't express that. Nor could you branch based on whether or not the
other side supports window scaling, for example.

### Packetimpact tests

Packetimpact tests are similar to Packetdrill tests except that they are written
in Go instead of the packetdrill scripting language. That gives them all the
**control-flow** abilities of Go (loops, functions, variables, etc). They are
**multi-platform** in the same way as packetdrill tests but even more
**flexible** because Go is more expressive than the scripting language of
packetdrill. However, Go is **not as concise** as the packetdrill language. Many
design decisions below are made to mitigate that.

## How it works

```
     Testbench                           Device-Under-Test (DUT)
    +-------------------+               +------------------------+
    |                   |   TEST NET    |                        |
    | rawsockets.go <-->| <===========> | <---+                  |
    |           ^       |               |     |                  |
    |           |       |               |     |                  |
    |           v       |               |     |                  |
    |     unittest      |               |     |                  |
    |           ^       |               |     |                  |
    |           |       |               |     |                  |
    |           v       |               |     v                  |
    |         dut.go <========gRPC========> posix server         |
    |                   |  CONTROL NET  |                        |
    +-------------------+               +------------------------+
```

Two network namespaces are created by the test runner, one for the testbench and
the other for the device under test (DUT). The runner connects the two
namespaces with a control veth pair and test veth pair. It also does some other
tasks like waiting until the DUT is ready before starting the test and
installing iptables rules so that RST won't be generated for TCP segments from
the DUT that the kernel has no knowledge about.

### DUT

The DUT namespace runs a program called the "posix_server". The posix_server is
written in c++ for maximum portability. Its job is to receive directions from
the test bench on what actions to take. For this, the posix_server does three
steps in a loop:

1.  Listen for a request from the test bench.
2.  Execute a command.
3.  Send the response back to the test bench.

The requests and responses are
[protobufs](https://developers.google.com/protocol-buffers) and the
communication is done with [gRPC](https://grpc.io/). The commands run are
[POSIX socket commands](https://en.wikipedia.org/wiki/Berkeley_sockets#Socket_API_functions),
with the inputs and outputs converted into protobuf requests and responses. All
communication is on the control network, so that the test network is unaffected
by extra packets.

For example, this is the request and response pair to call
[`socket()`](http://man7.org/linux/man-pages/man2/socket.2.html):

```protocol-buffer
message SocketRequest {
  int32 domain = 1;
  int32 type = 2;
  int32 protocol = 3;
}

message SocketResponse {
  int32 fd = 1;
  int32 errno_ = 2;
}
```

##### Alternatives considered

*   We could have use JSON for communication instead. It would have been a
    lighter-touch than protobuf but protobuf handles all the data type and has
    strict typing to prevent a class of errors. The test bench could be written
    in other languages, too.
*   Instead of mimicking the POSIX interfaces, arguments could have had a more
    natural form, like the `bind()` getting a string IP address instead of bytes
    in a `sockaddr_t`. However, conforming to the existing structures keeps more
    of the complexity in Go and keeps the posix_server simpler and thus more
    likely to compile everywhere.

### Test Bench

The test bench does most of the work in a test. It is a Go program that compiles
on the host and is run inside the test bench's namespace. It is a regular
[go unit test](https://golang.org/pkg/testing/) that imports the test bench
framework. The test bench framework is based on three basic utilities:

*   Commanding the DUT to run POSIX commands and return responses.
*   Sending raw packets to the DUT on the test network.
*   Listening for raw packets from the DUT on the test network.

#### DUT commands

To keep the interface to the DUT consistent and easy-to-use, each POSIX command
supported by the posix_server is wrapped in functions with signatures similar to
the ones in the [Go unix package](https://godoc.org/golang.org/x/sys/unix). This
way all the details of endianess and (un)marshalling of go structs such as
[unix.Timeval](https://godoc.org/golang.org/x/sys/unix#Timeval) is handled in
one place. This also makes it straight-forward to convert tests that use `unix.`
or `syscall.` calls to `dut.` calls.

For example, creating a connection to the DUT and commanding it to make a socket
looks like this:

```go
dut := testbench.NewDut(t)
fd, err := dut.SocketWithErrno(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_IP)
if fd < 0 {
  t.Fatalf(...)
}
```

Because the usual case is to fail the test when the DUT fails to create a
socket, there is a concise version of each of the `...WithErrno` functions that
does that:

```go
dut := testbench.NewDut(t)
fd := dut.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_IP)
```

The DUT and other structs in the code store a `*testing.T` so that they can
provide versions of functions that call `t.Fatalf(...)`. This helps keep tests
concise.

##### Alternatives considered

*   Instead of mimicking the `unix.` go interface, we could have invented a more
    natural one, like using `float64` instead of `Timeval`. However, using the
    same function signatures that `unix.` has makes it easier to convert code to
    `dut.`. Also, using an existing interface ensures that we don't invent an
    interface that isn't extensible. For example, if we invented a function for
    `bind()` that didn't support IPv6 and later we had to add a second `bind6()`
    function.

#### Sending/Receiving Raw Packets

The framework wraps POSIX sockets for sending and receiving raw frames. Both
send and receive are synchronous commands.
[SO_RCVTIMEO](http://man7.org/linux/man-pages/man7/socket.7.html) is used to set
a timeout on the receive commands. For ease of use, these are wrapped in an
`Injector` and a `Sniffer`. They have functions:

```go
func (s *Sniffer) Recv(timeout time.Duration) []byte {...}
func (i *Injector) Send(b []byte) {...}
```

##### Alternatives considered

*   [gopacket](https://github.com/google/gopacket) pcap has raw socket support
    but requires cgo. cgo is not guaranteed to be portable from the host to the
    container and in practice, the container doesn't recognize binaries built on
    the host if they use cgo. Packetimpact used to be based on docker, so the
    library was not adopted, now we can start to consider using the library.
*   Both gVisor and gopacket have the ability to read and write pcap files
    without cgo but that is insufficient here because we can't just replay pcap
    files, we need a more dynamic solution.
*   The sniffer and injector can't share a socket because they need to be bound
    differently.
*   Sniffing could have been done asynchronously with channels, obviating the
    need for `SO_RCVTIMEO`. But that would introduce asynchronous complication.
    `SO_RCVTIMEO` is well supported on the test bench.

#### `Layer` struct

A large part of packetimpact tests is creating packets to send and comparing
received packets against expectations. To keep tests concise, it is useful to be
able to specify just the important parts of packets that need to be set. For
example, sending a packet with default values except for TCP Flags. And for
packets received, it's useful to be able to compare just the necessary parts of
received packets and ignore the rest.

To aid in both of those, Go structs with optional fields are created for each
encapsulation type, such as IPv4, TCP, and Ethernet. This is inspired by
[scapy](https://scapy.readthedocs.io/en/latest/). For example, here is the
struct for Ethernet:

```go
type Ether struct {
  LayerBase
  SrcAddr *tcpip.LinkAddress
  DstAddr *tcpip.LinkAddress
  Type    *tcpip.NetworkProtocolNumber
}
```

Each struct has the same fields as those in the
[gVisor headers](https://github.com/google/gvisor/tree/master/pkg/tcpip/header)
but with a pointer for each field that may be `nil`.

##### Alternatives considered

*   Just use []byte like gVisor headers do. The drawback is that it makes the
    tests more verbose.
    *   For example, there would be no way to call `Send(myBytes)` concisely and
        indicate if the checksum should be calculated automatically versus
        overridden. The only way would be to add lines to the test to calculate
        it before each Send, which is wordy. Or make multiple versions of Send:
        one that checksums IP, one that doesn't, one that checksums TCP, one
        that does both, etc. That would be many combinations.
    *   Filtering inputs would become verbose. Either:
    *   large conditionals that need to be repeated many places:
        `h[FlagOffset] == SYN && h[LengthOffset:LengthOffset+2] == ...` or
    *   Many functions, one per field, like: `filterByFlag(myBytes, SYN)`,
        `filterByLength(myBytes, 20)`, `filterByNextProto(myBytes, 0x8000)`,
        etc.
    *   Using pointers allows us to combine `Layer`s with reflection. So the
        default `Layers` can be overridden by a `Layers` with just the TCP
        conection's src/dst which can be overridden by one with just a test
        specific TCP window size.
    *   It's a proven way to separate the details of a packet from the byte
        format as shown by scapy's success.
*   Use packetgo. It's more general than parsing packets with gVisor. However:
    *   packetgo doesn't have optional fields so many of the above problems
        still apply.
    *   It would be yet another dependency.
    *   It's not as well known to engineers that are already writing gVisor
        code.
    *   It might be a good candidate for replacing the parsing of packets into
        `Layer`s if all that parsing turns out to be more work than parsing by
        packetgo and converting *that* to `Layer`. packetgo has easier to use
        getters for the layers. This could be done later in a way that doesn't
        break tests.

#### `Layer` methods

The `Layer` structs provide a way to partially specify an encapsulation. They
also need methods for using those partially specified encapsulation, for example
to marshal them to bytes or compare them. For those, each encapsulation
implements the `Layer` interface:

```go
// Layer is the interface that all encapsulations must implement.
//
// A Layer is an encapsulation in a packet, such as TCP, IPv4, IPv6, etc. A
// Layer contains all the fields of the encapsulation. Each field is a pointer
// and may be nil.
type Layer interface {
    // toBytes converts the Layer into bytes. In places where the Layer's field
    // isn't nil, the value that is pointed to is used. When the field is nil, a
    // reasonable default for the Layer is used. For example, "64" for IPv4 TTL
    // and a calculated checksum for TCP or IP. Some layers require information
    // from the previous or next layers in order to compute a default, such as
    // TCP's checksum or Ethernet's type, so each Layer has a doubly-linked list
    // to the layer's neighbors.
    toBytes() ([]byte, error)

    // match checks if the current Layer matches the provided Layer. If either
    // Layer has a nil in a given field, that field is considered matching.
    // Otherwise, the values pointed to by the fields must match.
    match(Layer) bool

    // length in bytes of the current encapsulation
    length() int

    // next gets a pointer to the encapsulated Layer.
    next() Layer

    // prev gets a pointer to the Layer encapsulating this one.
    prev() Layer

    // setNext sets the pointer to the encapsulated Layer.
    setNext(Layer)

    // setPrev sets the pointer to the Layer encapsulating this one.
    setPrev(Layer)
}
```

The `next` and `prev` make up a link listed so that each layer can get at the
information in the layer around it. This is necessary for some protocols, like
TCP that needs the layer before and payload after to compute the checksum. Any
sequence of `Layer` structs is valid so long as the parser and `toBytes`
functions can map from type to protool number and vice-versa. When the mapping
fails, an error is emitted explaining what functionality is missing. The
solution is either to fix the ordering or implement the missing protocol.

For each `Layer` there is also a parsing function. For example, this one is for
Ethernet:

```
func ParseEther(b []byte) (Layers, error)
```

The parsing function converts bytes received on the wire into a `Layer`
(actually `Layers`, see below) which has no `nil`s in it. By using
`match(Layer)` to compare against another `Layer` that *does* have `nil`s in it,
the received bytes can be partially compared. The `nil`s behave as
"don't-cares".

##### Alternatives considered

*   Matching against `[]byte` instead of converting to `Layer` first.
    *   The downside is that it precludes the use of a `cmp.Equal` one-liner to
        do comparisons.
    *   It creates confusion in the code to deal with both representations at
        different times. For example, is the checksum calculated on `[]byte` or
        `Layer` when sending? What about when checking received packets?

#### `Layers`

```
type Layers []Layer

func (ls *Layers) match(other Layers) bool {...}
func (ls *Layers) toBytes() ([]byte, error) {...}
```

`Layers` is an array of `Layer`. It represents a stack of encapsulations, such
as `Layers{Ether{},IPv4{},TCP{},Payload{}}`. It also has `toBytes()` and
`match(Layers)`, like `Layer`. The parse functions above actually return
`Layers` and not `Layer` because they know about the headers below and
sequentially call each parser on the remaining, encapsulated bytes.

All this leads to the ability to write concise packet processing. For example:

```go
etherType := 0x8000
flags = uint8(header.TCPFlagSyn|header.TCPFlagAck)
toMatch := Layers{Ether{Type: &etherType}, IPv4{}, TCP{Flags: &flags}}
for {
  recvBytes := sniffer.Recv(time.Second)
  if recvBytes == nil {
    println("Got no packet for 1 second")
  }
  gotPacket, err := ParseEther(recvBytes)
  if err == nil && toMatch.match(gotPacket) {
    println("Got a TCP/IPv4/Eth packet with SYNACK")
  }
}
```

##### Alternatives considered

*   Don't use previous and next pointers.
    *   Each layer may need to be able to interrogate the layers around it, like
        for computing the next protocol number or total length. So *some*
        mechanism is needed for a `Layer` to see neighboring layers.
    *   We could pass the entire array `Layers` to the `toBytes()` function.
        Passing an array to a method that includes in the array the function
        receiver itself seems wrong.

#### `layerState`

`Layers` represents the different headers of a packet but a connection includes
more state. For example, a TCP connection needs to keep track of the next
expected sequence number and also the next sequence number to send. This is
stored in a `layerState` struct. This is the `layerState` for TCP:

```go
// tcpState maintains state about a TCP connection.
type tcpState struct {
    out, in                   TCP
    localSeqNum, remoteSeqNum *seqnum.Value
    synAck                    *TCP
    portPickerFD              int
    finSent                   bool
}
```

The next sequence numbers for each side of the connection are stored. `out` and
`in` have defaults for the TCP header, such as the expected source and
destination ports for outgoing packets and incoming packets.

##### `layerState` interface

```go
// layerState stores the state of a layer of a connection.
type layerState interface {
    // outgoing returns an outgoing layer to be sent in a frame.
    outgoing() Layer

    // incoming creates an expected Layer for comparing against a received Layer.
    // Because the expectation can depend on values in the received Layer, it is
    // an input to incoming. For example, the ACK number needs to be checked in a
    // TCP packet but only if the ACK flag is set in the received packet.
    incoming(received Layer) Layer

    // sent updates the layerState based on the Layer that was sent. The input is
    // a Layer with all prev and next pointers populated so that the entire frame
    // as it was sent is available.
    sent(sent Layer) error

    // received updates the layerState based on a Layer that is received. The
    // input is a Layer with all prev and next pointers populated so that the
    // entire frame as it was received is available.
    received(received Layer) error

    // close frees associated resources held by the LayerState.
    close() error
}
```

`outgoing` generates the default Layer for an outgoing packet. For TCP, this
would be a `TCP` with the source and destination ports populated. Because they
are static, they are stored inside the `out` member of `tcpState`. However, the
sequence numbers change frequently so the outgoing sequence number is stored in
the `localSeqNum` and put into the output of outgoing for each call.

`incoming` does the same functions for packets that arrive but instead of
generating a packet to send, it generates an expect packet for filtering packets
that arrive. For example, if a `TCP` header arrives with the wrong ports, it can
be ignored as belonging to a different connection. `incoming` needs the received
header itself as an input because the filter may depend on the input. For
example, the expected sequence number depends on the flags in the TCP header.

`sent` and `received` are run for each header that is actually sent or received
and used to update the internal state. `incoming` and `outgoing` should *not* be
used for these purpose. For example, `incoming` is called on every packet that
arrives but only packets that match ought to actually update the state.
`outgoing` is called to created outgoing packets and those packets are always
sent, so unlike `incoming`/`received`, there is one `outgoing` call for each
`sent` call.

`close` cleans up after the layerState. For example, TCP and UDP need to keep a
port reserved and then release it.

#### Connections

Using `layerState` above, we can create connections.

```go
// Connection holds a collection of layer states for maintaining a connection
// along with sockets for sniffer and injecting packets.
type Connection struct {
    layerStates []layerState
    injector    Injector
    sniffer     Sniffer
    t           *testing.T
}
```

The connection stores an array of `layerState` in the order that the headers
should be present in the frame to send. For example, Ether then IPv4 then TCP.
The injector and sniffer are for writing and reading frames. A `*testing.T` is
stored so that internal errors can be reported directly without code in the unit
test.

The `Connection` has some useful functions:

```go
// Close frees associated resources held by the Connection.
func (conn *Connection) Close() {...}
// CreateFrame builds a frame for the connection with layer overriding defaults
// of the innermost layer and additionalLayers added after it.
func (conn *Connection) CreateFrame(layer Layer, additionalLayers ...Layer) Layers {...}
// SendFrame sends a frame on the wire and updates the state of all layers.
func (conn *Connection) SendFrame(frame Layers) {...}
// Send a packet with reasonable defaults. Potentially override the final layer
// in the connection with the provided layer and add additionLayers.
func (conn *Connection) Send(layer Layer, additionalLayers ...Layer) {...}
// Expect a frame with the final layerStates layer matching the provided Layer
// within the timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *Connection) Expect(layer Layer, timeout time.Duration) (Layer, error) {...}
// ExpectFrame expects a frame that matches the provided Layers within the
// timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *Connection) ExpectFrame(layers Layers, timeout time.Duration) (Layers, error) {...}
// Drain drains the sniffer's receive buffer by receiving packets until there's
// nothing else to receive.
func (conn *Connection) Drain() {...}
```

`CreateFrame` uses the `[]layerState` to create a frame to send. The first
argument is for overriding defaults in the last header of the frame, because
this is the most common need. For a TCPIPv4 connection, this would be the TCP
header. Optional additionalLayers can be specified to add to the frame being
created, such as a `Payload` for `TCP`.

`SendFrame` sends the frame to the DUT. It is combined with `CreateFrame` to
make `Send`. For unittests with basic sending needs, `Send` can be used. If more
control is needed over the frame, it can be made with `CreateFrame`, modified in
the unit test, and then sent with `SendFrame`.

On the receiving side, there is `Expect` and `ExpectFrame`. Like with the
sending side, there are two forms of each function, one for just the last header
and one for the whole frame. The expect functions use the `[]layerState` to
create a template for the expected incoming frame. That frame is then overridden
by the values in the first argument. Finally, a loop starts sniffing packets on
the wire for frames. If a matching frame is found before the timeout, it is
returned without error. If not, nil is returned and the error contains text of
all the received frames that didn't match. Exactly one of the outputs will be
non-nil, even if no frames are received at all.

`Drain` sniffs and discards all the frames that have yet to be received. A
common way to write a test is:

```go
conn.Drain() // Discard all outstanding frames.
conn.Send(...) // Send a frame with overrides.
// Now expect a frame with a certain header and fail if it doesn't arrive.
if _, err := conn.Expect(...); err != nil { t.Fatal(...) }
```

Or for a test where we want to check that no frame arrives:

```go
if gotOne, _ := conn.Expect(...); gotOne != nil { t.Fatal(...) }
```

#### Specializing `Connection`

Because there are some common combinations of `layerState` into `Connection`,
they are defined:

```go
// TCPIPv4 maintains the state for all the layers in a TCP/IPv4 connection.
type TCPIPv4 Connection
// UDPIPv4 maintains the state for all the layers in a UDP/IPv4 connection.
type UDPIPv4 Connection
```

Each has a `NewXxx` function to create a new connection with reasonable
defaults. They also have functions that call the underlying `Connection`
functions but with specialization and tighter type-checking. For example:

```go
func (conn *TCPIPv4) Send(tcp TCP, additionalLayers ...Layer) {
    (*Connection)(conn).Send(&tcp, additionalLayers...)
}
func (conn *TCPIPv4) Drain() {
    conn.sniffer.Drain()
}
```

They may also have some accessors to get or set the internal state of the
connection:

```go
func (conn *TCPIPv4) state() *tcpState {
    state, ok := conn.layerStates[len(conn.layerStates)-1].(*tcpState)
    if !ok {
        conn.t.Fatalf("expected final state of %v to be tcpState", conn.layerStates)
    }
    return state
}
func (conn *TCPIPv4) RemoteSeqNum() *seqnum.Value {
    return conn.state().remoteSeqNum
}
func (conn *TCPIPv4) LocalSeqNum() *seqnum.Value {
    return conn.state().localSeqNum
}
```

Unittests will in practice use these functions and not the functions on
`Connection`. For example, `NewTCPIPv4()` and then call `Send` on that rather
than cast is to a `Connection` and call `Send` on that cast result.

##### Alternatives considered

*   Instead of storing `outgoing` and `incoming`, store values.
    *   There would be many more things to store instead, like `localMac`,
        `remoteMac`, `localIP`, `remoteIP`, `localPort`, and `remotePort`.
    *   Construction of a packet would be many lines to copy each of these
        values into a `[]byte`. And there would be slight variations needed for
        each encapsulation stack, like TCPIPv6 and ARP.
    *   Filtering incoming packets would be a long sequence:
    *   Compare the MACs, then
    *   Parse the next header, then
    *   Compare the IPs, then
    *   Parse the next header, then
    *   Compare the TCP ports. Instead it's all just one call to
        `cmp.Equal(...)`, for all sequences.
    *   A TCPIPv6 connection could share most of the code. Only the type of the
        IP addresses are different. The types of `outgoing` and `incoming` would
        be remain `Layers`.
    *   An ARP connection could share all the Ethernet parts. The IP `Layer`
        could be factored out of `outgoing`. After that, the IPv4 and IPv6
        connections could implement one interface and a single TCP struct could
        have either network protocol through composition.

## Putting it all together

Here's what te start of a packetimpact unit test looks like. This test creates a
TCP connection with the DUT. There are added comments for explanation in this
document but a real test might not include them in order to stay even more
concise.

```go
func TestMyTcpTest(t *testing.T) {
  // Prepare a DUT for communication.
  dut := testbench.NewDUT(t)

  // This does:
  //   dut.Socket()
  //   dut.Bind()
  //   dut.Getsockname() to learn the new port number
  //   dut.Listen()
  listenFD, remotePort := dut.CreateListener(unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
  defer dut.Close(listenFD) // Tell the DUT to close the socket at the end of the test.

  // Monitor a new TCP connection with sniffer, injector, sequence number tracking,
  // and reasonable outgoing and incoming packet field default IPs, MACs, and port numbers.
  conn := testbench.NewTCPIPv4(t, dut, remotePort)

  // Perform a 3-way handshake: send SYN, expect SYNACK, send ACK.
  conn.Handshake()

  // Tell the DUT to accept the new connection.
  acceptFD := dut.Accept(acceptFd)
}
```

### Adding a new packetimpact test

*   Create a go test in the [tests directory](tests/)
*   Add a `packetimpact_testbench` rule in [BUILD](tests/BUILD)
*   Add the test into the `ALL_TESTS` list in [defs.bzl](runner/defs.bzl),
    otherwise you will see an error message complaining about a missing test.

## Other notes

*   The time between receiving a SYN-ACK and replying with an ACK in `Handshake`
    is about 3ms. This is much slower than the native unix response, which is
    about 0.3ms. Packetdrill gets closer to 0.3ms. For tests where timing is
    crucial, packetdrill is faster and more precise.
