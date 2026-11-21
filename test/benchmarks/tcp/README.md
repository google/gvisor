# TCP Benchmarks

This directory contains a standardized TCP benchmark. This helps to evaluate the
performance of netstack and native networking stacks under various conditions.

## `tcp_benchmark`

This benchmark allows TCP throughput testing under various conditions. The setup
consists of an iperf client, a client proxy, a server proxy and an iperf server.
The client proxy and server proxy abstract the network mechanism used to
communicate between the iperf client and server.

The setup looks like the following:

```
 +--------------+  (native)            +--------------+
 | iperf client |[lo @ 10.0.0.1]------>| client proxy |
 +--------------+                      +--------------+
                                    [client.0 @ 10.0.0.2]
                            (netstack)  |            |  (native)
                                        +------+-----+
                                               |
    Bottleneck for acknowledgements ---> [client.1]
                                               |
                                             [br0]
                                               |
          Network emulation applied ---> [wan.0:wan.1]
                                               |
                                             [br1]
                                               |
                Bottleneck for data ---> [server.1]
                                               |
                                        +------+-----+
                            (netstack)  |            |  (native)
                                     [server.0 @ 10.0.0.3]
 +--------------+                      +--------------+
 | iperf server |<------[lo @ 10.0.0.4]| server proxy |
 +--------------+            (native)  +--------------+
```

Different configurations can be run using different arguments. For example:

*   Native test under normal internet conditions: `tcp_benchmark`
*   Native test under ideal conditions: `tcp_benchmark --ideal`
*   Netstack client under ideal conditions: `tcp_benchmark --client --ideal`
*   Netstack client with 5% packet loss: `tcp_benchmark --client --ideal --loss
    5`

Use `tcp_benchmark --help` for full arguments.

The benchmark prints one line in the Go benchmark format, which `benchstat`
reads:

```
BenchmarkTCP/sender=netstack-cubic/receiver=linux/role=client/.../mtu=1500/rtt=50ms/.../rate=100/queue=416/ecn=false 1 87.2 Mb/s 0.41 cpu-time 112 retransmits
```

*   `sender` and `receiver` are the network stacks that send and receive the
    data on the emulated network: `netstack-reno`, `netstack-cubic` or
    `linux-<congestion control>` for the sender, and `netstack` or `linux` for
    the receiver.
*   `role` is the measured proxy: `client` for the sender and `server` for the
    receiver.
*   `netstack-gso` is `none`, `host` when netstack sends GSO packets that Linux
    segments (`--gso`), or `gvisor` when netstack segments them (`--swgso`).
*   `mtu`, `rtt`, `jitter`, `loss`, `duplicate`, `reorder` and `rate` are the
    values of `--mtu`, `--latency`, `--latency-variation`, `--loss`,
    `--duplicate`, `--reorder` and `--rate`. `queue` is the length of the
    bottleneck queue in packets, and `ecn` is `true` with `--ecn`. `loss` is
    2 times the loss of the data packets.
*   `Mb/s` is the rate at which the iperf server received the data.
*   `cpu-time` is the average number of CPUs that the measured proxy used.
*   `retransmits` is the number of segments that the sender retransmitted during
    the run.

The name does not contain the other options, for example `--sack` and
`--duration`. Use a different output file for each set of these options,
because `benchstat` puts results with the same name together.

### Network emulation

The benchmark applies `--latency`, `--loss`, `--duplicate` and `--reorder` to
each direction at half of the given value. For example, `--latency 50 --loss
0.2` gives a round-trip time of 50ms, and drops 0.1% of the data packets and
0.1% of the acknowledgements.

`--rate` adds a bottleneck in each direction, after the latency. The rate
includes the Ethernet header, so the throughput at `--rate 100` is approximately
95 Mbit/s. The bottleneck has a queue that holds `--queue` packets of the
maximum size. The default is one bandwidth-delay product, and not less than 20
packets. The queue drops packets when it is full. After an idle period, a burst
goes through the bottleneck before the queue starts to fill. The burst is 4ms of
traffic, and not more than the queue. With `--ecn`, the queue is a CoDel queue
that marks ECN-capable packets and drops other packets. Netstack does not use
ECN, so with netstack as the sender or as the receiver the queue drops packets
and does not mark them.

Netem drops a GSO packet as one packet, and a GSO packet that is not larger
than the burst goes into the queue as one packet. Use `--disable-linux-gso` to
make each packet on the emulated network not larger than the MTU.

Without `--rate`, the path has no congestion. Throughput then depends on the
latency, the random loss, the buffer sizes and the CPU.

### Comparison with Linux

`tcp_matrix.sh` runs the benchmark with a 100 Mbit/s bottleneck at round-trip
times of 1ms, 50ms and 150ms and data loss of 0%, 0.01% and 0.1%. It runs
netstack with Reno and with CUBIC as the sender, each without GSO, with host
GSO and with gVisor GSO. It also runs netstack as the receiver, and Linux on
both sides. It disables TSO and GSO in the Linux network stack, so that the
network emulation drops and queues single packets for each stack. It takes the
number of runs, the output file to append to, and more options for
`tcp_benchmark.sh`. Build the helpers, then run it from the source directory:

```
make copy TARGETS="//test/benchmarks/tcp:tcp_proxy //test/benchmarks/tcp:nsjoin" DESTINATION=<directory>
./tcp_matrix.sh 24 results.txt --helpers <directory>
benchstat -filter /role:client -row /rtt,/loss -col /sender,/netstack-gso results.txt
benchstat -filter /role:server -row /rtt,/loss -col /receiver results.txt
```

The first `benchstat` command compares the senders and the netstack GSO modes,
and the second `benchstat` command compares the receivers. One run of the
matrix takes approximately 50 minutes with the default `--duration` of 30
seconds. 24 runs take approximately 20 hours.

A run of 30 seconds has few congestion events at the longer round-trip times,
and the result then depends on the first events. Use a larger `--duration` to
measure the steady state. At a round-trip time of 150ms and 0% loss, the
senders do not fill the default queue and the result has 0 retransmits, so
that case does not measure congestion control.
