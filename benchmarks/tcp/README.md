# Benchmarks

This directory contains a standardized benchmarks. This helps to evaluate the
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
                                             [br0]
                                               |
          Network emulation applied ---> [wan.0:wan.1]
                                               |
                                             [br1]
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

This tool may be used to easily generate data for graphing. For example, to
generate a CSV for various latencies, you might do:

```
rm -f /tmp/netstack_latency.csv /tmp/native_latency.csv
latencies=$(seq 0 5 50;
            seq 60 10 100;
            seq 125 25 250;
            seq 300 50 500)
for latency in $latencies; do
  read throughput client_cpu server_cpu <<< \
    $(./tcp_benchmark --duration 30 --client --ideal --latency $latency)
  echo $latency,$throughput,$client_cpu >> /tmp/netstack_latency.csv
done
for latency in $latencies; do
  read throughput client_cpu server_cpu <<< \
    $(./tcp_benchmark --duration 30 --ideal --latency $latency)
  echo $latency,$throughput,$client_cpu >> /tmp/native_latency.csv
done
```

Similarly, to generate a CSV for various levels of packet loss, the following
would be appropriate:

```
rm -f /tmp/netstack_loss.csv /tmp/native_loss.csv
losses=$(seq 0 0.1 1.0;
         seq 1.2 0.2 2.0;
         seq 2.5 0.5 5.0;
         seq 6.0 1.0 10.0)
for loss in $losses; do
  read throughput client_cpu server_cpu <<< \
    $(./tcp_benchmark --duration 30 --client --ideal --latency 10 --loss $loss)
  echo $loss,$throughput,$client_cpu >> /tmp/netstack_loss.csv
done
for loss in $losses; do
  read throughput client_cpu server_cpu <<< \
    $(./tcp_benchmark --duration 30 --ideal --latency 10 --loss $loss)
  echo $loss,$throughput,$client_cpu >> /tmp/native_loss.csv
done
```
