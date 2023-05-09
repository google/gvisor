# gVisor RACK

gVisor has implemented the [RACK](https://datatracker.ietf.org/doc/html/rfc8985)
(Recent ACKnowledgement) TCP loss-detection algorithm in our network stack,
which improves throughput in the presence of packet loss and reordering.

TCP is a connection-oriented protocol that detects and recovers from loss by
retransmitting packets. [RACK](https://datatracker.ietf.org/doc/html/rfc8985) is
one of the recent loss-detection methods implemented in Linux and BSD, which
helps in identifying packet loss quickly and accurately in the presence of
packet reordering and tail losses.

## Background

The TCP congestion window indicates the number of unacknowledged packets that
can be sent at any time. When packet loss is identified, the congestion window
is reduced depending on the type of loss. The sender will recover from the loss
after all the packets sent before reducing the congestion window are
acknowledged. If the loss is identified falsely by the connection, then the
connection enters loss recovery unnecessarily, resulting in sending fewer
packets.

Packet loss is identified mainly in two ways:

1.  Three duplicate acknowledgments, which will result in either
    [Fast](https://datatracker.ietf.org/doc/html/rfc2001#section-4) or
    [SACK](https://datatracker.ietf.org/doc/html/rfc6675) recovery. The
    congestion window is reduced depending on the type of congestion control
    algorithm. For example, in the
    [Reno](https://en.wikipedia.org/wiki/TCP_congestion_control#TCP_Tahoe_and_Reno)
    algorithm it is reduced to half.
2.  RTO (Retransmission Timeout) which will result in Timeout recovery. The
    congestion window is reduced to one
    [MSS](https://en.wikipedia.org/wiki/Maximum_segment_size).

Both of these cases result in reducing the congestion window, with RTO being
more expensive. Most of the existing algorithms do not detect packet reordering,
which get incorrectly identified as packet loss, resulting in an RTO.
Furthermore, the loss of an ACK at the end of a sequence (known as "tail loss")
will also trigger RTO and slow down future transmissions unnecessarily. RACK
helps us to identify loss accurately in all these scenarios, and will avoid
entering RTO.

## Implementation of RACK

Implementation of RACK requires support for:

1.  Per-packet transmission timestamps: RACK detects loss depending on the
    transmission times of the packet and the timestamp at which ACK was
    received.
2.  SACK and ability to detect DSACK: Selective Acknowledgement and Duplicate
    SACK are used to adjust the timer window after which a packet can be marked
    as lost.

### Packet Reordering

Packet reordering commonly occurs when different packets take different paths
through a network. The diagram below shows the transmission of four packets
which get reordered in transmission, and the resulting TCP behavior with and
without RACK.

![Figure 1](/assets/images/2021-08-31-rack-figure1.png "Packet reordering.")

In the above example, the sender sees three duplicate acknowledgments. Without
RACK, this is identified falsely as packet loss, and the congestion window will
be reduced after entering Fast/SACK recovery.

To detect packet reordering, RACK uses a reorder window, bounded between
[[RTT](https://en.wikipedia.org/wiki/Round-trip_delay)/4, RTT]. The reorder
timer is set to expire after _RTT+reorder\_window_. A packet is marked as lost
when the packets following it were acknowledged using SACK and the reorder timer
expires. The reorder window is increased when a DSACK is received (which
indicates that there is a higher degree of reordering).

### Tail Loss

Tail loss occurs when the packets are lost at the end of data transmission. The
diagram below shows an example of tail loss when the last three packets are
lost, and how it is handled with and without RACK.

![Figure 2](/assets/images/2021-08-31-rack-figure2.png "Tail loss figure 2.")

For tail losses, RACK uses a Tail Loss Probe (TLP), which relies on a timer for
the last packet sent. The TLP timer is set to _2 \* RTT,_ after which a probe is
sent. The probe packet will allow the connection one more chance to detect a
loss by triggering ACK feedback to avoid entering RTO. In the above example, the
loss is recovered without entering the RTO.

TLP will also help in cases where the ACK was lost but all the packets were
received by the receiver. The below diagram shows that the ACK received for the
probe packet avoided the RTO.

![Figure 3](/assets/images/2021-08-31-rack-figure3.png "Tail loss figure 3.")

If there was some loss, then the ACK for the probe packet will have the SACK
blocks, which will be used to detect and retransmit the lost packets.

In gVisor, we have support for
[NewReno](https://datatracker.ietf.org/doc/html/rfc6582) and SACK loss recovery
methods. We
[added support for RACK](https://github.com/google/gvisor/issues/5243) recently,
and it is the default when SACK is enabled. After enabling RACK, our internal
benchmarks in the presence of reordering and tail losses and the data we took
from internal users inside Google have shown ~50% reduction in the number of
RTOs.

While RACK has improved one aspect of TCP performance by reducing the timeouts
in the presence of reordering and tail losses, in gVisor we plan to implement
the undoing of congestion windows and
[BBRv2](https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control)
(once there is an RFC available) to further improve TCP performance in less
ideal network conditions.

If you haven’t already, try gVisor. The instructions to get started are in our
[Quick Start](https://gvisor.dev/docs/user_guide/quick_start/docker/). You can
also get involved with the gVisor community via our
[Gitter channel](https://gitter.im/gvisor/community),
[email list](https://groups.google.com/forum/#!forum/gvisor-users),
[issue tracker](https://gvisor.dev/issue/new), and
[Github repository](https://github.com/google/gvisor).
