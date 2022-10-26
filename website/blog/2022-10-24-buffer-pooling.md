# How we Eliminated 99% of gVisor Networking Memory Allocations with Enhanced Buffer Pooling

In an
[earlier blog post](https://gvisor.dev/blog/2020/04/02/gvisor-networking-security/)
about networking security, we described how and why gVisor implements its own
userspace network stack in the Sentry (gVisor kernel). In summary, we’ve
implemented our networking stack – aka Netstack – in Go to minimize exposure to
unsafe code and avoid using an unsafe Foreign Function Interface. With Netstack,
gVisor can do all packet processing internally and only has to enable a few host
I/O syscalls for near-complete networking capabilities. This keeps gVisor’s
exposure to host vulnerabilities as narrow as possible.

Although writing Netstack in Go was important for runtime safety, up until now
it had an undeniable performance cost. iperf benchmarks showed Netstack was
spending between 20-30% of its processing time allocating memory and pausing for
garbage collection, a slowdown that limited gVisor’s ability to efficiently
sandbox networking workloads. In this blog we will show how we crafted a cure
for Netstack’s allocation addiction, reducing them by 99%, while also increasing
gVisor networking throughput by 30+%.

![Figure 1](/assets/images/2022-10-24-buffer-pooling-figure1.png "Buffer pooling results."){:width="100%"}

## A Waste Management Problem

Go guarantees a basic level of memory safety through the use of a garbage
collector (GC), which is described in great detail by the Go team
[here](https://tip.golang.org/doc/gc-guide). The Go runtime automatically tracks
and frees objects allocated from the heap, relieving the programmer of the often
painful and error-prone process of manual memory management. Unfortunately,
tracking and freeing memory during runtime comes at a performance cost. Running
the GC adds scheduling overhead, consumes valuable CPU time, and occasionally
pauses the entire program’s progress to track down garbage.

Go’s GC is highly optimized, tunable, and sufficient for a majority of
workloads. Most of the other parts of gVisor happily use Go's GC with no
complaints. However, under high network stress, Netstack needed to aggressively
allocate buffers used for processing TCP/IP data and metadata. These buffers
often had short lifespans, and once the processing was done they were left to be
cleaned up by the GC. This meant Netstack was producing tons of garbage that
needed to be tracked and freed by GC workers.

## Recycling to the Rescue

Luckily, we weren't the only ones with this problem. This pattern of small,
frequently allocated and discarded objects was common enough that the Go team
introduced [`sync.Pool`](https://pkg.go.dev/sync#Pool) in Go1.3. `sync.Pool` is
designed to relieve pressure off the Go GC by maintaining a thread-safe cache of
previously allocated objects. `sync.Pool` can retrieve an object from the cache
if it exists or allocate a new one according to a user specified allocation
function. Once the user is finished with an object they can safely return it to
the cache to be reused again.

While `sync.Pool` was exactly what we needed to reduce allocations,
incorporating it into Netstack wasn’t going to be as easy as just replacing all
our `make()`s with `pool.Get()`s.

## Netstack Challenges

Netstack uses a few different types of buffers under the hood. Some of these are
specific to protocols, like
[`segment`](https://github.com/google/gvisor/blob/master/pkg/tcpip/transport/tcp/segment.go)
for TCP, and others are more widely shared, like
[`PacketBuffer`](https://github.com/google/gvisor/blob/master/pkg/tcpip/stack/packet_buffer.go),
which is used for IP, ICMP, UDP, etc. Although each of these buffer types are
slightly different, they generally share a few common traits that made it
difficult to use `sync.Pool` out of the box:

*   The buffers were originally built with the assumption that a garbage
    collector would clean them up automatically – there was little (if any)
    effort put into tracking object lifetimes. This meant that we had no way to
    know when it was safe to return buffers to a pool.
*   Buffers have dynamic sizes that are determined during creation, usually
    depending on the size of the packet holding them. A `sync.Pool` out of the
    box can only accommodate buffers of a single size. One common solution to
    this is to fill a pool with
    [`bytes.Buffer`](https://pkg.go.dev/bytes#Buffer), but even a pooled
    `bytes.Buffer` could incur allocations if it were too small and had to be
    grown to the requested size.
*   Netstack splits, merges, and clones buffers at various points during
    processing (for example, breaking a large segment into smaller MTU-sized
    packets). Modifying a buffer’s size during runtime could mean lots of
    reallocating from the pool in a one-size-fits-all setup. This would limit
    the theoretical effectiveness of a pooled solution.

We needed an efficient, low-level buffer abstraction that had answers for the
Netstack specific challenges and could be shared by the various intermediate
buffer types. By sharing a common buffer abstraction, we could maximize the
benefits of pooling and avoid introducing additional allocations while minimally
changing any intermediate buffer processing logic.

## Introducing bufferv2

Our solution was
[bufferv2](https://github.com/google/gvisor/tree/master/pkg/bufferv2). Bufferv2
is a non-contiguous, reference counted, pooled, copy-on-write, buffer-like data
structure.

Internally, a bufferv2 `Buffer` is a linked list of `View`s. Each `View` has
start/end indices and holds a pointer to a `Chunk`. A `Chunk` is a
reference-counted structure that’s allocated from a pool and holds data in a
byte slice. There are several `Chunk` pools, each of which allocates chunks with
different sized byte slices. These sizes start at 64 and double until 64k.

![Figure 2](/assets/images/2022-10-24-buffer-pooling-figure2.png "bufferv2 implementation diagram."){:width="100%"}

The design of bufferv2 has a few key advantages over simpler object pooling:

*   **Zero-cost copies and copy-on-write**: Cloning a Buffer only increments the
    reference count of the underlying chunks instead of reallocating from the
    pool. Since buffers are much more frequently read than modified, this saves
    allocations. In the cases where a buffer is modified, only the chunk that’s
    changed has to be cloned, not the whole buffer.
*   **Fast buffer transformations**: Truncating and merging buffers or appending
    and prepending Views to Buffers are fast operations. Thanks to the
    non-contiguous memory structure these operations are usually as quick as
    adding a node to a linked list or changing the indices in a View.
*   **Tiered pools**: When growing a Buffer or appending data, the new chunks
    come from different pools of previously allocated chunks. Using multiple
    pools means we are flexible enough to efficiently accommodate packets of all
    sizes with minimal overhead. Unlike a one-size-fits-all solution, we don't
    have to waste lots of space with a chunk size that is too big or loop
    forever allocating small chunks.

## Trade-offs

Shifting Netstack to bufferv2 came with some costs. To start, rewriting all
buffers to use bufferv2 was a sizable effort that took many months to fully roll
out. Any place in Netstack that allocated or used a byte slice needed to be
rewritten. Reference counting had to be introduced so all the aforementioned
intermediate buffer types (`PacketBuffer`, `segment`, etc) could accurately
track buffer lifetimes, and tests had to be modified to ensure reference
counting correctness.

In addition to the upfront cost, the shift to bufferv2 also increased the
engineering complexity of future Netstack changes. Netstack contributors must
adhere to new rules to maintain memory safety and maximize the benefits of
pooling. These rules are strict – there needs to be strong justification to
break them. They are as follows:

*   Never allocate a byte slice; always use `NewView()` instead.
*   Use a `View` for simple data operations (e.g writing some data of a fixed
    size) and a `Buffer` for more complex I/O operations (e.g appending data of
    variable size, merging data, writing from an `io.Reader`).
*   If you need access to the contents of a `View` as a byte slice, use
    `View.AsSlice()`. If you need access to the contents of a `Buffer` as a byte
    slice, consider refactoring, as this will cause an allocation.
*   Never write or modify the slices returned by `View.AsSlice()`; they are
    still owned by the view.
*   Release bufferv2 objects as close to where they're created as possible. This
    is usually most easily done with defer.
*   Document function ownership of bufferv2 object parameters. If there is no
    documentation, it is assumed that the function does not take ownership of
    its parameters.
*   If a function takes ownership of its bufferv2 parameters, the bufferv2
    objects must be cloned before passing them as arguments.
*   All new Netstack tests must enable the leak checker and run a final leak
    check after the test is complete.

## Give it a Try

Bufferv2 is enabled by default as of
[gVisor 20221017](https://github.com/google/gvisor/releases/tag/release-20221017.0),
and will be rolling out to
[GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
soon, so no action is required to see a performance boost. Network-bound
workloads, such as web servers or databases like Redis, are the most likely to
see benefits. All the code implementing bufferv2 is public
[here](https://github.com/google/gvisor/tree/master/pkg/bufferv2), and
contributions are welcome! If you’d like to run the iperf benchmark for
yourself, you can run:

```
make run-benchmark BENCHMARKS_TARGETS=//test/benchmarks/network:iperf_test \
  RUNTIME=your-runtime-here BENCHMARKS_OPTIONS=-test.benchtime=60s
```

in the base gVisor directory. If you experience any issues, please feel free to
let us know at [gvisor.dev/issues](https://github.com/google/gvisor/issues).
