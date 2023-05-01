# Releasing Systrap - A high-performance gVisor platform

We are releasing a new gVisor platform: Systrap. Like the existing ptrace
platform, Systrap runs on most Linux machines out of the box without
virtualization. Unlike the ptrace platform, it’s fast 🚀. Go try it by adding
`--platform=systrap` to the runsc flags. If you want to know more about it, read
on.

--------------------------------------------------------------------------------

gVisor is a security boundary for arbitrary Linux processes. Boundaries do not
come for free, and gVisor imposes some performance overhead on sandboxed
applications. One of the most fundamental performance challenges with the
security model implemented by gVisor is system call interception, which is the
focus of this post.

To recap on the
[security model](https://gvisor.dev/docs/architecture_guide/security/#what-can-a-sandbox-do):
gVisor is an application kernel that implements the Linux ABI. This includes
system calls, signals, memory management, and more. For example, when a
sandboxed application calls
[`read(2)`](https://man7.org/linux/man-pages/man2/read.2.html), it actually
transparently calls into
[gVisor's implementation of this system call](https://github.com/google/gvisor/blob/44e2d0fcfeb641f3b8013c3f93cacdae447cc0f1/pkg/sentry/syscalls/linux/sys_read_write.go#L36)
This minimizes the attack surface of the host kernel, because sandboxed programs
simply can’t make system calls directly to the host in the first place[^1]. This
interception happens through an internal layer called the Platform interface,
which we have written about in a previous
[blog post](https://gvisor.dev/blog/2020/10/22/platform-portability/). To handle
these interceptions, this interface must also create new address spaces,
allocate memory, and create execution contexts to run the workload.

gVisor had two platform implementations: KVM and ptrace. The KVM platform uses
the kernel’s KVM functionality to allow the Sentry to act as both guest OS and
VMM (Virtual machine monitor). It does system call interception just like a
normal virtual machine would. This gives good performance when using bare-metal
virtualization, but has a noticeable impact with nested virtualization. The
other obvious downside is that it requires support for nested virtualization in
the first place, which is not supported by all hardware (such as ARM CPUs) or
within some Cloud environments.

The ptrace platform was the alternative wherever KVM was not available. It works
through the
[`PTRACE_SYSEMU`](http://man7.org/linux/man-pages/man2/ptrace.2.html) action,
which makes the user process hand back execution to the sentry whenever it
encounters a system call. This is a clean method to achieve system call
interception in any environment, virtualized or not, except that it’s quite
slow. To see how slow, an unrealistic but highly illustrative benchmark to use
is the
[`getpid` benchmark](https://github.com/google/gvisor/blob/108410638aa8480e82933870ba8279133f543d2b/test/perf/linux/getpid_benchmark.cc)[^2].
This benchmark runs the
[`getpid(2)`](https://man7.org/linux/man-pages/man2/getpid.2.html) system call
in a tight `while` loop. No useful application has this behavior, so it is not a
realistic benchmark, but it is well-suited to measure system call latency.

![Figure 1](/assets/images/2023-04-28-getpid-ptrace-vs-native.svg "Getpid benchmark: ptrace vs. native Linux."){:width="100%"}

All `getpid` runs have been performed on a GCE n2-standard-4 VM, with the
`debian-11-bullseye-v20230306` image.

While this benchmark is not applicable to most real-world workloads, just about
any workload will generally suffer from high overhead in system call
performance. Since running in a virtualized environment is the default state for
most cloud users these days, it's important that gVisor performs well in this
context. Systrap is the new platform targeting this important use case.

Systrap relies on multiple techniques to implement the Platform interface. Like
the ptrace platform, Systrap uses Linux's ptrace subsystem to initialize
workload executor threads, which are started as child processes of the main
gVisor sentry process. Systrap additionally sets a very restrictive seccomp
filter, installs a custom signal handler, and allocates chunks of memory shared
between user threads and runsc sentry. This shared memory is what serves as the
main form of communication between the sentry and sandboxed programs: whenever
the sandboxed process attempts to execute a system call, it triggers a `SIGSYS`
signal which is handled by our signal handler. The signal handler in turn
populates shared memory regions, and requests the sentry to handle the requested
system call. This alone proved to be faster than using `PTRACE_SYSEMU`, as
demonstrated by the `getpid` benchmark:

![Figure 2](/assets/images/2023-04-28-getpid-ptrace-vs-systrap-unoptimized.svg "Getpid benchmark: ptrace vs. Systrap."){:width="100%"}

Can we make it even faster? Recall what the main purpose of our signal handler
is: to send a request to the sentry via shared memory. To do that, the sandboxed
process must first incur the overhead of executing the seccomp filter[^3], and
then generating a full signal stack before being able to run the signal handler.
What if there was a way to simply have the sandboxed process jump to another
user-space function when it wanted to perform a system call? Well, turns out,
there is[^4] There is a popular x86 instruction pattern that’s used to perform
system calls, and it goes a little something like this: **`mov sysno, %eax;
syscall`**. The size of the mov instruction is 5 bytes and the size of the
syscall instruction is 2 bytes. Luckily this is just enough space to fit in a
**`jmp *%gs:offset`** instruction. When the signal handler sees this instruction
pattern, it signals to the sentry that the original instructions can be replaced
with a **`jmp`** to trampoline code that performs the same function as the
regular `SIGSYS` signal handler. The system call number is not lost, but rather
encoded in the offset. The results are even more impressive:

![Figure 3](/assets/images/2023-04-28-getpid-ptrace-vs-systrap-opt.svg "Getpid benchmark: ptrace vs. Optimized Systrap."){:width="100%"}

As mentioned, the `getpid` benchmark is not representative of real-world
performance. To get a better picture of the magnitude of improvement, here are
some real-world workloads:

*   The
    [Build ABSL benchmark](https://github.com/google/gvisor/blob/master/blob/master/test/benchmarks/fs/bazel_test.go)
    measures compilation performance by compiling
    [abseil.io](https://abseil.io/); this is a highly system call dependent
    workload due to needing to do a lot of I/O filesystem operations (gVisor’s
    file system overhead is also dependent upon file system isolation it
    implements, which is something you can learn about
    [here](https://gvisor.dev/docs/user_guide/filesystem/)).
*   The
    [ffmpeg benchmark](https://github.com/google/gvisor/blob/master/blob/master/test/benchmarks/media/ffmpeg_test.go)
    runs a multimedia processing tool, to perform video stream encoding/decoding
    for example; this workload does not require a significant amount of system
    calls and there are very few userspace to kernel mode switches.
*   The
    [Tensorflow benchmark](https://github.com/google/gvisor/blob/master/blob/master/test/benchmarks/ml/tensorflow_test.go)
    trains a variety of machine learning models on CPU; the system-call usage of
    this workload is in between compilation and ffmpeg, due to needing to
    retrieve training and validation data, but the majority of time is still
    spent just running userspace computations.
*   Finally, the Redis benchmark performs SET RPC calls with 5 concurrent
    clients, measures the latency that each call takes to execute, and reports
    the median (scaled by 250,000 to fit the graph's axis); this workload is
    heavily bounded by system call performance due to high network stack usage.

![Figure 4](/assets/images/2023-04-28-systrap-sample-workloads.svg "Comparison of sample workloads running on ptrace, Systrap, and native Linux."){:width="100%"}

Systrap will replace the ptrace platform by September 2023 and become the
default. Until then, we are working really hard to make it production-ready,
which includes working on additional performance and stability improvements, and
making sure we maintain a high bar for security through targeted fuzz-testing
for Systrap specifically.

In the meantime, we would like gVisor users to try it out, and give us feedback!
If you run gVisor using ptrace today (either by specifying `--platform ptrace`
or not specifying the `--platform` flag at all), or you use the KVM platform with
nested virtualization, switching to Systrap should be a drop-in performance
upgrade. All you have to do is specify `--platform systrap` to runsc. If you
encounter any issues, please let us know at
[gvisor.dev/issues](https://github.com/google/gvisor/issues).
<br>
<br>

--------------------------------------------------------------------------------

<!-- mdformat off(Footnotes need to be separated by linebreaks to be rendered) -->

[^1]: Even if the sandbox itself is compromised, it will still be bound by
    several defense-in-depth layers, including a restricted set of seccomp
    filters. You can find more details here:
    [https://gvisor.dev/blog/2020/09/18/containing-a-real-vulnerability/](https://gvisor.dev/blog/2020/09/18/containing-a-real-vulnerability/).

[^2]: Once the system call has been intercepted by gVisor (or in the case of
    Linux, once the process has entered kernel-mode), actually executing the
    getpid system call itself is very fast, so this benchmark effectively
    measures single-thread syscall-interception overhead.

[^3]: Seccomp filters are known to have a “not insubstantial” overhead:
    [https://lwn.net/Articles/656307/](https://lwn.net/Articles/656307/).

[^4]: On the x86_64 architecture, ARM does not have this optimization as of the
    time of writing.

<!-- mdformat on -->
