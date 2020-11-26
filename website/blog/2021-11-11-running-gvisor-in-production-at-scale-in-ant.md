# Running gVisor in Production at Scale in Ant

>This post was contributed by [Ant Group](https://www.antgroup.com/), a
>large-scale digital payment platform. Jianfeng and Yong are engineers at Ant
>Group working on infrastructure systems, and contributors to gVisor.

At Ant Group, we are committed to keep online transactions safe and efficient.
Continuously improving security for potential system-level attacks is one of
many measures. As a container runtime, gVisor provides container-native security
without sacrificing resource efficiency. Therefore, it has been on our radar
since it was released.

However, there have been performance concerns raised by members of
[academia](https://www.usenix.org/system/files/hotcloud19-paper-young.pdf)
and [industry](https://news.ycombinator.com/item?id=19924036). Users of gVisor
tend to bear the extra overhead as the tax of security. But we tend to agree
that [security is no excuse for poor performance (See Chapter 6!)](https://sel4.systems/About/seL4-whitepaper.pdf).

In this article, we will present how we identified bottlenecks in gVisor and
unblocked large-scale production adoption. Our main focus are the CPU
utilization and latency overhead it brings. Small memory footprint is also a
valued goal, but not discussed in this blog. As a result of these efforts and
community improvements, 70% of our applications running on runsc have <1%
overhead; another 25% have <3% overhead. Some of our most valued application
are the focus of our optimization, and get even better performance compared with
runc.

The rest of this blog is organized as follows:
- First, we analyze the cost of different syscall paths in gVisor.
- Then, a way to profile a whole picture of a instance is proposed to find out
  if some slow syscall paths are encountered.
- Some invisible overhead in Go runtime is discussed.
- At last, a short summary on performance optimization with some other factors
  on production adoption.

For convenience of discussion, we are targeting KVM-based, or hypervisor-based
platforms, unless explicitly stated.

## Cost of different syscall paths

[Defense-in-depth](../../../../2019/11/18/gvisor-security-basics-part-1/#defense-in-depth)
is the key design principle of gVisor. In gVisor, different syscalls have
different paths, further leading to different cost (orders of magnitude) on
latency and CPU consumption. Here are the syscall paths in gVisor.

![Figure 1](/assets/images/2021-11-11-syscall-figure1.png "Sentry syscall paths.")

### Path 1: User-space vDSO

Sentry provides a [vDSO library](https://github.com/google/gvisor/tree/master/vdso)
for its sandboxed processes. Several syscalls are short circuited and
implemented in user space. These syscalls cost almost as much as native Linux.
But note that the vDSO library is partially implemented. We once noticed some
[syscalls](https://github.com/google/gvisor/issues/3101) in our environment are
not properly terminated in user space. We create some additional implementations
to the vDSO, and aim to push these improvements upstream when possible.

### Path 2: Sentry contained

Most syscalls, e.g., <code>clone(2)</code>, are implemented in Sentry. They are
some basic abstractions of a operating system, such as process/thread lifecycle,
scheduling, IPC, memory management, etc. These syscalls and all below suffer
from a structural cost of syscall interception. The overhead is about 800ns
while that of the native syscalls is about 70ns. We'll dig it further below.
Syscalls of this kind spend takes about several microseconds, which is
competitive to the corresponding native Linux syscalls.

### Path 3: Host-kernel involved

Some syscalls, resource related, e.g., read/write, are redirected into the host
kernel. Note that gVisor never passes through application syscalls directly into
host kernel for functional and security reasons. So comparing to native Linux,
time spent in Sentry seems an extra overhead. Another overhead is the way
to call a host kernel syscall. Let's use kvm platform of x86_64 as an example.
After Sentry issues the syscall instruction, if it is in GR0, it first goes
to the syscall entrypoint defined in LSTAR, and then halts to HR3 (a vmexit
happens here), and exits from a signal handler, and executes syscall instruction
again. We can save the "Halt to HR3" by introducing vmcall here, but there's
still a syscall trampoline there and the vmexit/vmentry overhead is not trivial.
Nevertheless, these overhead is not that significant.

For some sentry-contained syscalls in Path 2, although the syscall semantic is
terminated in Sentry, it may further introduces one or many unexpected exits to
host kernel. It could be a page fault when Sentry runs, and more likely, a
schedule event in Go runtime, e.g., M idle/wakeup. An example in hand is that
<code>futex(FUETX_WAIT)</code> and <code>epoll_wait(2)</code> could lead to M
idle and a further futex call into host kernel if it does not find any runnable
Gs. (See the comments in https://go.dev/src/runtime/proc.go for further
explanation about the GMP scheduler).

### Path 4: Gofer involved

Other IO-related syscalls, especially security sensitive, go through another
layer of protection - Gofer. For such a syscall, it usually involves one or
more Sentry/Gofer inter-process communications. Even with the recent
optimization that using lisafs to supersede P9, it's still the slowest path
which we shall try best to avoid.

As shown above, some syscall paths are by-design slow, and should be identified
and reduced as much as possible. Let's hold it to the next section, and dig
into the details of the structural and implementation-specific cost of syscalls
firstly, because the performance of some Sentry-contained syscalls are not good
enough.

### The structural cost

The first kind of cost is the comparatively stable, introduced by syscall
interception. It is platform-specific depending on the way to intercept syscalls.
And whether this cost matters also depends on the syscall rate of sandboxed
applications.

Here's the benchmark result on the structural cost of syscall. We got the data
on a Intel(R) Xeon(R) CPU E5-2650 v2 platform, using
[getpid benchmark](https://github.com/google/gvisor/blob/master/test/perf/linux/getpid_benchmark.cc).
As we can see, for KVM platform, the syscall interception costs more than 10x
than a native Linux syscall.

|            |getpid benchmark (ns)|
|------------|---------------------|
|Native      |62                   |
|Native-KPTI |236                  |
|runsc-KVM   |830                  |
|runsc-ptrace|6249                 |

* "Native" stands for using vanilla linux kernel.

To understand the structural cost of syscall interception,
we did a [quantitative analysis](https://github.com/google/gvisor/issues/2354)
on kvm platform. According to the analysis, the overhead mainly comes from:

1. KPTI-like CR3 switches: to maintain the address equation of Sentry running
in HR3 and GR0, it has to switch CR3 register twice, on each user/kernel switch;

2. Platform's Switch(): Linux is very efficient by just switching to a
per-thread kernel stack and calling the corresponding syscall entry function.
But in Sentry, each task is represented by a goroutine; before calling into
syscall entry functions, it needs to pop the stack to recover the big while
loop, i.e., kernel.(*Task).run.

Can we save the structural cost of syscall interception? This cost is actually
by-design. We can optimize it, for example, avoid allocation and map operations
in switch process, but it can not be eliminated.

Does the structural cost of syscall interception really matter? It depends on
the syscall rate. Most applications in our case have a syscall rate < 200K/sec,
and according to flame graphs (which will be described later in this blog), we
see 2~3% of samples are in the switch Secondly, most syscalls, except those
as simple as <code>getpid(2)</code>, take several microseconds. In proportion,
it's not a significant overhead. However, if you have an elephant RPC (which
involves many times of DB access), or a service served by a long-snake RPC
chain, this brings nontrivial overhead on latency.

### The implementation-specific cost

The other kind of cost is implementation-specific. For example, it involves
some heavy malloc operations; or defer is used in some frequent syscall paths
(defer is optimized in Go 1.14); what's worse, the application process may
trigger a long-path syscall with host kernel or Gofer involved.

When we try to do optimization on the gVisor runtime, we need information
on the sandboxed applications, POD configurations, and runsc internals. But
most people only play either as platform engineer or application engineer.
So we need an easier way to understand the whole picture.

## Performance profile of a running instance

To quickly understand the whole picture of performance, we need some ways to
profile a running gVisor instance. As gVisor sandbox process is essentially a
Go process, Go pprof is an existing way:

*  [Go pprof](https://golang.org/pkg/runtime/pprof/) - provides CPU and heap
   profile through [runsc debug subcommands](https://gvisor.dev/docs/user_guide/debugging/#profiling).
*  [Go trace](https://golang.org/pkg/runtime/trace/) - provides more
   internal profile types like synchronization blocking and scheduler latency.

Unfortunately, above tools only provide hot-spots in Sentry, instead of the
whole picture (how much time spent in GR3 and HR0). And CPU profile relies on
the [SIGPROF signal](https://golang.org/pkg/runtime/pprof/), which may not
accurate enough.

[perf-kvm](https://www.linux-kvm.org/page/Perf_events) cannot provide what we
need either. It may help to top/record/stat some information in guest with the
help of option [--guestkallsyms], but it cannot analyze the call chain (which
is not supported in the host kernel, see Linux's perf_callchain_kernel).

### Perf sandbox process like a normal process

Then we turn to a nice virtual address equation in Sentry: [(GR0 VA) = (HR3 VA)].
This is to make sure any pointers in HR3 can be directly used in GR0.

The equation is helpful to solve this problem in the way that we can profile
Sentry just as a normal HR3 process with a little hack on kvm.

- First, as said above, Linux does not support to analyze the call chain of
guest. So Change [is_in_guest] to pretend that it runs in host mode even it's
in guest mode. This can be done in
[kvm_is_in_guest](https://github.com/torvalds/linux/blob/v4.19/arch/x86/kvm/x86.c#L6560)

```
int kvm_is_in_guest(void)
 {
-       return __this_cpu_read(current_vcpu) != NULL;
+       return 0;
 }
```

- Secondly, change the process of guest profile. Previously, after PMU counter
overflows and triggers a NMI interrupt, vCPU is forced to exit to host, and
calls [int $2] immediately for later recording. Now instead of calling [int $2],
we shall call **do_nmi** directly with correct registers (i.e., pt_regs):

```
+void (*fn_do_nmi)(struct pt_regs *, long);
+
+#define HIGHER_HALF_CANONICAL_ADDR 0xFFFF800000000000
+
+void make_pt_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
+{
+       /* In Sentry GR0, we will use address among
+        *   [HIGHER_HALF_CANONICAL_ADDR, 2^64-1)
+        * when syscall just happens. To avoid conflicting with HR0,
+        * we correct these addresses into HR3 addresses.
+        */
+       regs->bp = vcpu->arch.regs[VCPU_REGS_RBP] & ~HIGHER_HALF_CANONICAL_ADDR;
+       regs->ip = vmcs_readl(GUEST_RIP) & ~HIGHER_HALF_CANONICAL_ADDR;
+       regs->sp = vmcs_readl(GUEST_RSP) & ~HIGHER_HALF_CANONICAL_ADDR;
+
+       regs->flags = (vmcs_readl(GUEST_RFLAGS) & 0xFF) |
+                     X86_EFLAGS_IF | 0x2;
+       regs->cs = __USER_CS;
+       regs->ss = __USER_DS;
+}
+
 static void vmx_complete_atomic_exit(struct vcpu_vmx *vmx)
 {
        u32 exit_intr_info;
@@ -8943,7 +8965,14 @@ static void vmx_complete_atomic_exit(struct vcpu_vmx *vmx)
        /* We need to handle NMIs before interrupts are enabled */
        if (is_nmi(exit_intr_info)) {
                kvm_before_handle_nmi(&vmx->vcpu);
-               asm("int $2");
+               if (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF)
+                       asm("int $2");
+               else {
+                       struct pt_regs regs;
+                       memset((void *)&regs, 0, sizeof(regs));
+                       make_pt_regs(&vmx->vcpu, &regs);
+                       fn_do_nmi(&regs, 0);
+               }
                kvm_after_handle_nmi(&vmx->vcpu);
        }
 }
@@ -11881,6 +11927,10 @@ static int __init vmx_init(void)
                }
        }

+       fn_do_nmi = (void *) kallsyms_lookup_name("do_nmi");
+       if (!fn_do_nmi)
+               printk(KERN_ERR "kvm: lookup do_nmi fail\n");
+
```

As shown above, we properly handle samples in GR3 and GR0 trampoline.

### An example of profile

Firstly, make sure we compile the runsc with symbols not stripped:
```
bazel build runsc --strip=never
```

As an example, run below script inside the gVisor container to make it busy:
```
stress -i 1 -c 1 -m 1
```

Perf the instance with command:
```
perf kvm --host --guest record -a -g -e cycles -G <path/to/cgroup> -- sleep 10 >/dev/null
```

Note we still need to perf the instance with 'perf kvm' and '--guest', because
kvm-intel requires this to keep the PMU hardware event enabled in guest mode.

Then generate a flame graph using
[Brendan's tool](https://github.com/brendangregg/FlameGraph), and we got this
[flame graph](https://raw.githubusercontent.com/zhuangel/gvisor/zhuangel_blog/website/blog/blog-kvm-stress.svg).

Let's roughly divide it to differentiate GR3 and GR0 like this:

![Figure 2](/assets/images/2021-11-11-flamegraph-figure2.png "Flamegraph of stress.")

### Optimize based on flame graphs

Now we can get clear information like:

1. The bottleneck syscall(s): the above flame graph shows
<code>sync(2)</code> is a relatively large block of samples. If we cannot avoid
them in user space, they are worth time for optimization. Some real cases we
found and optimized are: supersede CopyIn/CopyOut with CopyInBytes/CopyOutBytes
to avoid reflection; avoid use defer in some frequent syscalls in which case you
can say <code>deferreturn()</code> in the flame graph (not needed if you already
upgrade to newer Go version). Another optimization is: after we find that append
write of shared volume spends a lot of time querying gofer for current file
length in the flame graph, we propose to add
[an handle only for append write](https://github.com/google/gvisor/issues/1792).

2. If GC is a real problem: we can barely see sample related to GC in this
case. But if we do, we can further search <code>mallocgc()</code> to see where
the heap allocation is frequent. We can perform a heap profile to see allocated
objects. And we can consider adjust [GC percent](https://golang.org/pkg/runtime/debug/#SetGCPercent),
100% by default, to sacrifice memory for less CPU utilization. We once found
that allocating a object > 32 KB also triggers GC, referring to
[this](https://github.com/google/gvisor/commit/f697d1a33e4e7cefb4164ec977c38ccc2a228099).

3. Percentage of time spent in GR3 app and Sentry: We can determine if it worths
to continue the optimization. If most of the samples are in GR3, then we better
turn to optimizing the application code instead.

4. Rather large chunk of samples lie in ept violation and
<code>fallocate(2)</code> (into HR0). This is caused by frequent memory
allocation and free. We can either optimize the application to avoid this, or
add a memory buffer layer in memfile management to relieve it.

As a short summary, now we have a tool to get a visible graph of what's going
on in a running gVisor instance. Unfortunately, we cannot get the details of
the application processes in the above flame graph because of the semantic gap.
To get a flame graph of the application processes, we have prototyped a way in
Sentry. Hopefully, we'll discuss it in later blogs.

A visible way is very helpful when we try to optimize a new application on
gVisor. However, there's another kind of overhead, invisible like "Dark matter".

## Invisible overhead in Go runtime

Sentry inherits timer, scheduler, channel, and heap allocator in Go runtime.
While it saves a lot of code to build a kernel, it also introduces some
unpleasant overhead. The Go runtime, after all, is designed and massively used
for general purpose Go applications. While it's used as a part or the basis of a
kernel, we shall be very careful with the implementation and overhead of these
syntactic sugar.

Unfortunately, we did not find an universal method to identify this kind of
overhead. The only way seems to get your hands dirty with Go runtime. We'll show
some examples in our use case.

### Timer

It's known that Go (before 1.14) timer suffers from
[lock contention and context switches](https://github.com/golang/go/issues/27707).
What's worse, statistics of Sentry syscalls shows that a lot of
<code>futex()</code> is introduced by timers (64 timer buckets), and that Sentry
syscalls walks a much longer path (redpill), makes it worse.

We have two optimizations here: 1. decrease the number of timer buckets, from 64
to 4; 2. decrease the timer precision from ns to ms. You may worry about the
decrease of timer precision, but as we see, most of the applications are
event-based, and not affected by a coarse grained timer.

However, Go changes the implementation of timer in v1.14; how to port this
optimization remains an open question.

### Scheduler

gVisor introduces an extra level of schedule along with the host linux
scheduler (usually CFS). A L2 scheduler sometimes brings positive impact as it
saves the heavy context switch in the L1 scheduler. We can find many two-level
scheduler cases, for example, coroutines, virtual machines, etc.

gVisor reuses Go's work-stealing scheduler, which is originally designed for
coroutines, as the L2 scheduler. They share the same goal:

"We need to balance between keeping enough running worker threads to utilize
available hardware parallelism and parking excessive running worker threads
to conserve CPU resources and power." -- From
[Go scheduler code](https://golang.org/src/runtime/proc.go).

If not properly tuned, the L2 scheduler may leak the schedule pressure to the
L1 scheduler. According to G-P-M model of Go, the parallelism is close related to
the GOMAXPROCS limit. The upstream gVisor by default uses # of host cores,
which leads to a lot of wasted M wake/stop(s). By properly configuring the
GOMAXPROCS of a POD of 4/8/16 cores, we find it can save some CPU cycles
without worsening the workload latency.

To further restrict extra M wake/stop(s), before wakep(), we calculate the # of
running Gs and # of running Ps to decide if necessary to wake a M. And we find
it's better to firstly steal from the longest local run queue, comparing to
previously random-sequential way. Another related optimization is that we find
most applications will get back to Sentry very soon, and it's not necessary to
handle off its P when it leaves into user space and find an idle P when it gets
back.

Some optimizations in Go are put [here](https://github.com/zhuangel/go/tree/go1.13.4.blog).
What we learned from the optimization process of gVisor is that digging into
Go runtime to understand what's going on there. And it's normal that some ideas
work, but some fail.

## Summary

We introduced how we profiled gVisor for production-ready performance. Using
this methodology, along with some other aggressive measures, we finally got to
run gVisor with an acceptable overhead, and even better than runc in some
workloads.  We also absorbed a lot of optimization progress in the community,
e.g., VFS2.

So far, we have deployed more than 100K gVisor instances in the production
environment. And it very well supported transactions of
[Singles Day Global Shopping Festivals](https://en.wikipedia.org/wiki/Singles%27_Day).

Along with performance, there are also some other important aspects for
production adoption. For example, generating a core after a sentry panic is
helpful for debugging; a coverage tool is necessary to make sure new changes are
properly covered by test cases. We'll leave these topics to later discussions.
