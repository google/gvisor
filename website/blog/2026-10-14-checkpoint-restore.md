# Blink and it's back: how gVisor checkpoint/restore got 60x faster

<!-- disableFinding(FIGURE_NO_CAPTION) -->

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/cover.svg" alt="A running gVisor sandbox is saved with runsc checkpoint to snapshot files (checkpoint.img, pages_meta.img, pages.img and fs/), on local disk or in a GCS bucket, and restored with runsc restore into the same sandbox anywhere, any time later.">
</figure>

`runsc checkpoint` saves the full state of a gVisor sandbox to files: every
process, every open file, every socket, and every byte of memory.
`runsc restore` brings it back, on the same machine or on a different one, and
the applications continue as if nothing happened.

This feature is not new. gVisor could checkpoint a sandbox in 2018. But the
2018 version was slow, and some people still think of gVisor checkpoint/restore
that way. A lot changed in the last few years. In our tests below, restoring a
2 GiB sandbox went from **8.8 seconds to 0.15 seconds** on the same machine:
about 60 times faster.

This post tells the story of how we got there, one step at a time.

<!--/excerpt-->

## Why checkpoint a container at all?

Many workloads spend a long time getting ready before they do useful work:

-   An **LLM server** loads tens of gigabytes of model weights and warms up its
    caches.
-   A **Python or JVM app** imports libraries and JIT-compiles hot code.
-   An **AI agent sandbox** installs tools, clones a repository, and builds it.
-   A **reinforcement-learning environment** needs thousands of identical,
    fresh copies of the same start state (Tencent wrote about running
    [millions of these sandboxes with gVisor](/blog/2026/04/23/scaling-agentic-rl-sandboxes-to-the-millions-with-gvisor-at-tencent/)).

With checkpoint/restore, you do the warm-up one time, save it, and then restore
the warm sandbox as many times as you want. The restore is only useful if it is
fast. If a restore takes longer than a cold start, nobody will use it.

## Why gVisor is good at this

In a normal container, the state of your application lives in the host Linux
kernel. That state is spread across thousands of kernel data structures, and
the host kernel cannot easily write all of it to a file.

gVisor is different. Its kernel, the **Sentry**, is a normal Go program that
runs in user space. All the kernel state of the sandbox (tasks, file
descriptors, sockets, timers, memory mappings) are Go objects inside one
process. To save a sandbox, gVisor does these steps:

1.  Stop all application threads.
2.  Walk the graph of kernel objects and write it to a file.
3.  Write the application memory to a file.

To restore, gVisor reads the files, builds the objects again, and starts the
threads. Because the Sentry owns all of this state, the restore does not need
any special support from the host kernel.

So the hard part was never "can we save it?". The hard part was "can we
restore it fast?". Here is how that went.

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/timeline.svg" alt="Timeline of checkpoint/restore milestones: 2018 first version, one compressed file; 2023 compression optional, community patch; 2024 split snapshot, parallel load, O_DIRECT; 2024 multi-container and zero pages; 2024 background page loading; 2025 earlier loads and a 12x faster decoder; 2026 GCS gofer and filesystem snapshots; 2026 GPU, TPU and integrity checks.">
</figure>

## 2018: One big compressed file

The first version of `runsc checkpoint`
([2018](https://github.com/google/gvisor/commit/0c34b460f2)) wrote everything
into one file, `checkpoint.img`. Kernel objects and application memory were
mixed together in one stream, and the whole stream was compressed with flate
(DEFLATE, the same algorithm that zip and gzip use).

The file is small. But a restore must:

-   Read the file from the start to the end, in order.
-   Decompress every byte on the CPU.
-   Build the kernel and fill the memory one after the other.

Nothing can happen in parallel, and nothing can be skipped. The application
starts only after the last byte is done.

## 2023: Optional compression

Compression sounds like a good idea: a smaller file is faster to read, right?
In practice, the answer was often "no":

-   Application memory, such as model weights or encrypted data, does not
    compress well.
-   Decompression uses a lot of CPU time on the restore critical path.
-   The decompression buffers stay in memory long after the restore. One
    production user measured up to **2x memory overhead** and **hundreds of
    milliseconds** of extra startup time.

That user, Ivan Prisyazhnyy, sent a
[community patch](https://github.com/google/gvisor/pull/9146) that made
compression optional with `--compression=none`. It was a small change, but it
opened the door to every step below. An uncompressed file has a very useful
property: you can read any part of it, at any time, in any order.

We measured the trade-off on today's gVisor, with 2 GiB of app memory:

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/compression.svg" alt="Two bar charts. Snapshot size: random data is 2,049 MiB compressed and 2,052 MiB uncompressed; text-like data is 1,033 MiB compressed and 2,056 MiB uncompressed. Sandbox memory after restore: 318 MiB (random) and 285 MiB (text-like) with compression, and 11 MiB without.">
</figure>

-   **Random data, such as model weights, does not get smaller.** You pay for
    compression and get nothing back.
-   **Text-like data gets about 2x smaller.** That is real, if disk space is
    your main problem.
-   **Either way, the sandbox keeps about 300 MiB of extra memory** after the
    restore, against 11 MiB without compression. The save also takes 2 to 4
    times longer.

Compression is still available (`--compression=flate-best-speed`) for the
cases where disk space matters most. But it turns off the steps below, and
those steps are where the big wins are.

## 2024: Split the snapshot

Next, we split the single file by job
([pages file](https://github.com/google/gvisor/commit/5e9207a966),
[metadata file](https://github.com/google/gvisor/commit/a3ae7f25a0)):

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/snapshot-anatomy.svg" alt="Left: the 2018 format, one compressed file with kernel objects and app memory mixed. Right: today's format with checkpoint.img for kernel objects (211 KB), pages_meta.img for the memory map (1.9 KB), pages.img for raw app memory (70.7 MB), and an optional fs directory for the filesystem.">
</figure>

-   `checkpoint.img` has the kernel objects. It is small, usually kilobytes to
    a few megabytes.
-   `pages_meta.img` tells gVisor where each page of memory goes.
-   `pages.img` has the raw application memory. It is big, and it is
    uncompressed, so gVisor can read any range of it directly into place.

This split made three new things possible:

**Parallel load.** Loading the kernel needs CPU time. Loading memory needs disk
bandwidth. The two do not depend on each other. Now gVisor
[does them at the same time](https://github.com/google/gvisor/commit/39730b714c),
so the restore takes `max(kernel, memory)` instead of `kernel + memory`. The
save side [does the same](https://github.com/google/gvisor/commit/218f52a9f5).

**Direct I/O.** With `--direct`, gVisor reads and writes `pages.img` with
`O_DIRECT`
([restore](https://github.com/google/gvisor/commit/f895b63b04),
[checkpoint](https://github.com/google/gvisor/commit/032b103ec7)). The data
skips the host page cache. If you restore an image one time and then delete it,
this stops a second copy of your memory from sitting in the host page cache.

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/direct-io.svg" alt="Bar chart of extra host page cache for a 2 GiB snapshot. After checkpoint: 2,053 MiB by default, 2 MiB with --direct. After restore: 2,115 MiB by default, 63 MiB with --direct, with the same restore time of 7.9 seconds.">
</figure>

Without `--direct`, a 2 GiB snapshot leaves about 2 GiB of extra data in host
memory, after both the save and the restore. With `--direct`, almost nothing
stays, and the restore is just as fast. One thing to know: without `--direct`,
`runsc checkpoint` returns as soon as the data is in host memory (1.3 seconds
in our test), and the host writes it to disk later. With `--direct`, the
command returns only when the data is on the disk (7.3 seconds on our slow
disk).

**Many readers, but not too many.** Memory is read by a pool of parallel
readers. In 2026 we
[tuned this pool](https://github.com/google/gvisor/commit/b23d3c7541), and
found that more readers is not always better. With 128 readers on a 64-CPU
machine, 77% of the CPU time went to lock contention in the host kernel. With
12 readers, warm restores became **31% to 49% faster** for Go, Python and Java
apps, and used **56% to 91% less CPU**.

## 2024: Multi-container and zero pages

Real sandboxes often have more than one container, such as a Kubernetes pod
with an app and a sidecar.
[Multi-container restore](https://github.com/google/gvisor/commit/3d32050710)
saves the whole pod in one checkpoint. You then restore each container by name,
and gVisor connects the container IDs and host files again.

The same year, gVisor also became smarter about **zero pages**. Many apps,
especially ML apps, allocate big buffers and fill only part of them. A page of
zeros does not need to be saved: on restore, it can come back as fresh, empty
memory.

gVisor always skips the zero pages that it can find cheaply: pages that it has
not yet counted as "in use". But as soon as something asks the sandbox for its
memory statistics, gVisor counts every page the app touched, including the
zero ones. Reading `/proc/meminfo` does this, and so does the container runtime
when it collects memory metrics. After that, a normal save treats those zero
pages as data.

`--exclude-committed-zero-pages`
([commit](https://github.com/google/gvisor/commit/e882488ed7)) tells gVisor
to also check these pages at save time, and to leave out the ones that are all
zeros. Our test app had 512 MiB of data and 2 GiB of zeros:

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/zero-pages.svg" alt="Bar chart of snapshot size for an app with 512 MiB of data and 2 GiB of zeros. Not monitored, default: 516 MiB. Monitored, default: 2,564 MiB, save 2.1 s, restore 9.7 s, sandbox 2,600 MiB. Monitored, with --exclude-committed-zero-pages: 516 MiB, save 0.6 s, restore 2.4 s, sandbox 552 MiB.">
</figure>

For a monitored container, the flag made the snapshot **5 times smaller**. The
save was faster too, because there was less to write. The restore was 4 times
faster, and the restored sandbox used **2 GiB less host memory**, because the
zero pages come back as empty memory that uses no space.

## 2024: Background page loading

This is the big one.

Until now, the app started only after **all** memory was loaded. But an app
does not need all its memory at once. It needs the next instruction, the next
few pages of heap, and the stack. Most of the other pages can wait.

With `runsc restore --background`
([commit](https://github.com/google/gvisor/commit/41f01d8f9c)), gVisor starts
the app as soon as the kernel objects are loaded. Memory keeps loading in the
background, while the app runs:

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/restore-phases.svg" alt="Three restore timelines. 2018: one serial stream; the app starts at the end. 2024: kernel and memory load in parallel; the app starts when the slower one is done. With --background: the app starts when the kernel is done, and memory loads behind it. Pages the app touches are loaded first.">
</figure>

What happens if the app touches a page that is not loaded yet? gVisor moves
that page to the front of the queue, loads it at high priority, and lets the
thread continue. The app waits only for the pages that it really uses, not for
the full image.

## 2025: Early loading and a faster decoder

The faster the kernel loads, the sooner `--background` can start the app. So
we went looking for slow parts:

-   **Start reading memory earlier.** gVisor now
    [starts reading pages](https://github.com/google/gvisor/commit/7fb3b706c0)
    as soon as the sandbox starts to restore, and later
    [even earlier](https://github.com/google/gvisor/commit/94b30bda9e), before
    it reads the kernel state.
-   **A faster decoder.** A checkpoint of an SGLang server that ran
    `gemma-3-27b` had 368,245 kernel objects. The decoder rescanned a long list
    of pending objects 238,102 times to find the next one to finish. One
    [small data-structure change](https://github.com/google/gvisor/commit/aa52ddf3a1)
    (keep a separate list of the objects that are ready) cut the kernel load
    time from **2 minutes 30 seconds to 12 seconds**.

## 2026: GCS and filesystem snapshots

Two features made checkpoints easier to move around:

**Restore straight from Google Cloud Storage.** If the `--image-path`
directory has a `gcs_opts.json` file, gVisor
[reads and writes the checkpoint in a GCS bucket](https://github.com/google/gvisor/commit/7ea8dc5e5f).
A separate helper process, the checkpoint gofer, talks to GCS and reads the
data directly into the sandbox memory. The image does not need to be copied to
the local disk first. The helper is a separate binary, so the HTTP and cloud
code stays out of `runsc` and out of the sandbox.

**Filesystem snapshots.** A container is more than memory: it also has files
that it wrote. gVisor can save its in-memory root filesystem overlay and tmpfs
mounts as part of the checkpoint. With
[`runsc fscheckpoint`](https://github.com/google/gvisor/commit/9ca1678bc6) and
`--fs-checkpoint-paths`, you can also save **only** the filesystem, and restore
it into a brand new container with `runsc create --fs-restore-image-path`.

And in 2026 `--compression=none` became
[the default](https://github.com/google/gvisor/commit/79b7318d6d), so every
user gets the 2024 and 2025 improvements without extra flags.

## 2026: GPUs, TPUs, and more

Some newer additions:

-   **GPUs.** `--cuda-checkpoint-path` runs NVIDIA's `cuda-checkpoint` tool
    inside the sandbox, so gVisor can save CUDA apps too.
-   **TPUs.** Checkpoint/restore works with TPU devices through TPUproxy.
-   **The app can save itself.** When enabled with annotations, an app can ask
    for its own checkpoint by writing to `/proc/gvisor/checkpoint`, for example
    right after it finishes its warm-up.
-   **Integrity checks.** If a checkpoint has a hash key, gVisor verifies each
    chunk of up to 1 MiB before it uses the data, and
    [fails closed](https://github.com/google/gvisor/commit/28878b9b20) if the
    data does not match.
-   **More devices.** Sandboxes with
    [host networking](https://github.com/google/gvisor/commit/9d2d13b051) (apps
    reconnect after restore) and TUN devices can be saved and restored too.

## The results

How much does all of this matter? We measured it. We ran a Python app with
2 GiB of random (incompressible) memory, like model weights, then we
checkpointed it, deleted it, and restored it. We measured the time until the
app runs again.

All runs use the same machine and the same `runsc` binary. We only change the
flags, to turn each step on.

<figure class="img-100pct">
<img src="/assets/images/2026-10-14-checkpoint-restore/restore-staircase.svg" alt="Bar chart of the time until a 2 GiB app runs again after restore: 2018 style compressed single file 8.82 s; 2024 uncompressed split parallel 7.89 s; 2024+ with restore --background 1.71 s; 2024+ with the image already in page cache 0.15 s.">
</figure>

A few things to note:

-   **Split files are about as fast as the disk.** 7.9 seconds is about the
    time this disk (about 290 MB/s) needs to read 2 GiB. The compressed format
    was slower than the disk, because the CPU also had to decompress all of
    it. On a faster disk, that CPU cost becomes the biggest part.
-   **`--background` removes the disk from the critical path.** The app runs
    again in 1.7 seconds, even though the disk is just as slow. Memory keeps
    loading behind it. That is 5 times faster on the same slow disk.
-   **Fast storage makes it even faster.** When the image is already in the
    host page cache (for example, right after a checkpoint, or on very fast
    local storage), the app runs again in **0.15 seconds**.

The save side also improved: the same 2 GiB checkpoint took 5.1 seconds with
compression and about 1.3 seconds without.

One caveat: `--background` cannot make the disk faster. In our test, an
app that reads all 2 GiB of its memory right after the restore still has to
wait for the disk to deliver it. But most apps need only a part of their memory
to start serving, and those apps get a large benefit.

Speed is not the only thing that improved. Some steps save memory or disk space
instead. Here is a summary of what we measured, with 2 GiB of app memory:

| Optimization              | What it saves                   | Without   | With    |
| ------------------------- | ------------------------------- | --------- | ------- |
| No compression            | sandbox memory after restore    | 318 MiB   | 11 MiB  |
| `--direct`                | host page cache after restore   | 2,115 MiB | 63 MiB  |
| Zero pages, monitored app | snapshot size                   | 2,564 MiB | 516 MiB |
| Zero pages, monitored app | host memory of restored sandbox | 2,600 MiB | 552 MiB |

**Test setup:**

-   16 vCPU Google Cloud VM, Linux 6.17, disk at about 290 MB/s.
-   gVisor at commit `142ce817f8` (October 2026), systrap platform.
-   A Python app with 2 GiB of random data in memory.
-   Median of 3 runs, with a cold host page cache unless noted.

## Try it

```bash
# Save a running sandbox (and keep it running).
runsc checkpoint --image-path=/snapshots/warm --leave-running my-container

# Restore it, and let memory load in the background.
runsc restore --image-path=/snapshots/warm --background --detach \
  --bundle=/path/to/bundle my-new-container

# Optional: wait until all memory is loaded (for example, before you delete
# the image).
runsc wait --restore my-new-container
```

Some tips:

-   Use the defaults: they are uncompressed and split, which is what you want.
-   Add `--background` to `runsc restore` for large apps.
-   Add `--direct` if you restore an image only one time and do not want it in
    the host page cache.
-   Add `--exclude-committed-zero-pages` if your app (for example an LLM
    server) keeps large buffers that are mostly zeros, and something reads its
    memory statistics (most container platforms do).

The [checkpoint/restore guide](/docs/user_guide/checkpoint_restore/) has all
the details, including Docker, networking, GPUs, and app-driven checkpoints.

## What's next

We are not done. Some ideas we are looking at:

-   **Smaller downtime during save**, so a running app pauses for a shorter
    time when you checkpoint it with `--leave-running`.
-   **Incremental checkpoints**, which save only the memory that changed since
    the last checkpoint.
-   **Sharing memory between restored copies**, so 100 sandboxes restored from
    the same image do not need 100 copies of the same pages.

If gVisor checkpoint/restore was "the slow one" in your head, we hope this
post updates that picture. Give it a try, and tell us how it goes on
[GitHub](https://github.com/google/gvisor) or the
[mailing list](https://groups.google.com/forum/#!forum/gvisor-users).
