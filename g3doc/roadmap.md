# Roadmap

gVisor [GitHub Issues][issues] serve as the source-of-truth for most work in
flight. Specific performance and compatibility issues are generally tracked
there. [GitHub Milestones][milestones] may be used to track larger features that
span many issues. However, labels are also used to aggregate cross-cutting
feature work.

## Core Improvements

Most gVisor work is focused on four areas.

*   [Performance][performance]: overall sandbox performance, including platform
    performance, is a critical area for investment. This includes: network
    performance (throughput and latency), file system performance (metadata and
    data I/O), application switch and fault costs, etc. The goal of gVisor is to
    provide sandboxing without a material performance or efficiency impact on
    all but the most performance-sensitive applications.

*   [Compatibility][compatibility]: supporting a wide range of applications
    requires supporting a large system API, including special system files (e.g.
    proc, sys, dev, etc.). The goal of gVisor is to support the broad set of
    applications that depend on a generic Linux API, rather than a specific
    kernel version.

*   [Infrastructure & tooling][infrastructure]: the above goals require
    aggressive testing and coverage, and well-established processes. This
    includes adding appropriate system call coverage, end-to-end suites and
    runtime tests.

*   [Integration][integration]: Container infrastructure is evolving rapidly and
    becoming more complex, and gVisor must continuously implement relevant and
    popular features to ensure that integration points remain robust and
    feature-complete while preserving security guarantees.

## Releases

Releases are available on [GitHub][releases].

As a convenience, binary packages are also published. Instructions for their use
are available via the [Installation instructions](./user_guide/install.md).

[issues]: https://github.com/google/gvisor/issues
[milestones]: https://github.com/google/gvisor/milestones
[releases]: https://github.com/google/gvisor/releases
[performance]: https://github.com/google/gvisor/issues?q=is%3Aopen+is%3Aissue+label%3A%22area%3A+performance%22
[integration]: https://github.com/google/gvisor/issues?q=is%3Aopen+is%3Aissue+label%3A%22area%3A+integration%22
[compatibility]: https://github.com/google/gvisor/issues?q=is%3Aopen+is%3Aissue+label%3A%22area%3A+compatibility%22
[infrastructure]: https://github.com/google/gvisor/issues?q=is%3Aopen+is%3Aissue+label%3A%22area%3A+tooling%22
