# gVisor is being donated to CNCF

<!-- disableFinding(FIGURE_NO_CAPTION) -->

<figure class="img-100pct">
<img src="/assets/images/2026-10-02-gvisor-cncf/cover.jpeg" alt="gVisor being donated to the Cloud Native Computing Foundation, a subsidiary of the Linux Foundation.">
</figure><br/>

In 2018,
[Google open-sourced gVisor](https://cloud.google.com/blog/products/gcp/open-sourcing-gvisor-a-sandboxed-container-runtime)
under the Apache 2.0 license. To the best of its contributors' knowledge, it has
ever since remained the second most mature implementation of Linux, after Linux.

This year, **the gVisor project is being donated to CNCF**, and its governance
model is shifting accordingly.

<!--/excerpt-->

## What's happening?

Google is donating the gVisor project, including its name and trademarks, to the
[Cloud Native Computing Foundation (CNCF)](https://www.cncf.io/), a subsidiary
of the [Linux Foundation](https://www.linuxfoundation.org/). Like its name
implies, CNCF is focused on cloud-native computing, with Google having seeded
its creation by donating the Kubernetes project. Since then, Kubernetes has
grown to become the industry-standard for container orchestration, and has grown
a large and vibrant ecosystem around it. gVisor is now following the same
footsteps.

You can see gVisor's
[CNCF application and process](https://github.com/cncf/sandbox/issues/521).

## What's the timeline?

**What has already happened**:

-   2026-09-07: Google submitted its
    [CNCF donation application](https://github.com/cncf/sandbox/issues/521).
-   2026-09-22: The CNCF reviewed the application.
-   2026-09-28: The application was accepted.
-   2026-10-02: This blog post was published.

**Over the next few weeks**:

-   The project will move to CNCF "**Sandbox**" status (quite
    appropriately-named for a project like gVisor).
-   gVisor's build and testing infrastructure will move to GitHub Actions and
    Buildkite
-   Google's internal gVisor test infrastructure will no longer block PRs.
-   The gVisor project's governance model will transition to a
    [maintainers-based model](https://github.com/google/gvisor/blob/master/MAINTAINERS.md).
-   Non-Google maintainers will be added and given merge permissions.

**Over the next few months**:

-   The project will take the steps needed to move to CNCF "**Incubation**"
    status.
-   The GitHub repository will move out of the `google` GitHub organization.
-   The gVisor project's governance model will transition to a long-term model
    that features **org-based voting**, thereby preventing Google from having
    unilateral control over governance decisions.
-   Any further steps to become a fully-fledged CNCF project will proceed.

## Why donate?

gVisor doesn't fit neatly into the industry's well-known boxes of the
sandboxing/security landscape, which tends to separate "vanilla containers" from
"virtual machines" with shades of gray in between. gVisor straddles this
middle-ground, providing
[**empirically-equivalent security**](/security-track-record/) but without
checking the familiar "virtualization" checkbox that security auditors,
regulators, or security practitioners often treat as a one-to-one proxy for
"secure". This has caused **adoption challenges** over gVisor's history, as it
has been difficult to communicate the value of the project to an audience that
is used to this **false dichotomy**.

Another challenge gVisor has faced is that of a **performance perception
problem**. Internally within Google (and other gVisor-using companies, such as
Ant Group and Modal), there exist Linux kernel patches that improve gVisor
performance significantly. However, for other gVisor users, out-of-the-box
performance often shows performance degradation for certain I/O-intensive
workloads. This has led to **poor first-impressions** from potential adopters.
We have tried to address this by upstreaming Linux kernel patches that improve
its performance, but have been turned down by kernel maintainers due to gVisor
being a wholly-owned Google project.

Lastly, gVisor as a project has potential that is difficult to prioritize when
guided by corporate ownership alone. As a userspace implementation of Linux,
gVisor has potential non-commercial applications such as:

-   **gVisor-on-Mac**: Allowing **Linux programs to run on macOS**, with a
    similar experience as to how how Wine allows Windows programs on macOS.
-   **Desktop Linux sandboxing**: Allowing gVisor to be used as a **practical
    option for desktop Linux application sandboxing** that is much more secure
    than the current state of the art (bubblewrap/flatpak/nsjail/etc), yet much
    easier to integrate with than full-blown virtualization-based approaches
    like that of [Qubes OS](https://www.qubes-os.org/). We have made some
    advancements on this front with our
    [recently-introduced `bwrap` drop-in replacement](https://gvisor.dev/docs/user_guide/personalities/bwrap/),
    but gVisor is capable of sandboxing
    [so much more](/blog/2026/09/17/systemd-in-gvisor/).

We see evidence of these problems by looking at the
[current set of gVisor adopters](/users/), which are all either large tech
companies with the ability to invest and customize gVisor to suit their own
needs (Google, Ant Group, OpenAI, Anthropic), and startups with a
highly-specific focus that exactly fits gVisor's use-case, and where it makes
sense to spend a startup's limited resources specifically into making gVisor
work great for them (Modal, Tines). Who is *not* on this list?

-   **Hobbyist projects**: See aforementioned non-commercial applications where
    gVisor would be useful but isn't currently adopted.
-   The **"middle" of the industry**: Individuals and companies that would
    benefit from gVisor's security, but either aren't aware of its existence,
    dismiss it out of past perception problems, or don't have the resources to
    invest specifically into security but would happily adopt an off-the-shelf,
    widely-available sandboxing runtime were it to exist as a widespread and
    cheap option already available as an offering by their computing
    infrastructure provider.
-   **Other non-Google hyperscalers**: While gVisor is adopted internally by
    nearly all large tech companies for their own at-scale sandboxing needs
    (e.g. code snippet execution, RL), only a small subset (Google,
    DigitalOcean, and Modal) directly sell general-purpose gVisor-powered
    compute to their customers. This is in spite of gVisor's competitive
    operational margins, as well as the **demonstrable demand** for this,
    because issue reports to the gVisor repository show that a large number of
    entities are self-installing gVisor on non-Google hyperscalers. The
    remaining explanation of the lack of direct integration is likely the
    project's (pre-donation) governance risk.

By contributing the project to the CNCF, we aim to address all of these issues.
This enables gVisor and application kernels to become part of the container
ecosystem and security industry's lingua franca, enabling integration and
adoption beyond highly-motivated/sophisticated/resourceful corporate entities,
and enables upstreaming Linux patches that solve gVisor's performance for
everyone.

### Why donate to CNCF specifically?

gVisor is a drop-in-compatible container runtime that fits in the Cloud Native
container ecosystem. It integrates directly with CNCF technologies such as
Kubernetes, `containerd`, and
[Agent Substrate](https://github.com/cncf/sandbox/issues/523).

From a resource and efficiency standpoint, gVisor acts as a *more cloud-native*
container runtime than other security-focused container runtimes, thanks to its
container-like process model. This allows it to be efficiently and
tightly-sized, enabling secure container binpacking at a resolution and density
VM-based runtimes cannot match. It also does not require hardware virtualization
or nested virtualization, enabling it to run anywhere Linux runs. That makes
gVisor a good complement to CNCF's existing portfolio. gVisor and is already
usable on all major clouds, some of which offer it as a native offering, and
others for which cloud users can (and do) self-install it.

## Will Google divest from gVisor development in the future?

The past few months have been pivotal for the security industry and
[**for secure sandboxing specifically**](https://www.youtube.com/watch?v=87DyyMV0kCY).
It would make very little sense for Google to abandon its sandboxing technology
at a time when the need for cheap and secure sandboxing has never been clearer.
On the contrary, we (the gVisor contributors at Google) have been pushing for
this move internally with the expectation that this will *accelerate* gVisor's
growth and adoption both within and outside of Google, in a similar manner as
what has happened with Kubernetes.

## Who is joining gVisor's contributors beyond Google?

Google is reaching out to potentially-interested parties. As of this writing,
the following entities have committed to joining gVisor's maintainers for the
long haul: [Ant Group](https://www.antgroup.com/), [Modal](https://modal.com/),
and [Tines](https://www.tines.com/). Additionally, other companies including
[OpenAI](https://openai.com/), [Tencent](https://www.tencent.com/), and
[NVIDIA](https://www.nvidia.com/) will continuing their ongoing contributions to
gVisor.

## What does this mean for me?

-   In the short term: Not much.
-   In the medium term: A less painful PR contribution experience.
-   In the long run: A more free gVisor, with development accelerated by an
    influx of new contributors, and directed by a more open governance process
    in service of its users.

## What's next?

Some gVisor contributors will be at
[KubeCon North America 2026](https://events.linuxfoundation.org/kubecon-cloudnativecon-north-america/).
Come chat!
