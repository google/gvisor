# Who's Using gVisor

> **Note:** Using gVisor? You can add yourself to this page, contact
> [gvisor-dev@googlegroups.com](mailto:gvisor-dev@googlegroups.com).

This page lists companies and organizations that are known to use gVisor. This
does not constitute an endorsement.

--------------------------------------------------------------------------------

## Companies and organizations using gVisor

### [3B](https://www.tines.com/3b/)

<img src="https://gvisor.dev/assets/logos/tines_logo.svg" alt="Tines logo" height="40" align="right" />

Tines 3B is an AI-native platform for building agents, apps, and automations. It
gives IT and security teams the visibility and control to govern that work.

> gVisor gives 3B a strong isolation boundary for running untrusted code. We use
> checkpoint and restore to start each execution in a fresh, single-use sandbox.
> Its filesystem extension points let us present durable, versioned storage as
> familiar files and directories, while its network stack helps us control each
> step's network access and bandwidth.

<br clear="right" />

--------------------------------------------------------------------------------

### [Ant Group](https://www.antgroup.com/en)

Ant Group, develops online payment platforms. The company offers a wide range of
financial services to consumers and businesses worldwide.

> At Ant Group, we are committed to keeping online transactions safe and
> efficient. Continuously improving security for potential system-level attacks
> is one of many measures. As a container runtime, gVisor provides
> container-native security without sacrificing resource efficiency. Therefore,
> it has been on our radar since it was released.

Read Ant Group's blog post on running gVisor in production at scale
([source](https://gvisor.dev/blog/2021/12/02/running-gvisor-in-production-at-scale-in-ant/)).

--------------------------------------------------------------------------------

### [Anthropic](https://www.anthropic.com/)

<img src="https://gvisor.dev/assets/logos/anthropic_logo.png" alt="Anthropic logo" height="35" align="right" />

Anthropic is a leading AI safety and research company. They are known for
building reliable, interpretable, and steerable AI systems.

Anthropic is a regular open-source contributor to gVisor. They use gVisor to
securely contain code execution within claude.ai.

> The hypervisor, seccomp, and gVisor across our products have been dependable.
> ([How we contain Claude across products](https://www.anthropic.com/engineering/how-we-contain-claude))

<br clear="right" />

--------------------------------------------------------------------------------

### [Beam](https://www.beam.cloud/)

<img src="https://gvisor.dev/assets/logos/logo_beam.png" alt="Beam logo" height="40" align="right" />

Beam is a cloud platform for running application workloads on GPUs and
serverless CPUs, specializing in stateful code execution sandboxes for AI
agents.

> Beam combines stateful snapshots, gVisor isolation, GPU acceleration, and
> bring-your-own-compute so agents operate against a continuous, secure,
> production-grade workspace.
> ([Best Stateful Sandboxes for Code Execution in 2026](https://www.beam.cloud/blog/best-stateful-sandbox-code-execution-2026))

<br clear="right" />

--------------------------------------------------------------------------------

### [Blink](https://www.blinkops.com/)

Blink is a company that specializes in security automation and orchestration
powered by generative AI.

Blink uses gVisor to run pods with full isolation including system calls
([source](https://www.blinkops.com/blog/run-containers-securely-with-gvisor-on-eks)).

--------------------------------------------------------------------------------

### [Cloudflare](https://www.cloudflare.com)

Cloudflare is a content delivery network (CDN) and cloud computing security
company. It provides a range of services to businesses of all sizes.

> It takes just a few seconds for a new gVisor container to start up and begin
> executing meaningful work in a secure sandbox with near native performance.
> ([A new era for Cloudflare Pages builds](https://blog.cloudflare.com/cloudflare-pages-build-improvements/))

--------------------------------------------------------------------------------

### [Deductive AI](https://deductive.ai/)

<img src="https://gvisor.dev/assets/logos/deductive_ai_logo.svg" alt="Deductive AI logo" height="35" align="right" />

Deductive AI builds AI SRE agents for investigating production systems.

> Deductive uses gVisor as the compute isolation boundary for disposable
> sandboxes that execute agent-generated code, combined with Cilium network
> isolation and direct mTLS communication.
> ([Building Secure Sandboxes for AI Agent Execution](https://deductive.ai/blogs/building-secure-sandboxes-for-ai-agent-execution))

<br clear="right" />

--------------------------------------------------------------------------------

### [DigitalOcean](https://www.digitalocean.com/)

DigitalOcean is a cloud computing provider that offers cloud infrastructure
services to developers and businesses.

DigitalOcean uses gVisor in
[App Platform](https://docs.digitalocean.com/products/app-platform/) as a
container runtime sandbox
([source](https://docs.digitalocean.com/products/app-platform/details/limits/)).

--------------------------------------------------------------------------------

### [Docker](https://www.docker.com/)

Docker is a popular container management engine.

Docker for Mac
[uses the gVisor network stack library](https://docs.docker.com/desktop/release-notes/#4190)
for better performance than `vpnkit`. Note that on Docker for Linux, you can
[use gVisor as a container runtime](https://gvisor.dev/docs/user_guide/quick_start/docker/).

--------------------------------------------------------------------------------

### [Freedom of the Press Foundation](https://freedom.press/)

<img src="https://gvisor.dev/assets/logos/freedom_of_the_press_foundation.svg" alt="Freedom of the Press Foundation logo" height="80" align="right" />

The Freedom of the Press Foundation is a non-profit supporting free speech and
freedom of the press.

The [Dangerzone](https://dangerzone.rocks/) application converts potentially
dangerous PDFs, office documents, or images and convert them to safe PDFs for
use by journalists. The document conversion process runs in a
[gVisor sandbox](https://github.com/freedomofpress/dangerzone/blob/main/docs/developer/gvisor.md).

<br clear="right" />

--------------------------------------------------------------------------------

### [Google](https://www.google.com)

<img src="https://gvisor.dev/assets/logos/logo_goog.png" alt="Google logo" height="45" align="right" />

gVisor was designed and developed to efficiently isolate production workloads at
scale for Google services. There are millions of gVisor sandbox instances
running daily. gVisor powers Google Cloud offerings
[GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods),
[Cloud Run](https://cloud.google.com/run),
[App Engine](https://cloud.google.com/appengine), and more.

<br clear="right" />

--------------------------------------------------------------------------------

### [Grist](https://www.getgrist.com/)

Grist combines the flexibility and familiarity of spreadsheets with the power of
databases.

Grist uses gVisor to isolate documents from each other and the network
([source](https://support.getgrist.com/self-managed/#how-do-i-sandbox-documents)).

--------------------------------------------------------------------------------

### [Modal](https://www.modal.com)

<img src="https://gvisor.dev/assets/logos/logo_modal.png" alt="Modal logo" height="40" align="right" />

Modal is a cloud platform that simplifies the execution and management of
various computing workloads for data teams and application developers
(particularly those working in the field of generative AI).

> Compute jobs at Modal are containerized and virtualized using gVisor.
> ([Security at Modal](https://modal.com/docs/guide/security).)

Modal labs tweeted about fully running on gVisor
([source](https://twitter.com/bernhardsson/status/1708929516955930699)).

<br clear="right" />

--------------------------------------------------------------------------------

### [Northflank](https://northflank.com/)

Northflank is a developer platform that simplifies building, deploying, and
scaling applications, databases, and jobs.

> Northflank uses gVisor to run GPU workloads inside sandboxed environments when
> nested virtualization is unavailable on the underlying infrastructure.
> ([GPU sandboxes: isolation models and platform support in 2026](https://northflank.com/blog/gpu-sandboxes)).

--------------------------------------------------------------------------------

### [OpenAI](https://openai.com/)

<img src="https://gvisor.dev/assets/logos/openai_logo.svg" alt="OpenAI logo" height="40" align="right" />

OpenAI develops Artificial Intelligence systems.

OpenAI uses gVisor for
"[some higher-risk tasks](https://openai.com/index/securing-research-infrastructure-for-advanced-ai/)",
such as
[code execution](https://drive.google.com/file/d/1jjqrV76-86rdEcmFNnxMs4lI-ncAookn/view?resourcekey).

<br clear="right" />

--------------------------------------------------------------------------------

### [Tailscale](https://tailscale.com)

<img src="https://gvisor.dev/assets/logos/tailscale_logo.svg" alt="Tailscale logo" height="40" align="right" />

Tailscale provides a mesh-based VPN service designed to simplify secure
networking between devices and servers.

> In userspace mode, Tailscale uses the gVisor netstack library, implementing
> networking in userspace.
> ([Kernel vs. netstack subnet routing & exit nodes](https://tailscale.com/kb/1177/kernel-vs-userspace-routers).)

<br clear="right" />
