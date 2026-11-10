<div class="jumbotron jumbotron-fluid">
  <div class="container">
    <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6">
        <h1 style="color:white;">The Sandbox Kernel for Agents</h1>
        <p>Memory-safe, lightweight Linux-compatible userspace kernel
        to safely sandbox agents at high density without virtual
        machine overhead.</p>
        <p style="margin-top: 20px;">
          <a class="btn" href="/docs/user_guide/install/">
            Get started&nbsp;
            <i class="fas fa-arrow-alt-circle-right ml-2"></i>
          </a>
          <a class="btn" href="/docs/">
            What is gVisor?&nbsp;
            <i class="fas fa-arrow-alt-circle-right ml-2"></i>
          </a>
        </p>
      </div>
      <div class="col-md-3"></div>
    </div>
  </div>
</div>

<!-- gVisor Use Cases -->

<section id="use-cases">
  <div class="container">
    <div class="row">
      <div class="col-md-6 pull-right gallery-popup">
        <img
          src="/assets/images/gvisor-high-level-arch.png"
          alt="gVisor high-level architecture"
          title="gVisor high-level architecture"
          class="img-responsive"
        />
      </div>
      <div class="col-md-6 pull-left">
        <div class="divide-xl"></div>
        <h2>Efficiently Sandbox Agentic &amp; AI Workloads</h2>
        <p class="info-text"><strong>Handle bursty code execution
            demand</strong> with <strong>high density</strong> from agentic
            tools, distributed RL environments, LLM-generated code,
            autoresearch and data science exploration.
        </p>
        <p class="info-text">
          <strong>Pack orders of magnitude more sandboxes per node</strong> by
          reclaiming idle memory dynamically back to the host. Eliminate
          hypervisor boot phases and memory fragmentation.
        </p>
        <div class="divide-xl"></div>
    </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
  <div class="container" style="margin-top:20px">
    <div class="row">
      <div class="col-md-4 pull-left">
       <img
          src="/assets/images/gvisor-run-untrusted.png"
          alt="gVisor can run untrusted code"
          title="gVisor can run untrusted code"
          class="img-responsive"
        />
      </div>
      <div class="col-md-8 pull-right">
        <div class="divide-xl"></div>
        <h2>Scale and Secure Autonomous AI Agents</h2>
        <p class="info-text">Deliver <strong>container-native pod density,
          instant cold starts, and dynamic host memory allocation without
          requiring nested virtualization</strong> inside virtual machines.
        </p>
        <p class="info-text">Standard containers lack isolation and
          <strong>microVMs still carry high idle memory and slow initialization
          overhead when compared to native containers</strong>.
        </p>
        <div class="divide-xl"></div>
      </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
  <div class="container" style="margin-top:20px">
    <div class="row">
      <div class="col-md-4 pull-right">
       <img
          src="/assets/images/gvisor-secure-by-default.png"
          alt="gVisor secure by default"
          title="gVisor secure by default"
          class="img-responsive"
        />
      </div>
      <div class="col-md-8 pull-left">
        <div class="divide-xl"></div>
        <h2>Harden Shared and Multi-Tenant Compute Clusters</h2>
        <p class="info-text"><strong>Harden clusters like Kubernetes</strong>
          against container breakouts, shared-kernel vulnerabilities, and
          unpatched host kernel CVEs.
       </p>
        <p class="info-text">Sandbox workloads by inserting an
          <strong>independent user-space kernel</strong>, removing direct
          access to the host Linux kernel.
       </p>
        <div class="divide-xl"></div>
      </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
  <div class="container" style="margin-top:20px">
    <div class="row">
      <div class="col-md-4 pull-left">
        <img src="/assets/images/gvisor-multi-cloud.png"
          alt="gVisor supports multi-cloud"
          title="gVisor supports multi-cloud"
          class="img-responsive"
        />
      </div>
      <div class="col-md-8 pull-right">
        <div class="divide-xl"></div>
        <h2>Support Agents Across Hybrid and Multi-Cloud Footprints</h2>
        <p class="info-text"><strong>Run agents and AI workloads</strong>
          without fragmenting Kubernetes tooling or pod specs.
        </p>
        <p class="info-text">gVisor <strong>implements the OCI Runtime
          Spec</strong>, functioning as a <strong>standard Kubernetes
          RuntimeClass</strong> without requiring custom VM images or
          hypervisor network bridges.
        </p>
        <div class="divide-xl"></div>
      </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
  <div class="container" style="margin-top:20px">
    <div class="row">
      <div class="col-md-4 pull-right">
        <img src="/assets/logos/agent-substrate-logo.png"
          alt="Agent Substrate Logo"
          title="Agent Substrate Logo"
          class="img-responsive"
        />
      </div>
      <div class="col-md-8 pull-left">
        <div class="divide-xl"></div>
        <h2>Don't Pay for Idle Sandboxes via Agent Substrate</h2>
        <p class="info-text">Automatically <strong>checkpoint idle
          sandboxes</strong> and <strong>seamlessly resume them in
          milliseconds</strong> via integration with
          <a href="https://ate.dev">Agent Substrate</a>.
        </p>
        <p class="info-text">gVisor <strong>natively integrates with Agent
            Substrate in Kubernetes</strong>, yielding superior density and
            checkpoint/restore performance.
        </p>
        <div class="divide-xl"></div>
      </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
</section> <!-- end use case section -->

<!-- gVisor Solutions -->

<section id="solutions">
  <div class="info-section-gray">
    <div class="container-fluid" style="margin-top:50px;background-color:#171433">
      <div class="row">
        <h1 align="center" style="color:white;font-size:38px">
          Why gVisor?
        </h1>
        <div class="container" style="margin-top:20px">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><i class="fas fa-shield-alt fa-4x"></i></span></div>
                <h2 align="center"><span>Host Kernel Exploit Mitigation</span></h2>
                <p class="info-text">gVisor implements core Linux kernel
                  abstractions (process management, memory layout, network stack,
                  VFS) so that application syscalls are serviced in user space,
                  isolating the host kernel from guest code.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-memory fa-4x"></i></b></span></div>
                <h2 align="center"><span>Zero Wasted Memory</span></h2>
                <p class="info-text">gVisor allocates and releases host OS
                  memory natively as a container does, rather than using guest
                  OS ballooning drivers. This eliminates memory fragmentation
                  issues and enables packing more sandboxes per host.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row">
        <div class="container">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-rocket fa-4x"></i></b></span></div>
                <h2 align="center"><span>Instant Sandbox Execution</span></h2>
                <p class="info-text">Bypass virtual hardware initialization
                  sequences (virtual BIOS, vCPU configuration, PCI bus
                  enumeration, guest kernel boot). Launch isolated sandboxes
                  with process-like startup latency, ideal for high-throughput
                  tool calling and short-lived execution tasks.
               </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-microchip fa-4x"></i></b></span></div>
                <h2 align="center"><span>GPU &amp; TPU Support</span></h2>
                <p class="info-text">gVisor supports GPU and TPU accelerators.
                  Driver operations are relayed to the host kernel drivers,
                  with near-native performance and zero memory copying overhead.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row">
        <div class="container" style="margin-bottom:20px">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-redo fa-4x"></i></b></span></div>
                <h2 align="center"><span>Load large GPU Models in Seconds</span></h2>
                <p class="info-text">NVIDIA GPU workloads may be seamlessly
                  checkpointed and restored within gVisor. GPU memory pages are
                  streamed in from checkpoint storage as they are restored into
                  VRAM, with hardware speeds as the only bottleneck.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-exclamation-triangle fa-4x"></i></b></span></div>
                <h2 align="center"><span>Intrusion and Tampering Detection</span></h2>
                <p class="info-text">Attach probes and trace sessions to gVisor
                  sandboxes, providing real-time observability over sandbox events.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
    </div><!-- /container -->
  </div>
</section>

<!-- gVisor Features -->

<section id="features">
  <div class="info-section-gray">
    <div class="container" style="margin-top:30px">
      <!-- Helmet universe image -->
      <div align="center">
        <img
          src="/assets/images/gvisor-helmet-universe.png"
          alt="gVisor features"
          title="gVisor features"
          class="img-responsive"
        >
      </div>
      <h1 align="center" style="margin-top:3px">gVisor Features</h1>
      <!-- Start features list -->
      <div class="row">
        <div class="container">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2>
                  <a href="docs/architecture_guide/security/#principles-defense-in-depth" class="feature-link">
                    Defense in Depth
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px"><strong>gVisor
                  implements the Linux API</strong>: by intercepting all
                  sandboxed application system calls to the kernel, it protects
                  the host from the application. In addition, <strong>gVisor
                  also sandboxes itself from the host</strong> using Linux's
                  isolation capabilities. Through these layers of defense,
                  gVisor achieves true defense-in-depth while still providing
                  <strong>VM-like performance</strong> and
                  <strong>container-like resource efficiency</strong>.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
              <h2>
                <a href="docs/architecture_guide/security/" class="feature-link">
                  Secure by Default
                </a>
              </h2>
              <p class="info-text" style="margin-bottom:0px;">gVisor runs with
                the <strong>least amount of privileges</strong> and the
                strictest possible system call filter needed to function. gVisor
                implements the Linux kernel and its network stack using Go, a
                memory-safe and type-safe language.
              </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row" style="margin-top:0px">
        <div class="container">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2>
                  <a href="docs/architecture_guide/platforms/" class="feature-link">
                    Runs Anywhere
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor
                  <strong>runs anywhere Linux does</strong>. It works on x86 and
                  ARM, on VMs or bare-metal, and does not require virtualization
                  support. gVisor works well on all popular cloud providers.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="docs/user_guide/compatibility/" class="feature-link">
                    Cloud Ready
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor
                  <strong>works with Docker, Kubernetes, and
                  containerd</strong>. Many popular applications and images are
                  deployed in production environments on gVisor.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row" style="margin-top:0px">
        <div class="container">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="docs/architecture_guide/performance/" class="feature-link">
                    Fast Startups and Execution
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor
                  containers start up in milliseconds and have minimal resource
                  overhead. They act like, feel like, and <em>actually are</em>
                  containers, not VMs. Their resource consumption can scale up
                  and down at runtime, enabling <strong>container-native
                  resource efficiency</strong>.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="docs/user_guide/checkpoint_restore/" class="feature-link">
                    Checkpoint and Restore
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor can
                  <strong>checkpoint and restore containers</strong>. Use it to
                  cache warmed-up services, resume workloads on other machines,
                  snapshot execution, save state for forensics, or branch
                  interactive REPL sessions.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row" style="margin-top:0px">
        <div class="container">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="/docs/user_guide/runtimemonitor/" class="feature-link">
                    Runtime Monitoring
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">Observe runtime
                  behavior of your applications by streaming application actions
                  (trace points) to an external threat detection
                  engine like
                  <a href="https://wiz.io" style="color:#272261">Wiz</a>
                  and generate alerts.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="docs/user_guide/gpu/" class="feature-link">
                    TPU &amp; GPU (CUDA) Support
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor
                  applications can <strong>use TPUs and CUDA on Nvidia GPUs</strong>,
                  bringing isolation to AI/ML workloads.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
    </div> <!-- /container -->
  </div>
</section>
