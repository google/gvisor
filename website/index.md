<div class="jumbotron jumbotron-fluid">
  <div class="container">
    <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6">
        <h1 style="color:white;">The Container Security Platform</h1>
        <p>Improve your container security, deliver security-imperative apps,
          increase security productivity, and enforce compliance.</p>
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
        <h2><span><b>gVisor</b></span> is the <span><b>missing security layer</b></span> for
          running containers efficiently and securely.
        </h2>
        <p class="info-text">gVisor is an open-source Linux-compatible sandbox
          that runs anywhere existing container tooling does. It enables
          cloud-native container security and portability. gVisor leverages
          years of experience isolating production workloads at Google.
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
        <h2>Run Untrusted Code</h2>
        <p class="info-text">Isolate Linux hosts from containers so you can
          <strong>safely run user-uploaded, LLM-generated, or third-party
          code</strong>. Add defense-in-depth measures to your stack, bringing
          additional security to your infrastructure.
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
        <h2>Protect Workloads & Infrastructure</h2>
        <p class="info-text">Fortify hosts and containers against
          <strong>escapes and privilege escalation CVEs</strong>, enabling
          strong isolation for security-critical workloads as well as
          multi-tenant safety.
        </p>
        <div class="divide-xl"></div>
      </div>
    </div> <!-- end row -->
  </div> <!-- end container -->
  <div class="container" style="margin-top:20px">
    <div class="row">
      <div class="col-md-4 pull-left">
        <img src="/assets/images/gvisor-reduce-risk.png"
          alt="gVisor reduces risk"
          title="gVisor reduces risk"
          class="img-responsive"
        />
      </div>
      <div class="col-md-8 pull-right">
        <div class="divide-xl"></div>
        <h2>Reduce Risk</h2>
        <p class="info-text">Deliver runtime visibility that integrates
          with popular <strong>threat detection tools</strong> to quickly
          identify threats, generate alerts, and enforce policies.
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
          The way containers should run
        </h1>
        <div class="container" style="margin-top:20px">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><i class="fas fa-shield-alt fa-4x"></i></span></div>
                <h2 align="center"><span>Improve your container security</span></h2>
                <p class="info-text">Give your K8s, SaaS, or Serverless
                  infrastructure additional layers of protection when running
                  end-user code, untrusted code, LLM-generated code, or
                  third-party code. Enable <strong>strong isolation</strong> for
                  sharing resources and delivering <strong>multi-tenant
                  environments</strong>.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-cogs fa-4x"></i></b></span></div>
                <h2 align="center"><span>Deliver security-imperative apps</span></h2>
                <p class="info-text">gVisor adds defense-in-depth measures to
                  your containers, allowing you to <strong>safeguard
                  security-sensitive workloads</strong> like financial
                  transactions, healthcare services, personal identifiable
                  information, and other <strong>security-imperative
                  applications</strong>.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-1"></div>
        </div> <!-- end row container -->
      </div><!-- /row -->
      <div class="row">
        <div class="container" style="margin-bottom:40px">
          <div class="col-md-1"></div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-rocket fa-4x"></i></b></span></div>
                <h2 align="center"><span>Increase security productivity</span></h2>
                <p class="info-text">Isolate your K8s, SaaS, Serverless,
                  DevSecOps lifecycle or CI/CD pipeline.
                  gVisor helps you achieve a secure-by-default posture. Spend
                  <strong>less time staying on top of security
                  disclosures</strong>, and <strong>more time building what
                  matters</strong>.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-solution">
              <div class="panel-body">
                <div align="center"><span><b><i class="fas fa-check fa-4x"></i></b></span></div>
                <h2 align="center"><span>Enforce compliance</span></h2>
                <p class="info-text">gVisor safeguards against many
                  cloud-native attacks by <strong>reducing the attack
                  surface</strong> exposed to your containers. Shield services
                  like APIs, configs, infrastructure as code, DevOps tooling,
                  and supply chains, lowering the risk present in a typical
                  cloud-native stack.
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
                <p class="info-text" style="margin-bottom:0px">
                  <strong>gVisor implements the Linux API</strong>: by
                  intercepting all sandboxed application system calls to the
                  kernel, it protects the host from the application. In
                  addition, <strong>gVisor also sandboxes itself from the
                  host</strong> using Linux's isolation capabilities.
                  Through these layers of defense, gVisor achieves true
                  defense-in-depth while still providing
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
                  (trace points) to an external <strong>threat detection
                  engine</strong> like
                  <a href="https://falco.org" style="color:#272261">Falco</a>
                  and generate alerts.
                </p>
              </div>
            </div>
          </div>
          <div class="col-md-5">
            <div class="panel panel-default" style="border:none;box-shadow:none;">
              <div class="panel-body">
                <h2 style="color:#272261">
                  <a href="blog/2023/06/20/gpu-pytorch-stable-diffusion/" class="feature-link">
                    GPU &amp; CUDA Support
                  </a>
                </h2>
                <p class="info-text" style="margin-bottom:0px;">gVisor
                  applications can <strong>use CUDA on Nvidia GPUs</strong>,
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
