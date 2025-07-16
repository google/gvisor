<div class="jumbotron jumbotron-fluid bg-dark text-white">
  <div class="container text-center">
    <h1>The Container Security Platform</h1>
    <p>Improve your container security, deliver security-imperative apps, increase security productivity, and enforce compliance.</p>
    <div class="mt-4">
      <a class="btn btn-primary mx-2" href="/docs/user_guide/install/">
        Get started&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i>
      </a>
      <a class="btn btn-outline-light mx-2" href="/docs/">
        What is gVisor?&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i>
      </a>
    </div>
  </div>
</div>

<section id="use-cases" class="container my-5">
  <div class="row align-items-center mb-5">
    <div class="col-md-6 order-md-2 text-center">
      <img src="/assets/images/gvisor-high-level-arch.png" alt="gVisor high-level architecture" title="gVisor high-level architecture" class="img-fluid rounded shadow"/>
    </div>
    <div class="col-md-6 order-md-1">
      <h2><b>gVisor</b> is the <b>missing security layer</b> for running containers efficiently and securely.</h2>
      <p class="lead">gVisor is an open-source Linux-compatible sandbox that runs anywhere existing container tooling does. It enables cloud-native container security and portability, leveraging years of experience isolating production workloads at Google.</p>
    </div>
  </div>

  <div class="row align-items-center mb-5">
    <div class="col-md-6 text-center">
      <img src="/assets/images/gvisor-run-untrusted.png" alt="gVisor can run untrusted code" title="gVisor can run untrusted code" class="img-fluid rounded shadow"/>
    </div>
    <div class="col-md-6">
      <h2>Run Untrusted Code</h2>
      <p>Isolate Linux hosts from containers so you can <strong>safely run user-uploaded, LLM-generated, or third-party code</strong>. Add defense-in-depth measures to your stack, bringing additional security to your infrastructure.</p>
    </div>
  </div>

  <div class="row align-items-center mb-5">
    <div class="col-md-6 order-md-2 text-center">
      <img src="/assets/images/gvisor-secure-by-default.png" alt="gVisor secure by default" title="gVisor secure by default" class="img-fluid rounded shadow"/>
    </div>
    <div class="col-md-6 order-md-1">
      <h2>Protect Workloads & Infrastructure</h2>
      <p>Fortify hosts and containers against <strong>escapes and privilege escalation CVEs</strong>, enabling strong isolation for security-critical workloads as well as multi-tenant safety.</p>
    </div>
  </div>

  <div class="row align-items-center mb-5">
    <div class="col-md-6 text-center">
      <img src="/assets/images/gvisor-reduce-risk.png" alt="gVisor reduces risk" title="gVisor reduces risk" class="img-fluid rounded shadow"/>
    </div>
    <div class="col-md-6">
      <h2>Reduce Risk</h2>
      <p>Deliver runtime visibility that integrates with popular <strong>threat detection tools</strong> to quickly identify threats, generate alerts, and enforce policies.</p>
    </div>
  </div>
</section>

<section id="solutions" class="bg-dark text-white py-5">
  <div class="container">
    <h1 class="text-center mb-5">The way containers should run</h1>
    <div class="row justify-content-center">
      <div class="col-md-5 mb-4">
        <div class="card h-100 text-center bg-secondary text-white shadow">
          <div class="card-body">
            <i class="fas fa-shield-alt fa-4x mb-3"></i>
            <h2>Improve your container security</h2>
            <p>Give your K8s, SaaS, or Serverless infrastructure additional layers of protection when running end-user code, untrusted code, LLM-generated code, or third-party code. Enable <strong>strong isolation</strong> for sharing resources and delivering <strong>multi-tenant environments</strong>.</p>
          </div>
        </div>
      </div>
      <div class="col-md-5 mb-4">
        <div class="card h-100 text-center bg-secondary text-white shadow">
          <div class="card-body">
            <i class="fas fa-cogs fa-4x mb-3"></i>
            <h2>Deliver security-imperative apps</h2>
            <p>gVisor adds defense-in-depth measures to your containers, allowing you to <strong>safeguard security-sensitive workloads</strong> like financial transactions, healthcare services, personal identifiable information, and other <strong>security-imperative applications</strong>.</p>
          </div>
        </div>
      </div>
      <div class="col-md-5 mb-4">
        <div class="card h-100 text-center bg-secondary text-white shadow">
          <div class="card-body">
            <i class="fas fa-rocket fa-4x mb-3"></i>
            <h2>Increase security productivity</h2>
            <p>Isolate your K8s, SaaS, Serverless, DevSecOps lifecycle or CI/CD pipeline. gVisor helps you achieve a secure-by-default posture. Spend <strong>less time staying on top of security disclosures</strong>, and <strong>more time building what matters</strong>.</p>
          </div>
        </div>
      </div>
      <div class="col-md-5 mb-4">
        <div class="card h-100 text-center bg-secondary text-white shadow">
          <div class="card-body">
            <i class="fas fa-check fa-4x mb-3"></i>
            <h2>Enforce compliance</h2>
            <p>gVisor safeguards against many cloud-native attacks by <strong>reducing the attack surface</strong> exposed to your containers. Shield services like APIs, configs, infrastructure as code, DevOps tooling, and supply chains, lowering the risk present in a typical cloud-native stack.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<section id="features" class="container my-5">
  <div class="text-center">
    <img src="/assets/images/gvisor-helmet-universe.png" alt="gVisor features" title="gVisor features" class="img-fluid mb-3" style="max-width: 300px;">
    <h1>gVisor Features</h1>
  </div>

  <div class="row mt-4">
    <div class="col-md-6 mb-4">
      <h2><a href="docs/architecture_guide/security/#principles-defense-in-depth" class="feature-link">Defense in Depth</a></h2>
      <p>gVisor implements the Linux API by intercepting all sandboxed application system calls to the kernel, protecting the host from the application. Additionally, it sandboxes itself from the host using Linux's isolation capabilities, achieving true defense-in-depth while providing <strong>VM-like performance</strong> and <strong>container-like resource efficiency</strong>.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/architecture_guide/security/" class="feature-link">Secure by Default</a></h2>
      <p>gVisor runs with the least privileges and strictest system call filter needed to function. Implemented in Go, a memory-safe and type-safe language, it secures the kernel and network stack.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/architecture_guide/platforms/" class="feature-link">Runs Anywhere</a></h2>
      <p>Runs anywhere Linux does: x86, ARM, VMs, bare-metal, no virtualization support required. Compatible with popular cloud providers.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/user_guide/compatibility/" class="feature-link">Cloud Ready</a></h2>
      <p>Works with Docker, Kubernetes, and containerd. Many applications and images are deployed on gVisor in production.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/architecture_guide/performance/" class="feature-link">Fast Startups and Execution</a></h2>
      <p>Containers start in milliseconds with minimal overhead, acting and scaling like containers, not VMs, ensuring <strong>container-native resource efficiency</strong>.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/user_guide/checkpoint_restore/" class="feature-link">Checkpoint and Restore</a></h2>
      <p>Supports checkpoint and restore of containers for caching, migration, snapshots, forensics, or interactive REPL sessions.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="/docs/user_guide/runtimemonitor/" class="feature-link">Runtime Monitoring</a></h2>
      <p>Streams application behavior to external threat detection engines like <a href="https://falco.org" class="feature-link">Falco</a> to generate alerts.</p>
    </div>
    <div class="col-md-6 mb-4">
      <h2><a href="docs/user_guide/gpu/" class="feature-link">GPU & CUDA Support</a></h2>
      <p>Enables CUDA on Nvidia GPUs for AI/ML workloads with isolation.</p>
    </div>
  </div>
</section>
