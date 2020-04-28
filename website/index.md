---
layout: base
---
<div class="jumbotron jumbotron-fluid">
  <div class="container">
    <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6">
        <p>gVisor is an <b>application kernel</b> and <b>container runtime</b> providing defense-in-depth for containers <em>anywhere</em>.</p>
        <p style="margin-top: 20px;">
          <a class="btn" href="/docs/">Get Started&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i></a>
          <a class="btn btn-inverse" href="https://github.com/google/gvisor">GitHub&nbsp;<i class="fab fa-github ml-2"></i></a>
        </p>
      </div>
      <div class="col-md-3"></div>
    </div>
  </div>
</div>

<div class="container"> <!-- Full page container. -->

<div class="row">
  <div class="col-md-4">
    <h4 id="seamless-security">Container-native Security <i class="fas fa-lock"></i></h4>
    <p>By providing each container with its own application kernel instance,
    gVisor limits the attack surface of the host while still integrating
    seamlessly with popular container orchestration systems, such as Docker and
    Kubernetes. This includes support for advanced features, such as a volumes,
    terminals and sidecars, and still providing visibility into the application
    behavior through cgroups and other monitoring mechanisms.
    </p>
    <a class="button" href="/docs/architecture_guide/security/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="resource-efficiency">Resource Efficiency <i class="fas fa-feather-alt"></i></h4>
    <p>Containers are efficient because workloads of different shapes and sizes
    can be packed together by sharing host resources. By using host native
    abstractions such as threads and memory mappings, gVisor closely co-operates
    with the host to enable the same resource model as native containers.
    Sandboxed containers can safely and securely share host resources with each
    other and native containers on the same system.
    </p>
    <a class="button" href="/docs/architecture_guide/resources/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="platform-portability">Platform Portability <sup>&#9729;</sup>&#9729;</h4>
    <p>Modern infrastructure spans multiple clouds and data centers, often using
    a mix of virtualized instances and traditional servers. The pluggable
    platform architecture of gVisor allows it to run anywhere, enabling security
    policies to be enforced consistently across multiple environments.
    Sandboxing requirements need not dictate where workloads can run.
    </p>
    <a class="button" href="/docs/architecture_guide/platforms/">Read More &raquo;</a>
  </div>
</div>

</div> <!-- container -->
