<div class="jumbotron jumbotron-fluid">
  <div class="container">
    <div class="row">
      <div class="col-md-3"></div>
      <div class="col-md-6">
        <p>gVisor is an <b>application kernel</b> for <b>containers</b> that provides efficient defense-in-depth anywhere.</p>
        <p style="margin-top: 20px;">
          <a class="btn" href="/docs/user_guide/install/">Get started&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i></a>
          <a class="btn" href="/docs/">Learn More&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i></a>
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
    <p>By providing each container with its own application kernel, gVisor
    limits the attack surface of the host. This protection does not limit
    functionality: gVisor runs unmodified binaries and integrates with container
    orchestration systems, such as Docker and Kubernetes, and supports features
    such as volumes and sidecars.</p>
    <a class="button" href="/docs/architecture_guide/security/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="resource-efficiency">Resource Efficiency <i class="fas fa-feather-alt"></i></h4>
    <p>Containers are efficient because workloads of different shapes and sizes
    can be packed together by sharing host resources. gVisor uses host-native
    abstractions, such as threads and memory mappings, to co-operate with the
    host and enable the same resource model as native containers.</p>
    <a class="button" href="/docs/architecture_guide/resources/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="platform-portability">Platform Portability <sup>&#9729;</sup>&#9729;</h4>
    <p>Modern infrastructure spans multiple cloud services and data centers,
    often with a mix of managed services and virtualized or traditional servers.
    The pluggable platform architecture of gVisor allows it to run anywhere,
    enabling consistent security policies across multiple environments without
    having to rearchitect your infrastructure.</p>
    <a class="button" href="/docs/architecture_guide/platforms/">Read More &raquo;</a>
  </div>

  <div class="col-md-5">
    <h4 id="platform-portability">Tune gVisor for Production Adoption <sup>&#9729;</sup>&#9729;</h4>
    <p>TODO: introduction</p>
    <a class="button" href="/docs/architecture_guide/platforms/">Read More &raquo;</a>
  </div>

</div>

</div> <!-- container -->
