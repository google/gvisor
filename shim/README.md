# gvisor-containerd-shim

gvisor-containerd-shim is a containerd shim. It implements the containerd v1
shim API. It can be used as a drop-in replacement for
[containerd-shim][containerd-shim]
(though containerd-shim must still be installed). It allows the use of both
gVisor (runsc) and normal containers in the same containerd installation by
deferring to the runc shim if the desired runtime engine is not runsc.

-   [Untrusted Workload Quick Start (containerd >=1.1)](docs/untrusted-workload-quickstart.md)
-   [Runtime Handler/RuntimeClass Quick Start (containerd >=1.2)](docs/runtime-handler-quickstart.md)
-   [Runtime Handler/RuntimeClass Quick Start (shim v2) (containerd >=1.2)](docs/runtime-handler-shim-v2-quickstart.md)
-   [Configure containerd-shim-runsc-v1 (shim v2) (containerd >= 1.3)](docs/configure-containerd-shim-runsc-v1.md)
-   [Configure gvisor-containerd-shim (shim v1) (containerd &lt;= 1.2)](docs/configure-gvisor-containerd-shim.md)

[containerd-shim]: https://github.com/containerd/containerd/tree/master/cmd/containerd-shim
