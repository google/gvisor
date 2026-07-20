# gVisor Python Bindings

Python bindings for [gVisor](https://github.com/google/gvisor).

## Overview

gVisor is an application kernel, written in Go, that implements a substantial
portion of the Linux system surface. It includes an Open Container Initiative
(OCI) runtime called `runsc` that provides an isolation boundary between the
application and the host kernel. The `runsc` runtime delivers strong sandbox
isolation while still allowing applications to behave as they would under
standard runtimes.

These Python bindings provide a programmable interface to interact with gVisor.

## License

Apache License 2.0
