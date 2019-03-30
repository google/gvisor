+++
title = "Compatibility"
weight = 100
+++
gVisor implements a large portion of the Linux surface and while we strive to
make it broadly compatible, there are (and always will be) unimplemented
features and bugs. The only real way to know if it will work is to try. If you
find a container that doesn’t work and there is no known issue, please [file a
bug][bug] indicating the full command you used to run the image.

If you're able to provide the [debug logs](../debugging/), the
problem likely to be fixed much faster.

## What works?

The following applications/images have been tested:

*   elasticsearch
*   golang
*   httpd
*   java8
*   jenkins
*   mariadb
*   memcached
*   mongo
*   mysql
*   nginx
*   node
*   php
*   postgres
*   prometheus
*   python
*   redis
*   registry
*   tomcat
*   wordpress

[bug]: https://github.com/google/gvisor/issues

## Syscall Reference

This section contains an architecture-specific syscall reference guide. These
tables are automatically generated from source-level annotations.
