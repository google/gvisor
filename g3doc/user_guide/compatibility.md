# Applications

[TOC]

gVisor implements a large portion of the Linux surface and while we strive to
make it broadly compatible, there are (and always will be) unimplemented
features and bugs. The only real way to know if it will work is to try. If you
find a container that doesn’t work and there is no known issue, please
[file a bug][bug] indicating the full command you used to run the image. You can
view open issues related to compatibility [here][issues].

If you're able to provide the [debug logs](../debugging/), the problem likely to
be fixed much faster.

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

## Utilities

Most common utilities work. Note that:

*   Some tools, such as `tcpdump` and old versions of `ping`, require explicitly
    enabling raw sockets via the unsafe `--net-raw` runsc flag.
*   Different Docker images can behave differently. For example, Alpine Linux
    and Ubuntu have different `ip` binaries.

    Specific tools include:

<!-- mdformat off(don't wrap the table) -->

| Tool     | Status                                    |
|:--------:|:-----------------------------------------:|
| apt-get  | Working.                                  |
| bundle   | Working.                                  |
| cat      | Working.                                  |
| curl     | Working.                                  |
| dd       | Working.                                  |
| df       | Working.                                  |
| dig      | Working.                                  |
| drill    | Working.                                  |
| env      | Working.                                  |
| find     | Working.                                  |
| gdb      | Working.                                  |
| gosu     | Working.                                  |
| grep     | Working (unless stdin is a pipe and stdout is /dev/null). |
| ifconfig | Works partially, like ip. Full support [in progress](https://gvisor.dev/issue/578). |
| ip       | Some subcommands work (e.g. addr, route). Full support [in progress](https://gvisor.dev/issue/578). |
| less     | Working.                                  |
| ls       | Working.                                  |
| lsof     | Working.                                  |
| mount    | Works in readonly mode. gVisor doesn't currently support creating new mounts at runtime. |
| nc       | Working.                                  |
| nmap     | Not working.                              |
| netstat  | [In progress](https://gvisor.dev/issue/2112). |
| nslookup | Working.                                  |
| ping     | Working.                                  |
| ps       | Working.                                  |
| route    | Working.                                  |
| ss       | [In progress](https://gvisor.dev/issue/2114). |
| sshd     | Partially working. Job control [in progress](https://gvisor.dev/issue/154). |
| strace   | Working.                                  |
| tar      | Working.                                  |
| tcpdump  | [In progress](https://gvisor.dev/issue/173). |
| top      | Working.                                  |
| uptime   | Working.                                  |
| vim      | Working.                                  |
| wget     | Working.                                  |

<!-- mdformat on -->

[bug]: https://github.com/google/gvisor/issues/new?title=Compatibility%20Issue:
[issues]: https://github.com/google/gvisor/issues?q=is%3Aissue+is%3Aopen+label%3A%22area%3A+compatibility%22
