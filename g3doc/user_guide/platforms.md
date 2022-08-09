# Changing Platforms

[TOC]

This guide described how to change the
[platform](../architecture_guide/platforms.md) used by `runsc`.

Configuring the platform provides significant performance benefits, but isn't
the only step to optimizing gVisor performance. See the [Production guide] for
more.

## Prerequisites

If you intend to run the KVM platform, you will also to have KVM installed on
your system. If you are running a Debian based system like Debian or Ubuntu you
can usually do this by ensuring the module is loaded, and your user has
permissions to access the `/dev/kvm` device. Usually, it means that the user is
in the `kvm` group.

```shell
# Check that /dev/kvm is owned by the kvm group
$ ls -l /dev/kvm
crw-rw----+ 1 root kvm 10, 232 Jul 26 00:04 /dev/kvm

# Make sure that the current user is part of the kvm group
$ groups | grep -qw kvm && echo ok
ok
```

**For best performance, use the KVM platform on bare-metal machines only**. If
you have to run gVisor within a virtual machine, the `ptrace` platform will
often yield better performance than KVM. If you still want to use KVM within a
virtual machine, you will need to make sure that nested virtualization is
configured. Here are links to documents on how to set up nested virtualization
in several popular environments:

*   Google Cloud: [Enabling Nested Virtualization for VM Instances][nested-gcp]
*   Microsoft Azure:
    [How to enable nested virtualization in an Azure VM][nested-azure]
*   VirtualBox: [Nested Virtualization][nested-virtualbox]
*   KVM: [Nested Guests][nested-kvm]

***Note: nested virtualization will have poor performance and is historically a
cause of security issues (e.g.
[CVE-2018-12904](https://nvd.nist.gov/vuln/detail/CVE-2018-12904)). It is not
recommended for production.***

## Configuring Docker

The platform is selected by the `--platform` command line flag passed to
`runsc`. By default, the ptrace platform is selected. For example, to select the
KVM platform, modify your Docker configuration (`/etc/docker/daemon.json`) to
pass the `--platform` argument:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--platform=kvm"
            ]
       }
    }
}
```

You must restart the Docker daemon after making changes to this file, typically
this is done via `systemd`:

```shell
$ sudo systemctl restart docker
```

Note that you may configure multiple runtimes using different platforms. For
example, the following configuration has one configuration for ptrace and one
for the KVM platform:

```json
{
    "runtimes": {
        "runsc-ptrace": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--platform=ptrace"
            ]
        },
        "runsc-kvm": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--platform=kvm"
            ]
        }
    }
}
```

[Production guide]: ../production/
[nested-azure]: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/nested-virtualization
[nested-gcp]: https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances
[nested-virtualbox]: https://www.virtualbox.org/manual/UserManual.html#nested-virt
[nested-kvm]: https://www.linux-kvm.org/page/Nested_Guests
