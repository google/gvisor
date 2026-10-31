# Changing Platforms

[TOC]

This guide describes how to change the
[platform](../architecture_guide/platforms.md) used by `runsc`.

Configuring the platform provides significant performance benefits, but isn't
the only step to optimizing gVisor performance. See the [Production guide] for
more.

## Prerequisites

If you intend to run the KVM platform, you will also need to have KVM installed
on your system. If you are running a Debian based system like Debian or Ubuntu
you can usually do this by ensuring the module is loaded, and your user has
permissions to access the `/dev/kvm` device. Usually, this means that your user
is in the `kvm` group.

```shell
# Check that /dev/kvm is owned by the kvm group
$ ls -l /dev/kvm
crw-rw----+ 1 root kvm 10, 232 Jul 26 00:04 /dev/kvm

# Make sure that the current user is part of the kvm group
$ groups | grep -qw kvm && echo ok
ok
```

**For best performance, use the KVM platform on bare-metal machines only**. If
you have to run gVisor within a virtual machine, the `systrap` platform will
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

A third platform, `ptrace`, also has the versatility of running on any
environment. However, it has higher performance overhead than `systrap` in
almost all cases. `systrap` replaced `ptrace` as the default platform in
mid-2023. While `ptrace` continues to exist in the codebase, it is no longer
supported and is expected to eventually be removed entirely. If you depend on
`ptrace`, and `systrap` doesn't fulfill your needs, please
[voice your feedback](../community.md).

## Clock source

The default `--clock-source=calibrated` mode derives application time from
hardware counters calibrated against the host clocks. It requires counters
that remain synchronized across every CPU on which the sandbox can run,
including after CPU migration or hotplug. A constant counter frequency alone
does not guarantee synchronization.

Use `--clock-source=reference` when the host cannot provide that counter
contract. The Sentry reads the host clocks directly, and application VDSO clock
reads fall back to system calls into the Sentry. This adds overhead to clock
reads but leaves syscall transport and CPU affinity unchanged. It applies to
both the KVM and systrap platforms; it is not selected automatically from the
hypervisor or clocksource name.

Clock selection follows the runtime configuration used to restore a sandbox.
Configure the destination's clock source explicitly; saved calibration does
not select the source on the destination. The existing sandbox monotonic-time
offset and optional distinct `CLOCK_MONOTONIC_RAW` behavior are preserved.

## Configuring Docker

The platform is selected by the `--platform` command line flag passed to
`runsc`. By default, the `systrap` platform is selected. For example, to select
the KVM platform, modify your Docker configuration (`/etc/docker/daemon.json`)
to pass the `--platform` argument:

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
example, the following configuration has one configuration for systrap and one
for the KVM platform:

```json
{
    "runtimes": {
        "runsc-kvm": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--platform=kvm"
            ]
        },
        "runsc-systrap": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--platform=systrap"
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
