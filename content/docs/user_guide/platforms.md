+++
title = "Platforms (KVM)"
weight = 30
+++

This document will help you set up your system to use a different gVisor
platform.

## What is a Platform?

gVisor requires a *platform* to implement basic context switching and memory
mapping functionality. These are described in more depth in the [Architecture
Guide](../../architecture_guide/).

## Selecting a Platform

The platform is selected by a `--platform` command line flag passed to `runsc`.
To select a different platform, modify your Docker configuration
(`/etc/docker/daemon.json`) to pass this argument:

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

Then restart the Docker daemon.

## Example: Using the KVM Platform

The KVM platform is currently experimental; however, it provides several
benefits over the default ptrace platform.

### Prerequisites

You will also to have KVM installed on your system. If you are running a Debian
based system like Debian or Ubuntu you can usually do this by installing the
`qemu-kvm` package.

```bash
sudo apt-get install qemu-kvm
```

If you are using a virtual machine you will need to make sure that nested
virtualization is configured. Here are links to documents on how to set up
nested virtualization in several popular environments.

 * Google Cloud: [Enabling Nested Virtualization for VM Instances][nested-gcp]
 * Microsoft Azure: [How to enable nested virtualization in an Azure VM][nested-azure]
 * VirtualBox: [Nested Virtualization][nested-virtualbox]
 * KVM: [Nested Guests][nested-kvm]

### Configuring Docker

Per above, you will need to configure Docker to use `runsc` with the KVM
platform.  You will remember from the Docker Quick Start that you configured
Docker to use `runsc` as the runtime.  Docker allows you to add multiple
runtimes to the Docker configuration.

Add a new entry for the KVM platform entry to your Docker configuration
(`/etc/docker/daemon.json`) in order to provide the `--platform=kvm` runtime
argument.

In the end, the file should look something like:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc"
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

You must restart the Docker daemon after making changes to this file, typically
this is done via `systemd`:

```bash
sudo systemctl restart docker
```

## Running a container

Now run your container using the `runsc-kvm` runtime. This will run the
container using the KVM platform:

```bash
docker run --runtime=runsc-kvm hello-world
```

[nested-azure]: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/nested-virtualization
[nested-gcp]: https://cloud.google.com/compute/docs/instances/enable-nested-virtualization-vm-instances
[nested-virtualbox]: https://www.virtualbox.org/manual/UserManual.html#nested-virt
[nested-kvm]: https://www.linux-kvm.org/page/Nested_Guests
