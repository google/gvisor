# Configuring Falco with gVisor

[TOC]

## Installation

This section explains the steps required to install Falco+gVisor integration
depending your environment.

### Docker

First, install [gVisor](/docs/user_guide/install/) and
[Falco](https://falco.org/docs/getting-started/installation/) on the machine.
Run `runsc --version` and check that `runsc version release-20220704.0` or newer
is reported. Run `falco --version` and check that `Falco version` reports
`0.33.1` or higher.

Once both are installed, you can configure gVisor to connect to Falco whenever a
new sandbox is started. The first command below generates a configuration file
containing a list of trace points that Falco is interested in receiving. This
file is passed to gVisor during container startup so that gVisor connects to
Falco *before* the application starts. The second command installs runsc as a
Docker runtime pointing it to the configuration file we just generated:

```shell
falco --gvisor-generate-config | sudo tee /etc/falco/pod-init.json
sudo runsc install --runtime=runsc-falco -- --pod-init-config=/etc/falco/pod-init.json
sudo systemctl restart docker
```

gVisor is now configured. Next, let's start Falco and tell it to enable gVisor
monitoring. You should use the same command line that you normally use to start
Falco with these additional flags:

-   `--gvisor-config`: path to the gVisor configuration file, in our case
    `/etc/falco/pod-init.json`.
-   `--gvisor-root`: path to the `--root` flag that docker uses with gVisor,
    normally: `/var/run/docker/runtime-runc/moby`.

For our example, let's just start with the default settings and rules:

```shell
sudo falco \
  -c /etc/falco/falco.yaml \
  --gvisor-config /etc/falco/pod-init.json \
  --gvisor-root /var/run/docker/runtime-runc/moby
```

> **Note:** If you get `Error: Cannot find runsc binary`, make sure `runsc` is
> in the `PATH`.

From this point on, every time a gVisor sandbox starts, it connects to Falco to
send trace points occurring inside the container. Those are translated into
Falco events that are processed by the rules you have defined. If you used the
command above, the configuration files are defined in
`/etc/falco/faco_rules.yaml` and `/etc/falco/faco_rules.local.yaml` (where you
can add your own rules).

### Kubernetes

If you are using Kubernetes, the steps above must be done on every node that has
gVisor enabled. Luckily, this can be done for you automatically using
[Falco's Helm chart](https://github.com/falcosecurity/charts/blob/master/falco/README.md).
You can find more details, like available options, in the
[*About gVisor*](https://github.com/falcosecurity/charts/blob/master/falco/README.md#about-gvisor)
section.

Here is a quick example using
[GKE Sandbox](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods),
which already pre-configures gVisor for you. You can use any version that is
equal or higher than 1.24.4-gke.1800:

```shell
gcloud container clusters create my-cluster --release-channel=rapid --cluster-version=1.25
gcloud container node-pools create gvisor --sandbox=type=gvisor --cluster=my-cluster
gcloud container clusters get-credentials my-cluster
helm install falco-gvisor falcosecurity/falco \
  -f https://raw.githubusercontent.com/falcosecurity/charts/master/falco/values-gvisor-gke.yaml \
  --namespace falco-gvisor --create-namespace
```

## Triggering Falco Events

Let's run something interesting inside a container to see a few rules trigger in
Falco. Package managers, like `apt`, don't normally run inside containers in
production, and often indicate that an attacker is trying to install tools to
expose the container. To detect such cases, the default set of rules trigger an
`Error` event when the package manager is invoked. Let's see it in action, first
start a container and run a simple `apt` command:

```shell
sudo docker run --rm --runtime=runsc-falco -ti ubuntu
$ apt update
```

In the terminal where falco is running, you should see in the output many `Error
Package management process launched` events. Here is one of the events informing
that a package manager was invoked inside the container:

```json
{
  "output": "18:39:27.542112944: Error Package management process launched in container (user=root user_loginuid=0 command=apt apt update container_id=1473cfd51410 container_name=sad_wu image=ubuntu:latest) container=1473cfd51410 pid=4 tid=4",
  "priority": "Error",
  "rule": "Launch Package Management Process in Container",
  "source": "syscall",
  "tags": [
    "mitre_persistence",
    "process"
  ],
  "time": "2022-08-02T18:39:27.542112944Z",
  "output_fields": {
    "container.id": "1473cfd51410",
    "container.image.repository": "ubuntu",
    "container.image.tag": "latest",
    "container.name": "sad_wu",
    "evt.time": 1659465567542113000,
    "proc.cmdline": "apt apt update",
    "proc.vpid": 4,
    "thread.vtid": 4,
    "user.loginuid": 0,
    "user.name": "root"
  }
}
```

As you can see, it's warning that `apt update` command was ran inside container
`sad_wu`, and gives more information about the user, TID, image name, etc. There
are also rules that trigger when there is a write under `/` and other system
directories that are normally part of the image and shouldn't be changed. If we
proceed with installing packages into the container, apart from the event above,
there are a few other events that are triggered. Let's execute `apt-get install
-y netcat` and look at the output:

```json
{
  "output": "18:40:42.192811725: Warning Sensitive file opened for reading by non-trusted program (user=root user_loginuid=0 program=dpkg-preconfigure command=dpkg-preconfigure /usr/sbin/dpkg-preconfigure --apt file=/etc/shadow parent=sh gparent=<NA> ggparent=<NA> gggparent=<NA> container_id=1473cfd51410 image=ubuntu) container=1473cfd51410 pid=213 tid=213",
  "priority": "Warning",
  "rule": "Read sensitive file untrusted",
  "source": "syscall",
  "tags": [
    "filesystem",
    "mitre_credential_access",
    "mitre_discovery"
  ],
}

{
  "output": "18:40:42.494933664: Error File below / or /root opened for writing (user=root user_loginuid=0 command=tar tar -x -f - --warning=no-timestamp parent=dpkg-deb file=md5sums program=tar container_id=1473cfd51410 image=ubuntu) container=1473cfd51410 pid=221 tid=221",
  "priority": "Error",
  "rule": "Write below root",
  "source": "syscall",
  "tags": [
    "filesystem",
    "mitre_persistence"
  ],
}
```

The first event is raised as a `Warning` when `/etc/shadow` is open by the
package manager to inform that a sensitive file has been open for read. The
second one triggers an `Error` when the package manager tries to untar a file
under the root directory. None of these actions are expected from a webserver
that is operating normally and should raise security alerts.

You can also install
[falcosidekick](https://github.com/falcosecurity/falcosidekick) and
[falcosidekick-ui](https://github.com/falcosecurity/falcosidekick-ui) for better
ways to visualize the events.

Now you can configure the rules and run your containers using gVisor and Falco.
