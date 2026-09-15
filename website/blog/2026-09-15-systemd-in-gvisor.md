# Full-system containers in gVisor with systemd and GNOME

As an OCI runtime, gVisor is traditionally used to sandbox application containers containing a single service.
These containers have little to no userspace running in them except the service itself.
While this is great for efficiency and scalability, there are some use cases that can benefit from having
something closer to a full Linux system inside the sandbox, with a "normal" service manager and system daemons.

Runsc has now gained experimental support for running systemd in a gVisor sandbox.
To this end, support for a handful of major new kernel APIs have been added to gVisor, including:
- The [new mount API](https://lwn.net/Articles/759499/),
- [Cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html),
- [Pidfds](https://lwn.net/Articles/794707/),
- POSIX ACL support for `tmpfs` and `overlayfs`,
- The [openat2(2)](https://lwn.net/Articles/796868/) system call,

along with numerous smaller features and bug fixes.

Systemd has been tested to work in full-system gVisor containers with Ubuntu, Debian, and Red Hat's
[Universal Base Images](https://catalog.redhat.com/en/software/base-images).

This opens up some interesting new use cases.

## Sandboxed developer workstation

The Docker image in the gVisor repository's `images/systemd-user/systemd-ubuntu` sets up a full-system
Ubuntu container, configured to boot with systemd.

To run it, first add the following flags to the runsc runtime in `/etc/docker/daemon.json`.
As an example:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--in-sandbox-cgroup=v2",
                "--allow-suid"
            ]
        }
    }
}
```

Next, build and run the container:

```bash
# Clone the gVisor repository
$ git clone https://github.com/google/gvisor.git
$ cd gvisor

# Build & run the systemd-ubuntu container in gVisor
$ docker build -t systemd-ubuntu images/systemd-user/systemd-ubuntu
$ docker run --runtime=runsc --tmpfs /run --tmpfs /home:exec --privileged -d --name dev --hostname dev -p 2222:22 systemd-ubuntu
```

It is important to note that when used with gVisor, `--privileged` does _not_ give any extra
host privilege to the application running in the sandbox; gVisor _simulates_ the extra privileges
(such as capabilities) that are observed by the sandboxed application.

Inside the container:

```bash
$ docker exec -it dev bash
root@dev:/# uname -r
4.19.0-gvisor
root@dev:/# head -4 /etc/os-release
PRETTY_NAME="Ubuntu 26.04 LTS"
NAME="Ubuntu"
VERSION_ID="26.04"
VERSION="26.04 LTS (Resolute Raccoon)"
root@dev:/# systemctl status
● dev
    State: running
    Units: 180 loaded (incl. loaded aliases)
     Jobs: 0 queued
   Failed: 0 units
    Since: Mon 2026-08-10 19:29:51 UTC; 5s ago
  systemd: 259.5-0ubuntu3.3
  Tainted: unmerged-bin:old-kernel
   CGroup: /
           ├─init.scope
           │ ├─ 1 /sbin/init
           │ ├─46 bash
           │ ├─48 systemctl status
           │ └─49 "(pager)"
           └─system.slice
             ├─dbus.service
             │ └─43 @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
             ├─systemd-journald.service
             │ └─18 /usr/lib/systemd/systemd-journald
             └─systemd-logind.service
               └─44 /usr/lib/systemd/systemd-logind
```

systemd is `running` normally in gVisor, with a full-system Ubuntu container.
As a first service, let's try installing OpenSSH and creating a user:

```bash
root@dev:/# apt update && apt install -y openssh-server
root@dev:/# systemctl enable --now sshd
root@dev:/# useradd --create-home --shell $SHELL chert
root@dev:/# echo ember | passwd chert --stdin
root@dev:/# gpasswd -a chert sudo
root@dev:/# exit
```

Now on the host we can ssh into the container as if it were a normal Linux VM:

```bash
$ ssh -p 2222 chert@127.0.0.1
The authenticity of host '[127.0.0.1]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is SHA256:kwuqlPBYfgMMrxlYxtG4EOq91EzXL9AJBdadJsuA9DM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts.
chert@127.0.0.1's password: 
Last login: Mon Aug 10 19:40:46 2026 from 172.17.0.1
chert@dev:~$ 
```

This is useful, for example, as a full-system development container when the code being
worked on or its dependencies are untrusted, perhaps as part of a CI/CD pipeline.

Let's try building [CUPS](https://www.cups.org/) in our new development container. First,
let's clone the source code and install build dependencies:

```bash
chert@dev:~$ sudo apt install -y autoconf build-essential \
     avahi-daemon libavahi-client-dev \
     libssl-dev libkrb5-dev libnss-mdns libpam-dev \
     libsystemd-dev libusb-1.0-0-dev zlib1g-dev unzip
chert@dev:~$ wget 'https://github.com/OpenPrinting/cups/releases/download/v2.4.19/cups-2.4.19-source.tar.gz'
chert@dev:~$ tar xvf cups-2.4.19-source.tar.gz
chert@dev:~$ cd cups-2.4.19/
chert@dev:~/cups-2.4.19$ ./configure --with-systemd=/lib/systemd/system --libdir=/usr/lib/x86_64-linux-gnu
chert@dev:~/cups-2.4.19$ make -j$(nproc)
chert@dev:~/cups-2.4.19$ sudo make install
```

Notice that the systemd unit files have been installed:

```bash
chert@dev:~/cups-2.4.19$ sudo systemctl list-unit-files | grep cups
cups.path                                    enabled         enabled
cups-lpd@.service                            static          -
cups.service                                 enabled         enabled
system-cups.slice                            static          -
cups-lpd.socket                              disabled        enabled
cups.socket                                  enabled         enabled
chert@dev:~/cups-2.4.19$
```

And we can enable and start the CUPS service directly, as with a normal
Linux VM:

```bash
chert@dev:~/cups-2.4.19$ sudo systemctl enable --now cups
Created symlink '/etc/systemd/system/printer.target.wants/cups.service' → '/usr/lib/systemd/system/cups.service'.
Created symlink '/etc/systemd/system/multi-user.target.wants/cups.service' → '/usr/lib/systemd/system/cups.service'.
Created symlink '/etc/systemd/system/sockets.target.wants/cups.socket' → '/usr/lib/systemd/system/cups.socket'.
Created symlink '/etc/systemd/system/multi-user.target.wants/cups.path' → '/usr/lib/systemd/system/cups.path'.
chert@dev:~/cups-2.4.19$ sudo systemctl status cups
● cups.service - CUPS Scheduler
     Loaded: loaded (/usr/lib/systemd/system/cups.service; enabled; preset: enabled)
     Active: active (running) since Thu 2026-09-03 18:39:47 UTC; 4h 17min ago
 Invocation: beac14c3deb245bb9db702ee186dfbc5
TriggeredBy: ○ cups.path
             ● cups.socket
       Docs: man:cupsd(8)
   Main PID: 16097 (cupsd)
     Status: "Scheduler is running..."
      Tasks: 1 (limit: 9830)
     Memory: 2.3M
     CGroup: /system.slice/system-cups.slice/cups.service
             └─16097 /usr/sbin/cupsd -l

Sep 03 18:39:47 dev systemd[1]: Starting cups.service - CUPS Scheduler...
Sep 03 18:39:47 dev systemd[1]: Started cups.service - CUPS Scheduler.
```

### GNOME in gVisor

We're not just limited to using the command-line in our sandboxed developer workstation,
though. While hosting a full-system container, gVisor can now run full a full sandboxed
desktop environment. To showcase this, let's set up a gVisor container with the popular
[GNOME](https://www.gnome.org/) desktop environment.

The gVisor repository contains the Docker image `images/systemd-user/systemd-debian-gnome`
for this purpose. In the gVisor repository we cloned earlier:

```bash
# Build & run the systemd-debian-gnome container in gVisor
$ docker build -t systemd-debian-gnome images/systemd-user/systemd-debian-gnome
$ docker run -d --name gnome --runtime=runsc --privileged -p 127.0.0.1:3389:3389 systemd-debian-gnome
```

The sandboxed GNOME workstation is exposed through RDP on port 3389, which can be accessed using
an RDP client such as [Remmina](https://remmina.org/) by connecting to `127.0.0.1:3389`.
The default username/password is `gnome:gnome`.

<figure class="img-100pct">
<img src="/assets/images/2026-09-15-systemd-in-gvisor/gnome-in-gvisor.png" alt="GNOME running in gVisor.">
</figure>

We can even browse the web in the sandbox:

<figure class="img-100pct">
<img src="/assets/images/2026-09-15-systemd-in-gvisor/chrome-in-gvisor.png" alt="Google Chrome running on GNOME in gVisor, showing the gVisor homepage.">
</figure>

Or, to go full circle, we can develop gVisor inside of gVisor:

<figure class="img-100pct">
<img src="/assets/images/2026-09-15-systemd-in-gvisor/vscode-in-gvisor.png" alt="VSCode running on GNOME in gVisor, with the gVisor source code open.">
</figure>

### Other distributions

In addition to Debian-based distributions, RHEL-based images work too.
For example:

```bash
$ docker run --runtime=runsc --privileged --name dev-rhel --hostname dev-rhel registry.access.redhat.com/ubi10/ubi-init
$ docker exec -it dev-rhel bash
[root@dev-rhel /]# uname -r
4.19.0-gvisor
[root@dev-rhel /]# head -2 /etc/os-release 
NAME="Red Hat Enterprise Linux"
VERSION="10.2 (Coughlan)"
[root@dev-rhel /]# systemctl status
● dev-rhel
    State: running
    Units: 119 loaded (incl. loaded aliases)
     Jobs: 0 queued
   Failed: 0 units
    Since: Fri 2026-09-04 19:57:08 UTC; 7min ago
  systemd: 257-23.el10_2.2-g009f2a8
  Tainted: old-kernel
   CGroup: /
           ├─init.scope
           │ ├─ 1 /sbin/init
           │ ├─54 bash
           │ ├─68 systemctl status
           │ └─69 "(pager)"
           └─system.slice
             └─systemd-journald.service
               └─14 /usr/lib/systemd/systemd-journald
[root@dev-rhel /]# 
```

## Ansible

[Ansible](https://www.redhat.com/en/technologies/management/ansible) is a tool for provisioning
and deploying software. Many Ansible roles expect a full Linux system, with a running service manager
(like systemd). This presents a problem for testing, since CI pipelines can be difficult to keep
secure, and native containers running systemd often require large amounts of privilege.

Full-system containers with gVisor sidestep this problem by allowing a VM-like container to be
provisioned for each test run. Multiple gVisor containers can be run on a single host without sharing
a kernel, making this setup much more secure.

To demonstrate, let's do a test run of [Jeff Geerling](https://github.com/geerlingguy)'s
[nginx role](https://github.com/geerlingguy/ansible-role-nginx), which installs nginx and
starts it as a systemd service, in gVisor.

Let's continue in our `dev` container we created earlier:

```bash
$ ssh -p 2222 chert@127.0.0.1
chert@dev:~$ sudo apt install -y ansible git
...
chert@dev:~$ sudo git clone https://github.com/geerlingguy/ansible-role-nginx /etc/ansible/roles/geerlingguy.nginx
chert@dev:~$ cat > playbook.yml <<'EOF'
---
- name: Install nginx with geerlingguy.nginx
  hosts: all
  become: true

  pre_tasks:
    - name: Update apt cache.
      ansible.builtin.apt:
        update_cache: true
        cache_valid_time: 600
      changed_when: false

  roles:
    - role: geerlingguy.nginx
EOF
chert@dev:~$ sudo ansible-playbook -i localhost, -c local playbook.yml

PLAY [Install nginx with geerlingguy.nginx] **************************

TASK [Gathering Facts] ***********************************************
[WARNING]: Host 'localhost' is using the discovered Python interpreter at '/usr/bin/python3.14', but future installation of another Python interpreter could cause a different interpreter to be discovered. See https://docs.ansible.com/ansible-core/2.20/reference_appendices/interpreter_discovery.html for more information.
ok: [localhost]

TASK [Update apt cache.] *********************************************
ok: [localhost]

TASK [geerlingguy.nginx : Include OS-specific variables.] ************
ok: [localhost]

TASK [geerlingguy.nginx : Define nginx_user.] ************************
ok: [localhost]

TASK [geerlingguy.nginx : include_tasks] *****************************
skipping: [localhost]

TASK [geerlingguy.nginx : include_tasks] *****************************
included: /etc/ansible/roles/geerlingguy.nginx/tasks/setup-Ubuntu.yml for localhost
...
chert@dev:~$
```

Now that the playbook has run and installed nginx, observe that systemd is managing nginx just like
on a normal Linux VM:

```bash
chert@dev:~$ sudo systemctl status nginx
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: enabled)
     Active: active (running) since Fri 2026-09-04 21:11:21 UTC; 1min 10s ago
 Invocation: f42bafe5b01a412f8c8a961eec0cf957
       Docs: man:nginx(8)
    Process: 2397 ExecStartPre=/usr/sbin/nginx -t -q -g daemon on; master_process on; (code=exited, status=0/SUCCESS)
    Process: 2398 ExecStart=/usr/sbin/nginx -g daemon on; master_process on; (code=exited, status=0/SUCCESS)
    Process: 2437 ExecReload=/usr/sbin/nginx -g daemon on; master_process on; -s reload (code=exited, status=0/SUCCESS)
   Main PID: 2400 (nginx)
      Tasks: 9 (limit: 9830)
     Memory: 24.5M
     CGroup: /system.slice/nginx.service
             ├─2400 "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"
             ├─2439 "nginx: worker process"
             ├─2440 "nginx: worker process"
             ├─2441 "nginx: worker process"
             ├─2442 "nginx: worker process"
             ├─2443 "nginx: worker process"
             ├─2444 "nginx: worker process"
             ├─2445 "nginx: worker process"
             └─2446 "nginx: worker process"

Sep 04 21:11:21 dev systemd[1]: Starting nginx.service - A high performance web server and a reverse proxy server...
Sep 04 21:11:21 dev systemd[1]: Started nginx.service - A high performance web server and a reverse proxy server.
Sep 04 21:11:23 dev systemd[1]: nginx.service: Failed to get CPU usage: No such file or directory
Sep 04 21:11:23 dev systemd[1]: Reloading nginx.service - A high performance web server and a reverse proxy server...
Sep 04 21:11:23 dev nginx[2437]: 2026/09/04 21:11:23 [notice] 2437#2437: signal process started
Sep 04 21:11:23 dev systemd[1]: Reloaded nginx.service - A high performance web server and a reverse proxy server.
Sep 04 21:12:32 dev systemd[1]: nginx.service: Failed to get CPU usage: No such file or directory
chert@dev:~$
```

And nginx responds to web traffic normally:

```
chert@dev:~$ curl http://127.0.0.1
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
chert@dev:~$
```

gVisor's
[integration test suite](https://github.com/google/gvisor/blob/master/test/e2e/systemd_test.go)
tests a number of other popular services under systemd, including Apache,
PostgreSQL, MariaDB, Redis, and Docker.

## Sandboxed agentic desktop access

gVisor's ability to run full-system containers opens up an interesting extension to
an earlier post,
[Multi-Agent gVisor Isolation (MAGI)](https://gvisor.dev/blog/2026/04/15/magi-multi-agent-gvisor-isolation/).
MAGI demoed sandboxing AI agents in gVisor with [OpenClaw](https://openclaw.ai/).

By inserting a small MCP server between OpenClaw and a GNOME container like the one
we created earlier, we can give our OpenClaw agents the ability to use a full Linux
desktop as a tool, with a virtual mouse and keyboard as input devices.

First, start by following the "Basic machine setup" section of the MAGI post, creating
a GPU VM instance and installing Docker, gVisor, and the NVIDIA drivers. There are two
modifications required:

1. When using ssh to access the instance, use the following port forwards: `-L 18789:127.0.0.1:18789 -L 3389:127.0.0.1:3389 -L 11434:127.0.0.1:11434`.
2. When running `runsc install`, add the following additional flags: `--in-sandbox-cgroup=v2 --allow-suid`.

Next, let's install [Ollama](https://ollama.com/) for local inference:

```bash
$ docker run -d --runtime=runsc --restart=always --name=ollama \
      --gpus=all \
      --mount=type=volume,src=ollama-data,dst=/root \
      --env=OLLAMA_FLASH_ATTENTION=1 \
      --env=OLLAMA_KV_CACHE_TYPE=q8_0 \
      -p 127.0.0.1:11434:11434 \
      ollama/ollama:latest

$ # Fetch qwen3 model
$ docker exec ollama ollama pull qwen3-vl:30b-a3b-instruct
```

Build and run the GNOME image on the GPU instance:

```bash
# Clone the gVisor repository
$ git clone https://github.com/google/gvisor.git
$ cd gvisor

# Build & run the systemd-debian-gnome container in gVisor
$ docker build -t systemd-debian-gnome images/systemd-user/systemd-debian-gnome
$ docker run -d --name gnome --runtime=runsc --privileged -p 127.0.0.1:3389:3389 systemd-debian-gnome
```

At this point, it is a good idea to use an RDP client to access the container
as we did earlier to verify that GNOME is working properly before continuing.

Now, let's build the proof-of-concept GNOME MCP server, which we will run alongside
GNOME and OpenClaw:

```bash
$ # Build & run gnome-mcp
$ docker build -t gnome-mcp images/systemd-user/gnome-mcp
$ mkdir -p ~/stack/openclaw/config ~/stack/openclaw/home/workspace/screenshots
$ docker run --detach --name=gnome-mcp --runtime=runsc --restart=always \
      --link=gnome:gnome --shm-size=512m \
      -p 127.0.0.1:8931:8931 \
      -v "$HOME/stack/openclaw/home/workspace/screenshots":/shots \
      gnome-mcp

$ # Build & run OpenClaw
$ cp images/systemd-user/gnome-mcp/openclaw.json ~/stack/openclaw/config/
$ cp images/systemd-user/gnome-mcp/AGENTS.md ~/stack/openclaw/home/workspace/
$ sudo chown -R 1000:1000 ~/stack/openclaw
$ sudo chmod 777 ~/stack/openclaw/home/workspace/screenshots
$ docker run --detach --name=openclaw --runtime=runsc --restart=always \
      --env=OPENCLAW_GATEWAY_TOKEN="dummy-token-for-sandbox" \
      --env=OPENCLAW_CONFIG_PATH="/etc/openclaw/openclaw.json" \
      --env=OLLAMA_API_KEY="ollama-local" \
      --env=OPENCLAW_SKIP_ONBOARDING=1 \
      --env=HOME=/home/node \
      -p 127.0.0.1:18789:18789 \
      --link=ollama:ollama --link=gnome-mcp:gnome-mcp \
      -v "$HOME/stack/openclaw/home":/home/node/.openclaw \
      -v "$HOME/stack/openclaw/config":/etc/openclaw \
      ghcr.io/openclaw/openclaw:2026.9.4 \
      node dist/index.js gateway --bind=lan --port=18789 --allow-unconfigured --verbose
```

In a browser, navigate to `http://127.0.0.1:18789/` and log in using the gateway secret
from above: `dummy-token-for-sandbox`. We've now logged into OpenClaw.

As an example, let's ask the agent to fetch the running Linux distribution. Enter

> Open the Settings app and tell me what Linux distribution the environment
> is running.

at the prompt. After a couple minutes, the agent has successfully fetched the version
as `Debian GNU/Linux 13 (trixie)`:

<figure class="img-100pct">
<img src="/assets/images/2026-09-15-systemd-in-gvisor/gnome-version-openclaw.png" alt="An OpenClaw session where the agent has fetched the running version of Debian and sent a screenshot of the settings page as proof.">
</figure>

Let's try a more complicated example:

> Use `apt` in the terminal to install LibreOffice, then open LibreOffice Calc and create a basic example finances spreadsheet. The sudo password is `gnome`.

<figure class="img-100pct">
<img src="/assets/images/2026-09-15-systemd-in-gvisor/libreoffice-calc-openclaw.png" alt="An OpenClaw session where the agent has installed LibreOffice and created a spreadsheet template.">
</figure>

The agent was successfully able to install LibreOffice and created a spreadsheet template
three columns, all within a gVisor sandbox! (This is also an easy way of showing that
LibreOffice works in gVisor).

Looking at the reasoning trace, we can see that the agent is clearly able to reason
about how to navigate the GUI:

```
I'll help you install LibreOffice and create a basic finances spreadsheet. Let's start by opening a terminal to install LibreOffice using apt.

## Tool (2026-09-15T21:50:28.164Z)

pressed super; screen changed

## Tool (2026-09-15T21:50:34.036Z)

I need to open a terminal to install LibreOffice. Let me search for the terminal application.

## Tool (2026-09-15T21:50:36.072Z)

typed 'terminal'; screen changed

## Tool (2026-09-15T21:50:42.369Z)

Now that I've found the terminal application, I'll click on it to open the terminal.

## Tool (2026-09-15T21:50:45.091Z)

clicked left at (500, 281); screen changed

## Tool (2026-09-15T21:50:53.059Z)

I see that we're still in the Settings application, but we need to get back to the desktop to open the terminal. Let me close the Settings window and return to the desktop.

## Tool (2026-09-15T21:50:55.183Z)

clicked left at (861, 148); screen changed

## Tool (2026-09-15T21:51:03.558Z)

Great! Now I have a terminal open. Let's proceed with installing LibreOffice using the apt package manager. I'll need to use sudo to install the software, so I'll run the installation command with the sudo password.

## Tool (2026-09-15T21:51:06.520Z)

typed 'sudo apt update && sudo apt install -y libreoffice'; screen changed

## Tool (2026-09-15T21:51:13.995Z)

Now that I've entered the command to install LibreOffice, I need to execute it. The command is ready in the terminal, so I'll press Enter to run it.

## Tool (2026-09-15T21:51:16.429Z)

pressed Return; screen changed

...
```

