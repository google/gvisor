# Security and Vulnerability Reporting

Sensitive security-related questions, comments, and reports should be sent to
the gvisor-security@googlegroups.com
([gvisor-security mailing list][gvisor-security-list]). You should receive a
prompt response, typically within 48 hours.

## Which issues get CVEs?

In general, we only assign CVEs for issues that meet all of the criteria:

-   The issue must generally **cross the sandbox boundary**.
-   The issue occurs in a context where the **attacker does not initially
    control the sandbox configuration**.
-   The issue must be **gVisor-specific** (i.e. the same issue would not occur
    in a non-gVisor sandbox).

Since gVisor is a container security platform, its main security focus is on
preventing a user workload from "getting out of the box", relative to issues
that remain within the proverbial box. Therefore, security issues that remain
contained to a single sandbox are generally not considered critical and are not
given CVE numbers by default. If you would still like to get a CVE number
issued, you may report it to [BugHunter](https://g.co/vulnz).

### Security issues in gVisor-the-project vs issues in production deployments using gVisor

gVisor is an open-source sandboxing solution meant to be generally useful, and
this document describes its policy for reporting security vulnerabilities
relevant to that context. This is why many categories of security issues are not
relevant from gVisor-the-project's perspective. However, gVisor is also used in
[many production contexts](https://gvisor.dev/users), which may have their own
security vulnerability disclosure programs that may accept gVisor
*misconfigurations* or incomplete policies as being security incidents from
their perspective.

For example, while gVisor-the-project's security policy considers control over a
sandbox's OCI spec as largely out-of-scope from gVisor's perspective, some
managed Kubernetes environments such as
[GKE Sandbox](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
under
[Autopilot](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/autopilot-security)
rely on gVisor and enforce some security policies on the `PodSpec` that
ultimately ends up being provided to gVisor. Therefore, a vulnerability that
would not be considered a CVE for gVisor-the-project as per this security policy
may still be considered a vulnerability in that gVisor production deployment.

**What this means for you**: If you find a security flaw in a gVisor-sandboxed
environment, consider whether the security vulnerability generally exists in
gVisor itself or whether it is specific to the production deployment of gVisor
where you have found this vulnerability, and route your report accordingly.

The rest of this policy assumes that you have made the assertion that the
security issue affects gVisor in general.

### Security issue taxonomy

We distinguish the following type of issues, listed from most to least severe:

-   Issues that go **beyond the sandbox boundary**:
    -   `Escape`: **Container escapes**. Issues that allow arbitrary code to run
        on the host machine.
        -   gVisor's purpose is to prevent these.
    -   `HostLeak`: **Host data access**. Issues that allow reading arbitrary
        files or file metadata from the host other than those *intended* to be
        visible to the sandbox.
    -   `Exfil`: **Data exfiltration**. Issues that allow sending data outside
        of the sandbox in ways that the sandbox configuration was meant to
        protect against.
        -   This includes writes to arbitrary unexposed host directories, or
            outbound network connections when sandbox networking is disabled.
    -   `Lateral`: **Sandbox-to-sandbox lateral movement**. Issues that allow an
        attacker to execute arbitrary code execution in a sandbox on the same
        host other than the one they started with.
    -   `HostDoS`: **Denial-of-service attacks** that affect **the host kernel**
        (e.g. trigger a host kernel panic).
    -   `PeerDoS`: **Denial-of-service attacks** that affect **other sandboxes
        on the same host**.
        -   This excludes things like causing CPU starvation when a sandbox is
            running without resource constraints.
-   Issues that **remain confined to a single sandbox**:
    -   `InternalEsc`: **Privilege escalation within the sandbox** (e.g. being
        able to do what in-sandbox `root` would be able to do from an in-sandbox
        non-`root` user).
    -   `SelfDoS`: **Denial-of-service attacks** that affect a single sandbox
        and are **triggerable from user code** running in that sandbox.
    -   `Integrity`: **Data integrity issues** relative to Linux behavior.
        -   gVisor aims to be bug-for-bug compatible with Linux. While most
            compatibility issues are not security issues, it is conceivable that
            some compatibility issues may manifest as persistent data
            corruption; for example, differences in I/O syscall implementations
            may cause a database program to end up storing invalid data.

### Attacker prerequisites

We distinguish the following levels of prerequisites surrounding the level of
initial access and privileges that the attacker may start with, from
least-privileged to most-privileged:

*   `Remote`: Control over **incoming traffic into the sandbox**. Attacker does
    not have control over the sandbox, but can open network connections to its
    network stack.
*   `SandboxUser`: Control over **non-root process in sandbox**. Attacker has
    control over a process running as non-root user within the sandbox (i.e. can
    cause this process to execute arbitrary code), but not over other in-sandbox
    processes, nor how the sandbox is configured or resource-restricted on the
    host.
*   `SandboxRoot`: Control over **sandboxed workload**. Attacker has root inside
    the sandbox (i.e. can cause any in-sandbox process to execute arbitrary code
    as root), but not how the sandbox is configured or resource-restricted on
    the host.
    -   `SandboxRoot` implies `SandboxUser`, as root-in-sandbox is able to
        impersonate every other in-sandbox user.
*   `SandboxImage`: Control over **container image**. Attacker has control over
    the root filesystem image used inside the sandbox, but no other bits of
    configuration. Implies `SandboxRoot`.
    -   This does **not** mean the user can change the *path* of the extracted
        root filesystem image specified in the OCI spec; only its contents on
        the host filesystem.
    -   The set of container image customizations under this definition are
        limited to those that can be successfully bundled and distributed as OCI
        images, downloaded over the network, and extracted into an `ext4`
        filesystem.
    -   `SandboxImage` implies `SandboxRoot`, as controlling the image allows
        adding `setuid` binaries and overwriting the workload's default binary
        to execute arbitrary code as root in the sandbox.
*   `SandboxSpec`: Control over **OCI spec configuration**. Attacker has control
    over the OCI spec that the sandbox uses. This includes control over host
    mountpoints beyond the root filesystem image, as well as resource limits.
    -   `SandboxSpec` implies `SandboxImage`, as the image is part of the spec
        and can be pointed to an attacker-controlled image name.
*   `RuntimeFlags`: Control over **gVisor runtime configuration**. Attacker has
    control over the set of flags that is used when starting *any* gVisor
    sandbox on the host.
    -   `RuntimeFlags` implies `SandboxSpec`, as runtime flags can affect
        gVisor's security measures and the finalized per-sandbox configuration.
*   `HostRoot`: Control over **host**. Attacker has full control over the host
    that sandboxes run on.
    -   `HostRoot` implies `RuntimeFlags`, since root can change the runtime
        configuration at will.

### Security issues in scope for CVEs

The following table lists the types of issues that qualify for CVEs, provided
that they are gVisor-specific (i.e. the same issue does not occur in a
non-gVisor sandbox):

**CVE?**      | `Remote` | `SandboxUser` | `SandboxRoot` | `SandboxImage` | `SandboxSpec` | `RuntimeFlags` | `HostRoot`
------------- | -------- | ------------- | ------------- | -------------- | ------------- | -------------- | ----------
`Integrity`   | ✔️       | ❌             | ❌             | ❌              | ❌             | ❌              | ❌
`SelfDoS`     | *N/A*    | ❌             | ❌             | ❌              | ❌             | ❌              | ❌
`InternalEsc` | *N/A*    | ✔️            | *N/A*         | ❌              | ❌             | ❌              | ❌
`PeerDoS`     | ✔️       | ✔️            | ✔️            | ✔️             | ❌             | ❌              | ❌
`HostDoS`     | ✔️       | ✔️            | ✔️            | ✔️             | ❌             | ❌              | ❌
`Lateral`     | *N/A*    | ✔️            | ✔️            | ❌              | ❌             | ❌              | ❌
`Exfil`       | ✔️       | ✔️            | ✔️            | ✔️             | ❌             | ❌              | ❌
`HostLeak`    | ✔️       | ✔️            | ✔️            | ✔️             | ❌             | ❌              | ❌
`Escape`      | ✔️       | ✔️            | ✔️            | ✔️             | ❌             | ❌              | ❌

### Examples of vulnerability classifications

-   An attacker running as root in a sandbox (that they don't control the
    configuration of) can execute arbitrary code on the host.
    -   **Classification**: `SandboxRoot / Escape`.
    -   **CVE**: ✔️ Yes. This is the primary scenario that gVisor aims to
        protect against.
-   An attacker running as root in a sandbox (that they don't control the
    configuration of) can read an arbitrary file on the host.
    -   **Classification**: `SandboxRoot / HostLeak`.
    -   **CVE**: ✔️ Yes.
-   An attacker can configure a sandbox to mount an arbitrary directory on the
    host, then read its files from inside the sandbox.
    -   **Classification**: `SandboxSpec / HostLeak`.
    -   **CVE**: ❌ No. Exposing host files to the sandbox via configured mounts
        and the sandbox being able to read them is intended behavior.
    -   However, if the production environment in which this exploit may be
        pulled off was not meant to allow host files to be read in this manner
        even by containers where users have control over the OCI spec, then
        consider reporting this as a security vulnerability for that production
        environment.
-   An attacker running as a non-privileged user in a sandbox can allocate more
    memory than the sandbox is allowed to use, causing the sandbox to crash.
    -   **Classification**: `SandboxUser / SelfDoS`.
    -   **CVE**: ❌ No, since the extent of the damage is limited to the sandbox
        the attacker runs in.
-   An attacker running in a sandbox can cause the blind removal of a critical
    file on the host filesystem (such as `/etc/passwd`) preventing
    administrative SSH logins to the host.
    -   **Classification**: `SandboxRoot / HostDoS`.
    -   **CVE**: ✔️ Yes.
-   An attacker exposes the host's `/var/run/docker.sock` UDS within a sandbox,
    then creates unsandboxed containers by using this UDS.
    -   **Classification**: `SandboxConf / Escape`.
    -   **CVE**: ❌ No. While the attacker is able to get out of the sandbox,
        they required access to the host's `/var/run/docker.sock` to do so,
        which secure deployments of gVisor do not expose. Additionally, running
        the same container with `runc` allows for container escape in the same
        manner.
-   An attacker is able to cause a sandbox (not a process within the sandbox) to
    crash by sending it specially-crafted network packets from another host.
    -   **Classification**: `Remote / PeerDoS`.
    -   **CVE**: ✔️ Yes.
-   An attacker running as root in a specific sandbox is able to cause a
    different sandbox on the same host to reliably crash.
    -   **Classification**: `SandboxRoot / PeerDoS`.
    -   **CVE**: ✔️ Yes.
-   An attacker running as an unprivileged user in a sandbox is able to read or
    write to a file that only root-in-sandbox should have been able to access.
    -   **Classification**: `SandboxUser / InternalEsc`.
    -   **CVE**: ✔️ Yes.
-   An attacker controlling the contents of the root filesystem image is able to
    call a SUID binary within the root filesystem image and escalate from
    unprivileged user to root-in-sandbox.
    -   **Classification**: `SandboxImage / InternalEsc`.
    -   **CVE**: ❌ No. The attacker is in control of the image, so they could
        just as well have modified its payload to execute whatever they wanted
        in the sandbox to begin with.
-   An attacker **not** controlling the contents of the root filesystem image is
    able to call a SUID binary within the root filesystem image and escalate
    from unprivileged user to root-in-sandbox.
    -   **Classification**: `SandboxUser / InternalEsc`.
    -   **CVE**: ❌ Still no. The same behavior would have happened in a
        non-gVisor sandbox.
-   An attacker running as root inside a specific sandbox is able to read
    arbitrary files from a different sandbox on the same host.
    -   **Classification**: `SandboxRoot / Lateral`.
    -   **CVE**: ✔️ Yes.
-   An attacker changes the Docker daemon configuration for the `runsc` runtime
    to not actually use gVisor.
    -   **Classification**: `HostRoot / Escape`.
    -   **CVE**: ❌ No. The attacker needs root on the host to perform this
        modification, so they are already in a position to defeat any layer of
        sandboxing gVisor could provide. The ability to configure the container
        runtime to use a non-gVisor runtime is a container runtime problem, not
        a gVisor problem.
-   An attacker sets the `runsc` runtime flags to `--network=host`, then uses a
    Linux network stack exploit from inside a gVisor sandbox to escalate to root
    on the host.
    -   **Classification**: `RuntimeFlags / Escape`.
    -   **CVE**: ❌ No. The underlying security issue here is in Linux, not
        gVisor. That the attacker gains increased attack surface area to the
        kernel by modifying the gVisor runtime flags is intended behavior of the
        flags.
-   An attacker running as root inside the sandbox is able to clear out the
    host's `/etc/shadow` file, locking out the host's system administrator.
    -   **Classification**: `SandboxRoot / HostDoS`.
    -   **CVE**: ✔️ Yes.
-   An attacker running as root inside the sandbox is able to write arbitrary
    data to the host's `/srv/www/secrets.txt` file, despite none of the host
    directories being mounted into the sandbox.
    -   **Classification**: `SandboxRoot / Exfil`.
    -   **CVE**: ✔️ Yes.

## Security list access

Policies for security list access, vulnerability embargo, and vulnerability
disclosure are outlined in the [governance policy](GOVERNANCE.md).

[gvisor-security-list]: https://groups.google.com/forum/#!forum/gvisor-security

## Information you must send as part of security vulnerability reports

-   High-level summary of the issue
-   Type of issue, e.g. "sandbox escape", "DoS", ...
-   Prerequisites, e.g. "the attacker requires the ability to set these special
    flags to be set".
-   Classification code as per the above scheme (e.g. "`Sandboxed / Escape`").
-   Explanation of gVisor-specificity, aka behavior and reproducibility when
    executing the attack in an unsandboxed context, everything else being equal
    (e.g. running with `runc` instead of `runsc`).
-   Proof-of-concept code and instructions on how to run it.
-   Each email must be about a single vulnerability. If you have found multiple
    vulnerabilities, send a separate email for each of them.

Submissions to the security mailing list that do not meet these requirements may
be rejected, ignored, or have the reporters blocked after repeat offenses.
