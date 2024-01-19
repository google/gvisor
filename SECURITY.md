# Security and Vulnerability Reporting

Sensitive security-related questions, comments, and reports should be sent to
the [gvisor-security mailing list][gvisor-security-list]. You should receive a
prompt response, typically within 48 hours.

## Security issue taxonomy

We distinguish the following type of issues, listed from most to least severe:

-   Issues that go **beyond the sandbox boundary**:
    -   **Container escapes**: Issues that allow arbitrary code to run on the
        host machine.
        -   gVisor's purpose is to prevent these.
    -   **Data exfiltration** from the host: Issues that allow reading arbitrary
        files or file metadata from the host (other than those intended to be
        visible to the sandbox).
    -   **Sandbox-to-sandbox lateral movement**: Issues that allow arbitrary
        code execution in a different sandbox on the same host.
    -   **Denial-of-service attacks** that affect **the host kernel** (i.e.
        trigger a host kernel panic).
    -   **Denial-of-service attacks** that affect **other sandboxes on the same
        host**.
        -   This excludes things like causing CPU starvation when a sandbox is
            running without resource constraints.
-   Issues that **remain confined to a single sandbox**:
    -   **Denial-of-service attacks** that affect a single sandbox and are
        **triggerable remotely** (e.g. by sending a specially-crafted network
        packet).
    -   **Privilege escalation within the sandbox** (e.g. being able to do what
        in-sandbox `root` would be able to do from an in-sandbox non-`root`
        user).
    -   **Denial-of-service attacks** that affect a single sandbox and are
        **triggerable from user code** running in that sandbox.
    -   **Data integrity issues** relative to Linux behavior.
        -   gVisor aims to be bug-for-bug compatible with Linux. While most
            compatibility issues are not security issues, it is conceivable that
            some compatibility issues may manifest as persistent data
            corruption; for example, differences in I/O syscall implementations
            may cause a database program to end up storing invalid data.

While all of the above are security issues, we generally only assign CVEs for
issues that go beyond the sandbox boundary. Since gVisor is a container security
platform, its main security focus is on preventing a user workload from "getting
out of the box", relative to issues that remain within the proverbial box.
Therefore, security issues that remain contained to a single sandbox are not
considered critical and are not given CVE numbers by default. If you would still
like to get a CVE number issued, you may report it to
[BugHunter](https://g.co/vulnz).

## Security list access

Policies for security list access, vulnerability embargo, and vulnerability
disclosure are outlined in the [governance policy](GOVERNANCE.md).

[gvisor-security-list]: https://groups.google.com/forum/#!forum/gvisor-security
