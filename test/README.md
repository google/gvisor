# Tests

The tests defined under this path are verifying functionality beyond what unit
tests can cover, e.g. integration and end to end tests. Due to their nature,
they may need extra setup in the test machine and extra configuration to run.

-   **syscalls**: system call tests use a local runner, and do not require
    additional configuration in the machine.
-   **integration:** defines integration tests that uses `docker run` to test
    functionality.
-   **image:** basic end to end test for popular images. These require the same
    setup as integration tests.
-   **root:** tests that require to be run as root. These require the same setup
    as integration tests.
-   **util:** utilities library to support the tests.

For the above noted cases, the relevant runtime must be installed via `runsc
install` before running. Just note that they require specific configuration to
work. This is handled automatically by the test scripts in the `scripts`
directory and they can be used to run tests locally on your machine. They are
also used to run these tests in `kokoro`.

**Example:**

To run image and integration tests, run:

`./scripts/docker_test.sh`

To run root tests, run:

`./scripts/root_test.sh`

There are a few other interesting variations for image and integration tests:

*   overlay: sets writable overlay inside the sentry
*   hostnet: configures host network pass-thru, instead of netstack
*   kvm: runsc the test using the KVM platform, instead of ptrace

The test will build runsc, configure it with your local docker, restart
`dockerd`, and run tests. The location for runsc logs is printed to the output.
