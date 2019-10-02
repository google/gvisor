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
-   **root:** tests that require to be run as root.
-   **util:** utilities library to support the tests.

For the above noted cases, the relevant runtime must be installed via `runsc
install` before running. This is handled automatically by the test scripts in
the `kokoro` directory.
