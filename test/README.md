# Tests

The tests defined under this path are verifying functionality beyond what unit
tests can cover, e.g. integration and end to end tests. Due to their nature,
they may need extra setup in the test machine and extra configuration to run.

-   **integration:** defines integration tests that uses `docker run` to test
    functionality.
-   **image:** basic end to end test for popular images.
-   **runtimes:** tests for popular language runtimes.
-   **root:** tests that require to be run as root.
-   **testutil:** utilities library to support the tests.

The following setup steps are required in order to run these tests:

     `./test/install.sh [--runtime <name>]`

The tests expect the runtime name to be provided in the `RUNSC_RUNTIME`
environment variable (default: `runsc-test`). To run the tests execute:

```
bazel test --test_env=RUNSC_RUNTIME=runsc-test \
  //test/image:image_test \
  //test/integration:integration_test
```
