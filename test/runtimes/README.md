# Runtime Tests

This directory contains standardized runtime tests. For instructions on running
specific runtime tests, see `make help` in the top-level directory.

## Testing Locally

To run runtime tests individually, you can use the following:

```bash
bazel run --test_sharding_strategy=disabled //test/runtimes:RUNTIME -- --runtime=master --filter=TEST
```

## Extending Runtime Tests

There are 3 components to this tests infrastructure:

-   [`runner`](runner) - This is the test entrypoint. This is the binary is
    invoked by `bazel test`. The runner spawns the target runtime container
    using `runsc` and then copies over the `proctor` binary into the container.
-   [`proctor`](proctor) - This binary acts as our agent inside the container
    which communicates with the runner and actually executes tests.
-   [`exclude`](exclude) - Holds a CSV file for each language runtime containing
    the full path of tests that should be excluded from running along with a
    reason for exclusion.
