# gVisor Runtime Tests

These tests execute language runtime test suites inside gVisor. They serve as
high-level integration tests for the various runtimes.

## Runtime Test Components

The runtime tests have the following components:

-   [`images`][runtime-images] - These are Docker images for each language
    runtime we test. The images contain all the particular runtime tests, and
    whatever other libraries or utilities are required to run the tests.
-   [`proctor`](proctor) - This is a binary that acts as an agent inside the
    container and provides a uniform command-line API to list and run the
    various language tests.
-   [`runner`](runner) - This is the test entrypoint invoked by `bazel run`.
    This binary spawns Docker (using `runsc` runtime) and runs the language
    image with `proctor` binary mounted.
-   [`exclude`](exclude) - Holds a CSV file for each language runtime containing
    the full path of tests that should be excluded from running along with a
    reason for exclusion.

## Testing Locally

The following `make` targets will run an entire runtime test suite locally.

Note: java runtime test take 1+ hours with 16 cores.

Language | Version | Running the test suite
-------- | ------- | ----------------------------------
Go       | 1.16    | `make go1.16-runtime-tests`
Java     | 17      | `make java17-runtime-tests`
NodeJS   | 16.13.2 | `make nodejs16.13.2-runtime-tests`
Php      | 8.1.1   | `make php8.1.1-runtime-tests`
Python   | 3.10.2  | `make python3.10.2-runtime-tests`

You can modify the runtime test behaviors by passing in the following `make`
variables:

*   `RUNTIME_TESTS_FILTER`: Comma-separated list of tests to run, even if
    otherwise excluded. Useful to debug single failing test cases.
*   `RUNTIME_TESTS_PER_TEST_TIMEOUT`: Modify per-test timeout. Useful when
    debugging a test that has a tendency to get stuck, in order to make it fail
    faster.
*   `RUNTIME_TESTS_RUNS_PER_TEST`: Number of times to run each test. Useful to
    find flaky tests.
*   `RUNTIME_TESTS_FLAKY_IS_ERROR`: Boolean indicating whether tests found flaky
    (i.e. running them multiple times has sometimes succeeded, sometimes failed)
    should be considered a test suite failure (`true`) or success (`false`).
*   `RUNTIME_TESTS_FLAKY_SHORT_CIRCUIT`: If true, when running tests multiple
    times, and a test has been found flaky (i.e. running it multiple times has
    succeeded at least once and failed at least once), exit immediately, rather
    than running all `RUNTIME_TESTS_RUNS_PER_TEST` attempts.

Example invocation:

```shell
$ make php8.1.1-runtime-tests \
    RUNTIME_TESTS_FILTER=ext/standard/tests/file/bug60120.phpt \
    RUNTIME_TESTS_PER_TEST_TIMEOUT=10s \
    RUNTIME_TESTS_RUNS_PER_TEST=100
```

### Clean Up

Sometimes when runtime tests fail or when the testing container itself crashes
unexpectedly, the containers are not removed or sometimes do not even exit. This
can cause some docker commands like `docker system prune` to hang forever.

Here are some helpful commands (should be executed in order):

```bash
docker ps -a  # Lists all docker processes; useful when investigating hanging containers.
docker kill $(docker ps -a -q)  # Kills all running containers.
docker rm $(docker ps -a -q)  # Removes all exited containers.
docker system prune  # Remove unused data.
```

## Updating Runtime Tests

To bump the version of an existing runtime test:

1.  Create a new [Docker image](runtime-images) for the new runtime version.
    This will likely look similar to the older version, so start by copying the
    older one. Update any packages or downloaded urls to point to the new
    version. Test building the image with `docker build
    images/runtime/<new_runtime>`

2.  Create a new [`runtime_test`](BUILD) target. The `name` field must be the
    dirctory name for the Docker image you created in Step 1.

3.  Run the tests, and triage any failures. Some language tests are flaky (or
    never pass at all), other failures may indicate a gVisor bug or divergence
    from Linux behavior. Known or expected failures can be added to the
    [exclude](exclude) file for the new version, and they will be skipped in
    future runs.

### Cleaning up exclude files

Usually when the runtime is updated, a lot has changed. Tests may have been
deleted, modified (fixed or broken) or added. After you have an exclude list
from step 3 above with which all runtime tests pass, it is useful to clean up
the exclude files with the following steps:

1.  Check for the existence of tests in the runtime image. See how each runtime
    lists all its tests (see `ListTests()` implementations in `proctor/lib`
    directory). Then you can compare against that list and remove any excluded
    tests that don't exist anymore.
2.  Run all excluded tests with runc (native) for each runtime. If the test
    fails, we can consider the test as broken. Such tests should be marked with
    `Broken test` in the reason column. These tests don't provide a
    compatibility gap signal for gvisor. We can happily ignore them. Some tests
    which were previously broken may not be unbroken and for them the reason
    field should be cleared.
3.  Run all the unbroken and non-flaky tests on runsc (gVisor). If the test is
    now passing, then the test should be removed from the exclude list. This
    effectively increases our testing surface. Once upon a time, this test was
    failing. Now it is passing. Something was fixed in between. Enabling this
    test is equivalent to adding a regression test for the fix.
4.  Some tests are excluded and marked flaky. Run these tests 100 times on runsc
    (gVisor). If it does not flake, then you can remove it from the exclude
    list.
5.  Finally, close all corresponding bugs for tests that are now passing. These
    bugs are stale.

Creating new runtime tests for an entirely new language is similar to the above,
except that Step 1 is a bit harder. You have to figure out how to download and
run the language tests in a Docker container. Once you have that, you must also
implement the [`proctor/TestRunner`](proctor/lib/lib.go) interface for that
language, so that proctor can list and run the tests in the image you created.

[runtime-images]: ../../images/runtimes/
