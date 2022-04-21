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

To run runtime tests individually from a given runtime, you must build or
download the language image and call Docker directly with the test arguments.

Language | Version | Download Image                     | Run Test(s)
-------- | ------- | ---------------------------------- | -----------
Go       | 1.16    | `make load-runtimes_go1.16`        | If the test name ends with `.go`, it is an on-disk test: <br> `docker run --runtime=runsc -it gvisor.dev/images/runtimes/go1.16 ( cd /usr/local/go/test ; go run run.go -v -- <TEST_NAME>... )` <br> Otherwise it is a tool test: <br> `docker run --runtime=runsc -it gvisor.dev/images/runtimes/go1.16 go tool dist test -v -no-rebuild ^TEST1$\|^TEST2$...`
Java     | 17      | `make load-runtimes_java17`        | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/java17 jtreg -agentvm -dir:/root/test/jdk -noreport -timeoutFactor:20 -verbose:summary <TEST_NAME>...`
NodeJS   | 16.13.2 | `make load-runtimes_nodejs16.13.2` | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/nodejs16.13.2 python tools/test.py --timeout=180 <TEST_NAME>...`
Php      | 8.1.1   | `make load-runtimes_php8.1.1`      | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/php8.1.1 make test "TESTS=<TEST_NAME>..."`
Python   | 3.10.2  | `make load-runtimes_python3.10.2`  | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/python3.10.2 ./python -m test <TEST_NAME>...`

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
    third_party/gvisor/images/runtime/<new_runtime>`

2.  Create a new [`runtime_test`](BUILD) target. The `name` field must be the
    dirctory name for the Docker image you created in Step 1.

3.  Run the tests, and triage any failures. Some language tests are flaky (or
    never pass at all), other failures may indicate a gVisor bug or divergence
    from Linux behavior. Known or expected failures can be added to the
    [exclude](exclude) file for the new version, and they will be skipped in
    future runs.

Creating new runtime tests for an entirely new language is similar to the above,
except that Step 1 is a bit harder. You have to figure out how to download and
run the language tests in a Docker container. Once you have that, you must also
implement the [`proctor/TestRunner`](proctor/lib/lib.go) interface for that
language, so that proctor can list and run the tests in the image you created.

[runtime-images]: ../../images/runtimes/
