# gVisor Runtime Tests

App Engine uses gvisor to sandbox application containers. The runtime tests aim
to test `runsc` compatibility with these
[standard runtimes](https://cloud.google.com/appengine/docs/standard/runtimes).
The test itself runs the language-defined tests inside the sandboxed standard
runtime container.

Note: [Ruby runtime](https://cloud.google.com/appengine/docs/standard/ruby) is
currently in beta mode and so we do not run tests for it yet.

### Testing Locally

To run runtime tests individually from a given runtime, use the following table.

Language | Version | Download Image                              | Run Test(s)
-------- | ------- | ------------------------------------------- | -----------
Go       | 1.12    | `make -C images load-runtimes_go1.12`       | If the test name ends with `.go`, it is an on-disk test: <br> `docker run --runtime=runsc -it gvisor.dev/images/runtimes/go1.12 ( cd /usr/local/go/test ; go run run.go -v -- <TEST_NAME>... )` <br> Otherwise it is a tool test: <br> `docker run --runtime=runsc -it gvisor.dev/images/runtimes/go1.12 go tool dist test -v -no-rebuild ^TEST1$\|^TEST2$...`
Java     | 11      | `make -C images load-runtimes_java11`       | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/java11 jtreg -agentvm -dir:/root/test/jdk -noreport -timeoutFactor:20 -verbose:summary <TEST_NAME>...`
NodeJS   | 12.4.0  | `make -C images load-runtimes_nodejs12.4.0` | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/nodejs12.4.0 python tools/test.py --timeout=180 <TEST_NAME>...`
Php      | 7.3.6   | `make -C images load-runtimes_php7.3.6`     | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/php7.3.6 make test "TESTS=<TEST_NAME>..."`
Python   | 3.7.3   | `make -C images load-runtimes_python3.7.3`  | `docker run --runtime=runsc -it gvisor.dev/images/runtimes/python3.7.3 ./python -m test <TEST_NAME>...`

To run an entire runtime test locally, use the following table.

Note: java runtime test take 1+ hours with 16 cores.

Language | Version | Running the test suite
-------- | ------- | ----------------------------------------
Go       | 1.12    | `make go1.12-runtime-tests{_vfs2}`
Java     | 11      | `make java11-runtime-tests{_vfs2}`
NodeJS   | 12.4.0  | `make nodejs12.4.0-runtime-tests{_vfs2}`
Php      | 7.3.6   | `make php7.3.6-runtime-tests{_vfs2}`
Python   | 3.7.3   | `make python3.7.3-runtime-tests{_vfs2}`

#### Clean Up

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

### Testing Infrastructure

There are 3 components to this tests infrastructure:

-   [`runner`](runner) - This is the test entrypoint. This is the binary is
    invoked by `bazel test`. The runner spawns the target runtime container
    using `runsc` and then copies over the `proctor` binary into the container.
-   [`proctor`](proctor) - This binary acts as our agent inside the container
    which communicates with the runner and actually executes tests.
-   [`exclude`](exclude) - Holds a CSV file for each language runtime containing
    the full path of tests that should be excluded from running along with a
    reason for exclusion.
