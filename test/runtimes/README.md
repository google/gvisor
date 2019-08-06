# Runtimes Tests Dockerfiles

The Dockerfiles defined under this path are configured to host the execution of
the runtimes language tests. Each Dockerfile can support the language indicated
by its directory.

The following runtimes are currently supported:

-   Go 1.12
-   Java 11
-   Node.js 12
-   PHP 7.3
-   Python 3.7

#### Prerequisites:

1) [Install and configure Docker](https://docs.docker.com/install/)

2) Build each Docker container from the runtimes directory:

```bash
$ docker build -f $LANG/Dockerfile [-t $NAME] .
```

### Testing:

If the prerequisites have been fulfilled, you can run the tests with the
following command:

```bash
$ docker run --rm -it $NAME [FLAG]
```

Running the command with no flags will cause all the available tests to execute.

Flags can be added for additional functionality:

-   --list: Print a list of all available tests
-   --test &lt;name&gt;: Run a single test from the list of available tests
-   --v: Print the language version
