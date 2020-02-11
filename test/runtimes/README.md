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

### Building and pushing the images:

The canonical source of images is the
[gvisor-presubmit container registry](https://gcr.io/gvisor-presubmit/). You can
build new images with the following command:

```bash
$ cd images
$ docker build -f Dockerfile_$LANG [-t $NAME] .
```

To push them to our container registry, set the tag in the command above to
`gcr.io/gvisor-presubmit/$LANG`, then push them. (Note that you will need
appropriate permissions to the `gvisor-presubmit` GCP project.)

```bash
gcloud docker -- push gcr.io/gvisor-presubmit/$LANG
```

#### Running in Docker locally:

1) [Install and configure Docker](https://docs.docker.com/install/)

2) Pull the image you want to run:

```bash
$ docker pull gcr.io/gvisor-presubmit/$LANG
```

3) Run docker with the image.

```bash
$ docker run [--runtime=runsc] --rm -it $NAME [FLAG]
```

Running the command with no flags will cause all the available tests to execute.

Flags can be added for additional functionality:

-   --list: Print a list of all available tests
-   --test &lt;name&gt;: Run a single test from the list of available tests
-   --v: Print the language version
