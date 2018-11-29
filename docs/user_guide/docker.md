# Run gVisor with Docker

## Configuring Docker

Next, configure Docker to use `runsc` by adding a runtime entry to your Docker
configuration (`/etc/docker/daemon.json`). You may have to create this file if
it does not exist. Also, some Docker versions also require you to [specify the
`storage-driver` field][docker-storage-driver].

In the end, the file should look something like:

```
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc"
        }
    }
}
```

You must restart the Docker daemon after making changes to this file, typically
this is done via:

```
sudo systemctl restart docker
```

## Running a container

Now run your container in `runsc`:

```
docker run --runtime=runsc hello-world
```

You can also run a terminal to explore the container.

```
docker run --runtime=runsc -it ubuntu /bin/bash
```
