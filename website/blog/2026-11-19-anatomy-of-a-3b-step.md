# The anatomy of a 3B step

> *This article was contributed by [Tines](https://www.tines.com/). Shayon Mukherjee is an engineer at Tines, working on the runtime infrastructure behind 3B. It was originally published on [Tines Notebook](https://notebook.tines.com/writing/anatomy-of-a-3b-step/).*

At Tines we’re building 3B, where people work with an agent to automate enterprise software. Workflows, internal apps, and agents are all made of steps, each a directory with a Dockerfile and a program that reads stdin and writes stdout. The result becomes the input to whatever runs next.

Each run gets a fresh Linux sandbox, including a fresh gVisor application kernel, which we delete afterwards because we have to treat the program as untrusted even if it appears to have worked. That means its image and persistent files have to survive outside the environment we throw away.

<!--/excerpt-->

## An example step

A step runs the command defined by its image, so the same setup can start a compiled binary, a shell script, or a language runtime. For our example, we’ll follow a step written in Python that looks up IP addresses in an incoming security alert and keeps the answers in SQLite, so later alerts can reuse them. It needs `requests` in `requirements.txt`, a volume for its database, and a [connector](https://docs.3b.tines.com/en/articles/15885706-connect-to-your-tools-by-creating-connectors) for the threat intelligence API. The API hostname below is illustrative.

**enrich-alert/Dockerfile**

```dockerfile
FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt
COPY --link . .
VOLUME ["alerts"]
CMD ["python", "./script.py"]
```

**enrich-alert/script.py**

```python
import json
import sqlite3
import sys
from urllib.parse import quote

import requests

endpoint = "https://api.threatintel.example/v1/ip"
alert = json.load(sys.stdin)
db = sqlite3.connect("/storage/alerts/seen.db")
db.execute(
    "CREATE TABLE IF NOT EXISTS seen "
    "(address TEXT PRIMARY KEY, verdict TEXT)"
)

enrichment = {}
for address in alert["addresses"]:
    row = db.execute(
        "SELECT verdict FROM seen WHERE address = ?",
        (address,),
    ).fetchone()
    if row is None:
        response = requests.get(
            f"{endpoint}/{quote(address, safe='')}",
            timeout=10,
        )
        response.raise_for_status()
        verdict = response.json()["verdict"]
        db.execute(
            "INSERT INTO seen VALUES (?, ?)",
            (address, verdict),
        )
    else:
        verdict = row[0]
    enrichment[address] = verdict

db.commit()
db.close()
alert["enrichment"] = enrichment
print(json.dumps(alert))
```

In 3B, `VOLUME ["alerts"]` declares a persistent volume mounted at `/storage/alerts`. The example leaves out cache expiry, so a cached verdict stays there until it is removed. There’s a connector attached for the threat intelligence service as well. Its API key isn’t passed to Python, though, because the request gets authenticated after leaving the sandbox through a proxy that sits right outside the sandbox.

## Running Linux in the sentry

For a regular container, Linux handles the program’s syscalls in the host kernel, subject to namespace and seccomp restrictions. We use [gVisor](https://gvisor.dev/users/) to handle them in a process called the [sentry](https://gvisor.dev/docs/). The sentry implements the Linux interface in Go, with its own task table, virtual memory system, and filesystems, and is itself an unprivileged process on the host.

So when Python asks for its PID, the sentry already has one in its task table, and if Python writes to a pipe, that just changes a buffer in the sentry. For networking, we use the host’s TCP/IP stack inside a separate network namespace for each sandbox, so connecting a socket does require a host syscall. The sentry asks the gofer, gVisor’s separate file server, for host files such as `/etc/resolv.conf` over the LisaFS protocol. We also use seccomp to restrict the host syscalls available to the sentry, which limits what it can do if it is compromised.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/stack.svg" caption="The sentry handles the step’s syscalls. It sends LisaFS requests to the gofer and makes its own host syscalls where needed." %}

We use gVisor’s systrap platform to get into the sentry without hardware virtualization. This is useful for our self-hosted offering, since access to KVM isn’t a given in a customer’s environment.

After the program has run, we stop trusting its sentry and delete it, because a successful exit doesn’t establish that the program didn’t exploit its kernel. So the next execution gets another sentry, even when the same step runs again.

## Starting before the job arrives

We run millions of steps a day across what we call "workers", each with a sandbox daemon called `sandboxd` (previously known as `gvisord`, with a little nod to systemd).

Before starting the pool, sandboxd creates its own user and network namespaces, so it can set up interfaces and routes there without needing those privileges over the host’s network. Each sandbox then gets a separate network namespace connected to the daemon’s network, where its TCP traffic is directed to our proxy, Pony.

With that in place, sandboxd prepares a pool of sandboxes ahead of time, starting the sentry and gofer and setting up the network so our runner can wait inside for a command. The runner starts the image’s configured command as the image’s user, with capabilities dropped, so in our example it runs `python ./script.py`. The slot remains occupied until the sandbox has been removed, including the resources it used outside the sentry.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/pool.svg" caption="Each slot goes through preparation, execution, and teardown before starting a replacement sandbox." %}

We put many slots on a worker, sized for the CPU and memory it has available, with resources left for the worker’s own processes. A command can exit before everything belonging to it has gone away, which is why cleanup counts towards the slot’s lifetime too.

We check this with a test that sends 100 requests at once, each running `node -v` in a fresh sandbox. Those runs use sandboxes already waiting in the pool and can reuse image data cached on the worker. We measure image attachment and command execution separately from the full request and response, which also includes the work before a worker receives the job.

## Who answers each path

In our example, the Python installation is part of the base image. When Python reads one of its libraries, the bytes come from the image, but if the program changes that file, its writes go into the sandbox’s private tmpfs. The sentry implements the overlay and supplies `/tmp` and `/proc` too, with their temporary state discarded at the end of the run.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/mounts.svg" caption="The image and temporary paths are served by the sentry; the gofer serves selected host files and persistent volumes." %}

## Files that outlive the sandbox

That’s different from, say, our SQLite file, which needs to survive the run so the next alert can find the answers this one saved. So when SQLite opens `/storage/alerts/seen.db`, the sentry sends a LisaFS request to our gofer’s Nest backend, which we wrote to serve persistent volumes. Nest reads from a snapshot and keeps this run’s writes separately until the run finishes. Concurrent runs each read their own snapshot, so SQLite’s locks only coordinate processes within a run. Stock gVisor code in the same gofer serves a few host files, such as `/etc/resolv.conf`.

Nest talks to Spongeblob through sandboxd’s storage gateway, which relays its requests. Spongeblob is our internal Rust database for filesystem data and snapshots. It powers a lot of other primitives we are able to offer at the filesystem level. Something we will cover in depth in another post.

Between Spongeblob, Nest, and Pony, we may have used up the sensible names on `runner` I think 😆.

A lookup like this may only need a few pages from the database. Our earlier implementation copied a volume file into a local backing file before returning from `open`, so gVisor could read and map it through a host file descriptor. But one production database had grown to 933 MB, which meant copying all of it before SQLite could look up a single row.

So we moved reads of committed files into the sentry’s page cache. Opening the file no longer copies its contents. Nest fetches the missing data from the snapshot when SQLite reads it, and if SQLite comes back to those pages, the sentry already has them. Writes stay separate, so Nest only has to publish the blocks the step changed.

That works well for a few pages, but if, say, the step scans the whole database, small fetches turn into one network wait after another. For larger reads, Nest now fetches 2 MiB windows, splitting each window across 4 concurrent requests, and reads ahead while the program keeps reading in order. We also changed the sentry to reclaim a quarter of its cache at a time under memory pressure, taking chunks read once before ones the program has returned to. So a scan can make progress without keeping the entire file in memory, and the cache gives memory back as the program needs it.

We measured those read-ahead and reclamation changes with the sentry page cache enabled in both versions. In our file-I/O benchmark, 200 cold lookups in a 900 MB database went from 8.42 seconds to 2.27 seconds. A SQL scan went from 13.0 seconds to 3.13 seconds, while a single point read stayed at 37 ms.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/database-reads.svg" caption="Selected cold-read benchmarks before and after the read-ahead changes, with the sentry page cache enabled in both. Median of 3 runs, 2 worker CPUs, cold storage packs, and 1 ms of added network latency." %}

In a separate contention test, a hot reader sharing its step’s CPU with 2 scans took 30% longer because the faster scans used more of that CPU, even though the whole step finished sooner.

## Building the image

When someone is working on a workflow and the agent edits a step’s code or Dockerfile, we build an updated image for that step as they iterate. That build runs in a sandbox as well, and BuildKit (with a couple of internal patches) turns the Dockerfile into image layers.

We use [Nydus](https://nydus.dev/docs/concepts/rafs/) to export the image in its EROFS-compatible format. The file data in each layer is split into separately compressed, hashed chunks, while the filesystem metadata is written in [EROFS](https://docs.kernel.org/filesystems/erofs.html), a read-only format that records the directory tree and references to the file data. Nydus merges the layers’ metadata into one bootstrap file describing the finished image.

The builder pushes the bootstrap and layer blobs through the storage gateway’s registry, which checks the uploaded blobs against their digests before publishing them in Spongeblob.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/build.svg" caption="The builder pushes through the gateway’s registry, where uploads are verified before publication." %}

Layer blobs are stored by digest within a tenant, so images can share a base layer or an identical *output layer* produced by another build. Spongeblob also stores a step’s build cache, including the pip directory in our example, so later builds can read cached layers and reuse saved cache directories as well.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/image.svg" caption="The bootstrap describes the final tree and references file contents in shared layer blobs." %}

Loading the bootstrap gives the sentry the directory tree up front, so a fresh run can get started with the pages its program touches during startup while the rest of the image stays in Spongeblob until needed.

We use this for the builder too. In one production trace, BuildKit found a cache hit in about a quarter of a second, then spent 23.5 seconds downloading and unpacking parent layers for a `COPY` that took 0.03 seconds. The builder was fresh, so it still had to reconstruct the files those cached instructions had produced. We changed it to mount the cached layers through the same lazy image path we use for executions.

That made the next edit faster, but a sequence of edits showed something else. A warm build could reuse those layers and then fail to export them into its own cache. The exporter dropped records it couldn’t load, along with the records depending on them, so one build saved only 3 of its 14 layers. The edit after that had to compile dependencies again.

Our benchmark had only checked the first edit after a cold build, so it missed this. We changed the exporter to try the other results for a cache record when one couldn’t load, and added a regression test that makes 2 successive edits. In the five-build comparison below, the third and fifth builds fell from 51 seconds each to 7.9 seconds each. The first build still took about the same time.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/successive-builds.svg" caption="Five consecutive builds of the same Rust fixture, before and after the cache-export fix. Each point is an individual benchmark build duration, in seconds." %}

## Faulting the image in

At this point, we have a fresh sandbox waiting on the worker and an image stored in Spongeblob. When it’s time to run the step, sandboxd attaches the image to the waiting sentry. The sentry reads the EROFS bootstrap for filesystem metadata, so it can answer a lookup or `stat` straight away, then requests file data through the storage gateway as reads and page faults need it. So the step can start as soon as the data it needs is available, without waiting for us to download and unpack the entire image.

There are a lot of “lazy design decisions” that can be found in these parts of the system. An image-backed fault reaches gVisor’s EROFS reader, which uses the bootstrap to find the requested blob range and asks the gateway to prepare it. If those bytes aren’t verified yet, the gateway reads the compressed chunks from Spongeblob, decompresses them into its local backing file, and checks their digests. It returns a read-only descriptor and the range now verified, and the sentry validates that reply before mapping the file and letting the program continue.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/fault.svg" caption="Illustrative cold fault: the gateway fetches and verifies missing data before the sentry maps the page. A later fault within the ready range needs no gateway request." %}

The backing file is shared per blob per tenant on a worker, so a second sentry using the same base image can map the same pages already in the host page cache. Each sentry tracks ready ranges locally and uses its mapped backing file for subsequent accesses, while the worker keeps the immutable image data available to fresh sandboxes. The volume pages from our SQLite example live in a sentry’s own cache, but these image pages can outlive it because the image never changes.

We also contributed [support for chunk-based files](https://github.com/google/gvisor/pull/15527) to gVisor’s EROFS reader. That part is upstream now, so gVisor can read and map ordinary chunked EROFS files. We still carry the remote-device integration that connects our image reads to the storage gateway and tracks which ranges are ready to map.

So steps using the same image can share its stored bytes and the pages already cached on a worker.

## Startup is the slow part

Starting Python can still mean waiting for one library after another, because the next read often depends on code that hasn’t loaded yet. On a cold worker, those waits can add up even though we’re only fetching a small part of the image.

When the gateway prepares an image and finds no startup list, it records the first distinct ranges requested during that attachment and saves the list in Spongeblob when the connection closes cleanly. A later cold attachment can replay those ranges in the background while the program starts, with a limit on concurrent fills across the worker. The program still fetches anything the list missed, and every chunk goes through the same verification.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/startup.svg" caption="The gateway records requested ranges for an image, then replays the list during a later cold attachment. Reads still wait for any data that is not ready." %}

The list belongs to a particular image digest, so a changed image gets a separate list. If the same image starts taking a different path, the old list can fetch data we no longer need and use up bandwidth and cache space.

## TCP egress goes through Pony

Now, say our step needs to look up an IP address that isn’t in its SQLite database. It calls the threat intelligence API with `requests.get`, which opens a socket in the sandbox’s network namespace, and the connection is directed to the sandbox’s transparent listener in Pony. Pony already knows which connectors are attached to the run. sandboxd creates the listener and a DNS socket when preparing the sandbox, then hands both to Pony with Unix file descriptor passing, `SCM_RIGHTS`. Pony accepts directly on those sockets after the handoff.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/network.svg" caption="The connection reaches Pony, where the request gets its connector credential before going to the API." %}

Pony can read the HTTPS request because it terminates TLS using a CA trusted by the sandbox. It holds the decrypted connector credential in its own memory, matches the request to the threat intelligence connector, and inserts the API key into the HTTP request it sends over a separate upstream TLS connection. The response goes back to our script, which could use the API without the key ever having been in its environment.

## Removing the sandbox

Once the step’s command has exited, the runner kills and reaps any remaining processes. If the command failed, we discard this run’s volume changes. Otherwise, the runner syncs `/storage`, flushing the sentry’s dirty pages too, including changes made through shared mappings. That way, no background process can keep changing the files while Nest publishes them.

Nest then attempts to publish the volume changes. If, say, 2 alerts ran at once and both changed `seen.db`, publication can fail with a conflict, even though SQLite committed and the program exited successfully. That conflict fails the step.

After the result is stored, sandboxd destroys the sentry and gofer and removes their network and runtime resources, and only then is the slot available to prepare a new sandbox.

## Wrapping up

Putting those pieces together, here’s what a step running on a worker looks like.

{% include diagram.html src="2026-11-19-anatomy-of-a-3b-step/overview.svg" caption="Our alert enrichment step runs in a fresh sandbox, using files stored in Spongeblob and calling the API through Pony." %}

We’re only getting started here. A 3B step can run Python, Node, shell scripts, or compiled x86-64 programs to automate enterprise workflows, within the [Linux interfaces gVisor supports](https://gvisor.dev/docs/user_guide/compatibility/) and our sandbox restrictions. We’ve invested in primitives that let us connect steps to self-hosted environments through our tunnel and fork volumes from a live branch into a draft, and those are just a couple of examples. We’ll share more about these in future posts.

Lastly, we’re also invested in gVisor’s success and as gVisor [moves to the CNCF](https://gvisor.dev/blog/2026/10/02/gvisor-cncf/), Tines has [committed to joining its maintainers](https://cloud.google.com/blog/products/containers-kubernetes/open-infrastructure-for-autonomous-agents-comes-to-cncf) alongside Modal and Ant Group. We are stoked for what lies ahead.
