# Wordpress with Docker Compose

This page shows you how to deploy a sample [WordPress][wordpress] site using
[Docker Compose][docker-compose].

### Before you begin

[Follow these instructions][docker-install] to install runsc with Docker. This
document assumes that Docker and Docker Compose are installed and the runtime
name chosen for gVisor is `runsc`.

### Configuration

We'll start by creating the `docker-compose.yaml` file to specify our services.
We will specify two services, a `wordpress` service for the Wordpress Apache
server, and a `db` service for MySQL. We will configure Wordpress to connect to
MySQL via the `db` service host name.

> **Note**: This example uses gVisor to sandbox the frontend web server, but not
> the MySQL database backend. In a production setup, due to
> [the I/O overhead](../../architecture_guide/performance) imposed by gVisor,
> **it is not recommended to run your database in a sandbox**. The frontend is
> the critical component with the largest outside attack surface, where gVisor's
> security/performance trade-off makes the most sense. See the
> [Production guide] for more details.

> **Note**: Docker Compose uses it's own network by default and allows services
> to communicate using their service name. Docker Compose does this by setting
> up a DNS server at IP address 127.0.0.11 and configuring containers to use it
> via [resolv.conf][resolv.conf]. This IP is not addressable inside a gVisor
> sandbox so it's important that we set the DNS IP address to the alternative
> `8.8.8.8` and use a network that allows routing to it. See
> [Networking in Compose][compose-networking] for more details.

> **Note**: The `runtime` field was removed from services in the 3.x version of
> the API in versions of docker-compose < 1.27.0. You will need to write your
> `docker-compose.yaml` file using the 2.x format or use docker-compose >=
> 1.27.0. See this [issue](https://github.com/docker/compose/issues/6239) for
> more details.

```yaml
version: '2.3'

services:
   db:
     image: mysql:5.7
     volumes:
       - db_data:/var/lib/mysql
     restart: always
     environment:
       MYSQL_ROOT_PASSWORD: somewordpress
       MYSQL_DATABASE: wordpress
       MYSQL_USER: wordpress
       MYSQL_PASSWORD: wordpress
     # All services must be on the same network to communicate.
     network_mode: "bridge"
     # Uncomment the following line if you want to sandbox the database.
     #runtime: "runsc"

   wordpress:
     depends_on:
       - db
     # When using the "bridge" network specify links.
     links:
       - db
     image: wordpress:latest
     ports:
       - "8080:80"
     restart: always
     environment:
       WORDPRESS_DB_HOST: db:3306
       WORDPRESS_DB_USER: wordpress
       WORDPRESS_DB_PASSWORD: wordpress
       WORDPRESS_DB_NAME: wordpress
     # Specify the dns address if needed.
     dns:
       - 8.8.8.8
     # All services must be on the same network to communicate.
     network_mode: "bridge"
     # Specify the runtime used by Docker. Must be set up in
     #  /etc/docker/daemon.json.
     runtime: "runsc"

volumes:
    db_data: {}
```

Once you have a `docker-compose.yaml` in the current directory you can start the
containers:

```bash
docker-compose up
```

Once the containers have started you can access wordpress at
http://localhost:8080.

Congrats! You now how a working wordpress site up and running using Docker
Compose.

### What's next

Learn how to deploy [WordPress with Kubernetes][wordpress-k8s].

Before deploying this to production, see the [Production guide] for how to take
full advantage of gVisor.

[docker-compose]: https://docs.docker.com/compose/
[docker-install]: ../quick_start/docker.md
[wordpress]: https://wordpress.com/
[resolv.conf]: https://man7.org/linux/man-pages/man5/resolv.conf.5.html
[wordpress-k8s]: kubernetes.md
[compose-networking]: https://docs.docker.com/compose/networking/
[Production guide]: /docs/user_guide/production/
