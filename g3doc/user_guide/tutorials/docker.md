# WordPress with Docker

This page shows you how to deploy a sample [WordPress][wordpress] site using
[Docker][docker].

### Before you begin

[Follow these instructions][docker-install] to install runsc with Docker. This
document assumes that the runtime name chosen is `runsc`.

### Running WordPress

Now, let's deploy a WordPress site using Docker. WordPress site requires two
containers: web server in the frontend, MySQL database in the backend.

> **Note**: This example uses gVisor to sandbox the frontend web server, but not
> the MySQL database backend. In a production setup, due to
> [the I/O overhead](../../architecture_guide/performance) imposed by gVisor,
> **it is not recommended to run your database in a sandbox**. The frontend is
> the critical component with the largest outside attack surface, where gVisor's
> security/performance trade-off makes the most sense. See the
> [Production guide] for more details.

First, let's define a few environment variables that are shared between both
containers:

```bash
export MYSQL_PASSWORD=${YOUR_SECRET_PASSWORD_HERE?}
export MYSQL_DB=wordpress
export MYSQL_USER=wordpress
```

Next, let's start the database container running MySQL and wait until the
database is initialized:

```shell
# If you want to sandbox the database, add --runtime=runsc to this command.
$ docker run --name mysql -d \
    -e MYSQL_RANDOM_ROOT_PASSWORD=1 \
    -e MYSQL_PASSWORD="${MYSQL_PASSWORD}" \
    -e MYSQL_DATABASE="${MYSQL_DB}" \
    -e MYSQL_USER="${MYSQL_USER}" \
    mysql:5.7

# Wait until this message appears in the log.
$ docker logs mysql |& grep 'port: 3306  MySQL Community Server (GPL)'
```

Once the database is running, you can start the WordPress frontend. We use the
`--link` option to connect the frontend to the database, and expose the
WordPress to port 8080 on the localhost.

```shell
$ docker run --runtime=runsc --name wordpress -d \
    --link mysql:mysql \
    -p 8080:80 \
    -e WORDPRESS_DB_HOST=mysql \
    -e WORDPRESS_DB_USER="${MYSQL_USER}" \
    -e WORDPRESS_DB_PASSWORD="${MYSQL_PASSWORD}" \
    -e WORDPRESS_DB_NAME="${MYSQL_DB}" \
    -e WORDPRESS_TABLE_PREFIX=wp_ \
    wordpress
```

Now, you can access the WordPress website pointing your favorite browser to
<http://localhost:8080>.

Congratulations! You have just deployed a WordPress site using Docker and
gVisor.

### What's next

Learn how to deploy WordPress with [Kubernetes][wordpress-k8s] or
[Docker Compose][wordpress-compose].

Before deploying this to production, see the [Production guide] for how to take
full advantage of gVisor.

[docker]: https://www.docker.com/
[docker-install]: ../quick_start/docker.md
[wordpress]: https://wordpress.com/
[wordpress-k8s]: kubernetes.md
[wordpress-compose]: docker-compose.md
[Production guide]: /docs/user_guide/production/
