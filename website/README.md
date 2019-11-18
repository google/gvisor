# gVisor Website

This repository holds the content for the gVisor website, including
documentation.

## Requirements

Building the website requires Docker.

## Contributing to Documentation

### Using Github

You can use the "Edit this page" link on any documentation page to edit the page
content directly via GitHub and submit a pull request. This should generally be
done for relatively small changes.

### Using Git

You can submit pull requests by making changes in a Git branch. See more
information on GitHub pull requests
[here](https://help.github.com/en/articles/about-pull-requests).

Documentation is located in the [content/docs/](content/docs/) directory.

## Building

You can build the site locally by running:

```
make build
```

Incremental changes can be generated using:


```
make update
```

And the site can be served locally using:

```
make server
```

Access the site at `http://localhost:8080`.

The above will build all parts of the site, including the serving components.
