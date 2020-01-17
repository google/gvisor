# gVisor Website

This repository holds the content for the gVisor website. It uses
[hugo](https://gohugo.io/) to generate the website and
[Docsy](https://github.com/google/docsy) as the theme. 

## Using Github

The easiest way to contribute to the documentation is to use the "Edit this
page" link on any documentation page to edit the page content directly via
GitHub and submit a pull request. This should generally be done for changes to 
a single page.

## Using Git

You can submit pull requests by making changes in a Git branch. See more
information on GitHub pull requests
[here](https://help.github.com/en/articles/about-pull-requests).

Documentation is located in the [content/docs/](content/docs/) directory.
Documentation is written in markdown with hugo extensions. Please read more
about [content management](https://gohugo.io/categories/content-management) in
the hugo documentation.

### Requirements

Building the website requires [Docker](https://www.docker.com/). Please
[install](https://docs.docker.com/install/) it before building.

### Building

If you want to simply build the website, you can do that using `make`. This
will output the App Engine application code, configuration, and html and CSS
into the `public/` directory.

```
make
```

### Testing

You can use the hugo web server for testing documentation or style changes.
This will start a webserver that will rebuild the site when you make content
changes:

```
make devserver
```

Access the site at http://localhost:8080

If you need to test all functionality including redirects you can start the App
Engine app locally. However, you will need to restart the app when making
content changes:

```
make server
```
