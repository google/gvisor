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

## Updating Styles

If you want to update style on the website you can do this by updating
templates or CSS for the website. Check out the [Hugo
documentation](https://gohugo.io/documentation/) for info on hugo templating.
Check out the [Docsy documentation](https://www.docsy.dev/docs/) for info on
the Docsy theme.

### Custom templates, partials, and shortcodes

Custom templates, including partials and shortcodes, should go under the
[layouts/](layouts) directory.

## Custom CSS

Custom CSS styles should go into the
[_styles_project.scss](assets/scss/_styles_project.scss) file.

If you need to override or create variables used in scss styles, update the
[_variables_project.scss](assets/scss/_variables_project.scss) file.

## Troubleshooting

#### I get errors when building the website.

If you get the following errors you should check that you have the "extended"
version of Hugo. This is the version of hugo named "hugo\_extended" on the
[releases page](https://github.com/gohugoio/hugo/releases).