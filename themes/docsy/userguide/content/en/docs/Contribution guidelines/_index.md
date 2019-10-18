---
title: "Contribution Guidelines"
linkTitle: "Contribution Guidelines"
weight: 9
description: >
  How to contribute to Docsy
---

Docsy is an open source project and we love getting patches and contributions to make Docsy and its docs even better.

## Contributing to Docsy

The Docsy theme itself lives in <https://github.com/google/docsy>.

### Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

### Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

### Previewing your changes

As Docsy is a theme rather than a site, you can't serve the theme directly to check your changes work. Instead use your updated local theme in a local copy of the Docsy example site (copy or make your changes in the `themes/docsy` directory) and [preview](/docs/deployment/) from there. Alternatively, clone the [Docsy theme repo](https://github.com/google/docsy) and test your changes in a local copy of this site, as described [below](#previewing-your-changes-locally).

### Community guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

### Creating issues

Alternatively, if there's something you'd like to see in Docsy (or if you've found something that isn't working the way you'd expect), but you're not sure how to fix it yourself, please create an [issue](https://github.com/google/docsy/issues).

## Contributing to these docs

This user guide is, like our example site, a Docsy site that uses the Hugo static site generator. We welcome updates to the docs!

We use [Netlify](https://www.netlify.com/) to manage the deployment of the site and provide previews of doc updates. The instructions here assume you're familiar with basic GitHub workflows.

### Quick start with Netlify

1. Fork the [Docsy repo](https://github.com/google/docsy) on GitHub: this site's files live in the `userguide` subdirectory.
1. Make your changes and send a pull request (PR).
1. If you're not yet ready for a review, add "WIP" to the PR name to indicate 
  it's a work in progress. (**Don't** add the Hugo property 
  "draft = true" to the page front matter, because that prevents the 
  auto-deployment of the content preview described in the next point.)
1. Wait for the automated PR workflow to do some checks. When it's ready,
  you should see a comment like this: **deploy/netlify — Deploy preview ready!**
1. Click **Details** to the right of "Deploy preview ready" to see a preview
  of your updates.
1. Continue updating your doc and pushing your changes until you're happy with 
  the content.
1. When you're ready for a review, add a comment to the PR, and remove any
  "WIP" markers.

### Updating a single page

If you've just spotted something you'd like to change while using the docs, Docsy has a shortcut for you:

1. Click **Edit this page** in the top right hand corner of the page.
1. If you don't already have an up to date fork of the project repo, you are prompted to get one - click **Fork this repository and propose changes** or **Update your Fork** to get an up to date version of the project to edit. The appropriate page in your fork is displayed in edit mode.
1. Follow the rest of the [Quick start with Netlify](#quick-start-with-netlify) process above to make and preview your changes.


### Previewing your changes locally

If you want to run your own local Hugo server to preview your changes as you work:

1. Follow the instructions in [Getting started](/docs/getting-started) to install Hugo and any other tools you need.
1. Fork the [Docsy](https://github.com/google/docsy) repo into your own project, then create a local copy using `git clone`. Don’t forget to use `--recurse-submodules` or you won’t pull down some of the code you need to generate a working site.

    ```
    git clone --recurse-submodules --depth 1 https://github.com/google/docsy.git
    ```

1. Change to the `userguide` directory and run the following Hugo command to build the site and start the Hugo server.
   Note that you need the `themesDir` flag because the site files are inside the theme repo.

    ```
    cd userguide
    hugo server --themesDir ../..
    ```
    
    By default your site will be available at http://localhost:1313/. Now that you're serving your site locally, Hugo will watch for changes to the content and automatically refresh your site.
   
1. Continue with the usual GitHub workflow to edit files, commit them, push the
  changes up to your fork, and create a pull request.

### Creating an issue

If there's something you'd like to see in the docs, but you're not sure how to fix it yourself, please create an issue in [this repository](wherever it goes). You can also create an issue about a specific page by clicking the **Create Issue** button in the top right hand corner of the page.


