
---
title: "Getting Started"
linkTitle: "Getting Started"
weight: 2
date: 2018-07-30
description: >
  This page tells you how to get started with the Docsy theme, including installation and basic configuration.
---


## Prerequisites and installation

### Install Hugo 

You need a [recent **extended** version](https://github.com/gohugoio/hugo/releases) (we recommend version 0.53 or later) of [Hugo](https://gohugo.io/) to do local builds and previews of sites (like this one) that use Docsy. If you install from the release page, make sure to get the `extended` Hugo version, which supports [SCSS](https://sass-lang.com/documentation/file.SCSS_FOR_SASS_USERS.html); you may need to scroll down the list of releases to see it. 

For comprehensive Hugo documentation, see [gohugo.io](https://gohugo.io/).

#### Linux

Do **not** use `sudo apt-get install hugo`, as it currently doesn't get you the `extended` version. 

If you've already installed Hugo, check your version:

```
hugo version
```
If the result is `v0.52` or earlier, or if you don't see `Extended`, you'll need to install the latest version.
    
1.  Go to the [Hugo releases](https://github.com/gohugoio/hugo/releases) page.
2.  In the most recent release, scroll down until you find a list of
    **Extended** versions.
3.  Download the latest extended version (`hugo_extended_0.5X_Linux-64bit.tar.gz`).
4.  Create a new directory:

        mkdir hugo

5.  Extract the files you downloaded to `hugo`.

6.  Switch to your new directory:

        cd hugo

7.  Install Hugo:

        sudo install hugo /usr/bin    

#### macOS

Install Hugo using [Brew](https://gohugo.io/getting-started/installing/#homebrew-macos).

### Install PostCSS

To build or update your site's CSS resources, you also need [`PostCSS`](https://postcss.org/) to create the final assets. If you need to install it, you must have a recent version of [NodeJS](https://nodejs.org/en/) installed on your machine so you can use `npm`, the Node package manager. By default `npm` installs tools under the directory where you run `npm install`:

```
sudo npm install -D --save autoprefixer
sudo npm install -D --save postcss-cli
```

Note that versions of `PostCSS` later than 5.0.1 will not load `autoprefixer` if installed [globally](https://flaviocopes.com/npm-packages-local-global/), you must use a local install.

## Using the theme

To use the Docsy Hugo theme, you have a couple of options:

*   **Copy and edit the source for the [Docsy example site](https://github.com/google/docsy-example).** This approach gives you a skeleton structure for your site, with top-level and documentation sections and templates that you can modify as necessary. The example site uses Docsy as a [Git submodule](https://git-scm.com/book/en/v2/Git-Tools-Submodules), so it's easy to [keep up to date](#keeping-the-theme-up-to-date).
*   **Build your own site using the Docsy theme.** Specify the [Docsy theme](https://github.com/google/docsy) like any other [Hugo theme](https://gohugo.io/themes/) when creating or updating your site. With this option, you'll get Docsy look and feel, navigation, and other features, but you'll need to specify your own site structure. 

### Option 1: Clone the Docsy example site

The [Example Site](https://example.docsy.dev) gives you a good starting point for building your docs site and is
pre-configured to use the Docsy theme as a Git submodule. You can clone the Example Site either by:

*  [Using the GitHub UI](#using-the-github-ui)
*  [Using the command line](#using-the-command-line)

#### Using the GitHub UI

<!--This is the simplest approach, as the Docsy example site repo is a [template repository](https://github.blog/2019-06-06-generate-new-repositories-with-repository-templates/). To create your own copy of the Docsy example site repo:

1. Go to the [repo page](https://github.com/google/docsy-example) and click **Use this template**.

1. Type your chosen name for your new repository in the **Repository name** field. You can also add an optional **Description**.

1. Click **Create repository from template** to create your new repository. Congratulations, you now have a Docsy site repo!

1. To test your copied site locally with Hugo, or make local edits, you'll also need to make a local copy of your new repository. To do this, use `git clone`, replacing `https://github.com/my/example.git` with your repo's web URL (don't forget to use `--recurse-submodules` or you won't pull down some of the code you need to generate a working site):

    <pre>
    git clone --recurse-submodules --depth 1 <em>https://github.com/my/example.git</em>
    </pre>

You can now edit your local versions of the site's source files. To preview your site, go to your site root directory and run `hugo server`. By default, your site will be available at http://localhost:1313/. To push changes to your new repo, go to your site root directory and use `git push`.-->

Note that the following approach [forks](https://help.github.com/en/articles/fork-a-repo) our repo and so creates a connection in GitHub between your project repo and the Docsy example site project repo - our project will be the "upstream" version of your site project:

1.  In the [the Docsy example site's GitHub repo](https://github.com/google/docsy-example), click **Fork** and follow the prompts.
1.  Rename your new fork:
    1.  Click **Settings**, and type a new name in the **Repository name** field.
    1.  Click **Rename** to save your changes.
1.  Get the web URL for cloning your site repo by clicking **Clone or download** on its main repo page.
1.  Make your own local working copy of your repo using `git clone`, replacing `https://github.com/my/example.git` with your repo's web URL:

    <pre>
    git clone --recurse-submodules --depth 1 <em>https://github.com/my/example.git</em>
    </pre>

You can now edit your local versions of the site's source files. To preview your site, go to your site root directory and run `hugo server`. By default, your site will be available at http://localhost:1313/. To push changes to your new repo, go to your site root directory and use `git push`.


#### Using the command line

To copy the example site:

1.  Make a local working copy of the example site directly using `git clone`:

        git clone https://github.com/google/docsy-example.git
    
1. Switch to the root of the cloned project, for example:

        cd docsy-example

1. Get local copies of the project submodules so you can build and run your site locally:

        git submodule update --init --recursive
    
1. Build your site:
    
        hugo server
    
1. Preview your site in your browser at: http://localhost:1313/. You can use `Ctrl + c` to stop the Hugo server whenever you like.

1. Now that you have a site running, you can push it to a new repository:

   1. [Create a new repository in GitHub](https://help.github.com/en/articles/create-a-repo) 
      for your site with your chosen repo name. For clarity you may also want to rename the root 
      directory (`docsy-example`) of your working copy to match, though everything will still 
      work even if you don't.

   1. Configure 
      [`origin`](https://help.github.com/en/articles/configuring-a-remote-for-a-fork)
      in your project. From your site's root directory, set the URL for `origin` to your new 
      repo (otherwise you'll be trying to push changes to `google/docsy` rather than to your repo):

            git remote set-url origin https://github.com/MY-SITE/EXAMPLE.git


   1. Verify that your remote is configured correctly by running:
      
            git remote -v
 
	   
   1. Push your Docsy site to your repository:

            git push -u origin master

### Option 2: Use the Docsy theme in your own site

Specify the [Docsy theme](https://github.com/google/docsy) like any other Hugo theme when creating or updating your site. This gives you all the theme-y goodness but you'll need to specify your own site structure.  You can either use the theme as a submodule (our recommended approach for easy updates), or just clone the theme into your project's `themes` subdirectory.

Whichever approach you use, for simplicity we recommend copying and editing our [example site configuration](#configuring-your-site) for your project, or you may get Hugo errors for missing parameters and values when you try to build your site.

#### Using the Docsy theme as a submodule

Adding Docsy as a Git submodule is our recommended approach for using the theme, as it means your project
always refers to the Docsy repo version at your chosen revision, rather than you having your own copy in 
your repo that may result in merge conflicts when you try to update it. This is the approach used by our
[example project](https://github.com/google/docsy-example).


To create a new Hugo site project and then add the Docs theme as a submodule, run the following commands from your project's root directory. 

```shell
hugo new site myproject
cd myproject
git init
git submodule add https://github.com/google/docsy.git themes/docsy
echo 'theme = "docsy"' >> config.toml
git submodule update --init --recursive
```

To add the Docsy theme to an existing site, run the following commands from your project's root directory:

```
git submodule add https://github.com/google/docsy.git themes/docsy
echo 'theme = "docsy"' >> config.toml
git submodule update --init --recursive
```

#### Cloning the Docsy theme to your project's `themes` subdirectory

If you don't want to use a submodules (for example, if you want to customize and maintain your  own copy of the theme directly, or your deployment choice requires you to include a copy of the theme in your repository), you can clone the theme into your project.




To clone Docsy into your project's `theme` folder, run the following commands from your project's root directory:

```
cd themes
git clone https://github.com/google/docsy
```

For more information, see [Install and Use Themes](https://gohugo.io/themes/installing-and-using-themes/#install-a-single-theme) on the [Hugo](https://gohugo.io) site.

#### Preview your site

To build and preview your site locally:

```
cd myproject
hugo server
```
    
By default, your site will be available at http://localhost:1313/.

## Basic site configuration

Site-wide configuration details and parameters are defined in your project's `config.toml` file. These include your chosen Hugo theme (Docsy, of course!), project name, community links, Google Analytics configuration, and Markdown parser parameters. See the examples with comments in [`config.toml` in the example project](https://github.com/google/docsy-example/blob/master/config.toml) for how to add this information. **We recommend copying this `config.toml` and editing it even if you're just using the theme and not copying the entire Docsy example site**.

The Docsy example site comes with some defaults you may want to remove or customize straight away:

### Internationalization

The Docsy example site supports content in English and Norwegian. You can find out more about how Docsy supports multi-language content in [Multi-language support](/docs/language/_index.md).

If you don't intend to translate your site to Norwegian, you can remove the language switcher by removing the following lines from `config.toml`:

```
[languages.no]
title = "Docsy"
description = "Docsy er operativsystem for skyen"
languageName ="Norsk"
contentDir = "content/no"
```

To remove the translated source files, delete the `docsy-example/content/no` directory.

### Search

By default, the Docsy example site uses its own [Google Custom Search Engine](https://cse.google.com/cse/all). To disable site search, delete or comment out the following lines:

```
# Google Custom Search Engine ID. Remove or comment out to disable search.
gcs_engine_id = "011737558837375720776:fsdu1nryfng"
```

To use your own Custom Search Engine, replace the value in the `gcs_engine_id` with the ID of your own search engine.


## What's next?

* [Add content and customize your site](/docs/adding-content/)
* Get some ideas from our [Example Site](https://github.com/google/docsy-example) and other [Examples](/docs/examples/).
* [Publish your site](/docs/deployment/).


	
