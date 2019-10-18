
---
title: "Welcome to Docsy"
linkTitle: "Documentation"
menu:
  main:
    weight: 20
---

Welcome to the Docsy theme user guide! This guide shows you how to get started creating technical documentation sites using Docsy, including site customization and how to use Docsy's blocks and templates.

## What is Docsy?

Docsy is a theme for the [Hugo](https://gohugo.io/) static site generator that's specifically designed for technical 
documentation sets and has a lot of best practices built in. Use Docsy to get a working and reliable documentation 
site up and running fast, and then get back to focusing on great content for your users. 
[Learn more about Docsy](/about).

In addition to the theme itself, we provide an [example site](https://github.com/google/docsy-example) that uses lots of Docsy features and has a useful skeleton site structure (with advice for what to put in it!) for a large technical documentation set. You can copy the entire site and edit it for your own projects, or just explore the site and its source to see what Docsy can do. The site you're currently reading also uses Docsy and is a useful example of a smaller Docsy docset: feel free to copy it or borrow from it if it suits your needs better than the "big" example.

Docsy itself does **not** provide:

* **Source hosting and management**: Our theme and site source files live on [GitHub](https://github.com/), which is the simplest approach for most projects. However, you can also keep your project files in [GitLab](https://about.gitlab.com/), [BitBucket](https://bitbucket.org/product), locally, or wherever you like. Be aware that where your source files live may affect the Docsy features you can use (such as letting users file documentation issues) and site deployment options.
* **Site deployment**: You can find out about deployment options in [Previews and Deployment](./deployment/). This site uses [Netlify](https://www.netlify.com/). 

Docsy also doesn't actually generate your site's HTML files: that's Hugo's job! Hugo takes your Markdown or HTML doc source files and Docsy's theme files and builds them into a static site for deployment. You can find out more about Hugo and how it works in the [Hugo documentation](https://gohugo.io/documentation/).

## Is Docsy for me?

Docsy is particularly useful for medium to large technical documentation sets with 20+ pages of docs and/or multiple types of docs and pages: tutorials, reference documentation, blog posts, community pages, and so on.

If you have a smaller project with only a couple of pages of documentation and hence simpler navigation needs, Docsy may be too heavyweight a solution for you. Instead, consider:

* A simpler Hugo or Jekyll theme: find out what's available in Github Pages' [built-in Jekyll options](https://pages.github.com/themes/) and the [Hugo theme gallery](https://themes.gohugo.io/).
* A good README file that tells users what your project does and links to some examples.

If you have a very large documentation project, our example site structure may not be sufficient either, though you can still use our theme, possibly with heavier customization.

If you'd like to use Docsy's layouts but prefer to use Jekyll, [vsoch](https://github.com/vsoch) has created a [Docsy Jekyll port](https://github.com/vsoch/docsy-jekyll) that includes many of Docsy's features (though as this is a separate project it won't be automatically updated along with Docsy).

## Ready to get started?

Find out how to build and serve your first site in [Getting Started](./getting-started/). Or visit the [example site](https://example.docsy.dev) and [its repo](https://github.com/google/docsy-example) and start exploring!


