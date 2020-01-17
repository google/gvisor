---
title: "Organizing Your Content"
linkTitle: "Organizing Your Content"
weight: 9
description: >
  Optional guidance and recommendations on how to organize your documentation site.
---

If you have a look at our [Example Site](https://example.docsy.dev/about/), you'll see that we've organized 
the Documentation section into a number of subsections, each with some recommendations about what you might put 
in that section.

## Do I need to use this structure?

Absolutely not! The site structure in the Example Site was created to meet the needs of large docsets for large
products with lots of features, potential tasks, and reference elements. For a simpler docset (like this one!),
it's fine to just structure your docs around specific features that your users need to know about.  Even for larger
documentation sets, you may find that the structure isn't useful "as is", or that you don't need to use all the 
section types. 

We do recommend that (as we've done here) you provide at least:

* An **Overview** of the product (either on the docs landing page or a separate Overview page) that tells the user 
  why they should be interested in your project.
* A **Getting Started** page.
* Some **Examples**.

You may also want to create some tasks/how-tos for your project's features. Feel free to copy this Docsy user guide 
site or even just the docs section instead if you like this simpler structure better. 

{{% alert title="Tip" %}}
If you want to copy this guide, be aware that its [source files](https://github.com/google/docsy/tree/master/userguide) are *inside* the Docsy theme repo, and so it doesn't have its own `themes/` directory: instead, we run `hugo server --themesDir ../..` to use Docsy from its parent directory. You may want to either copy the site and [add a `themes/` directory with Docsy](/docs/getting-started/#option-2-use-the-docsy-theme-in-your-own-site), or just copy the `docs/` folder into your existing site's content root.
{{% /alert %}}

[Learn more about how Hugo and Docsy use folders and other files to organize your site](/docs/adding-content/content/#organizing-your-documentation).

## Why this structure?

We based the Example Site structure on our own experiences creating (and using) large documentation sets for
different types of project and on user research carried out on some of our bigger sites. In user studies we saw that 
users cared most about and immediately looked for a Get Started or Getting Started section 
(so they could, well, get started), and some examples to explore and copy, so we made those into prominent top-level doc 
sections in our site. Users also wanted to find "recipes" that they could easily look up to perform specific tasks and 
put together to create their own applications or projects, so we suggest that you add this kind of content as Tasks. 
Other content types such as conceptual docs, reference docs, and end-to-end tutorials are less important for all doc sets, 
particularly for smaller projects. We emphasize in our Example Site that these sections are optional.

We hope to improve the Example Site structure further as we learn more about how users interact with technical 
documentation, particularly for Open Source projects.

## Writing style guide

This guide and the example site just address how to organize your documentation content into pages and sections. For some g
uidance on how to organize and write the content in each page, we recommend the 
[Google Developer Documentation Style Guide](https://developers.google.com/style/), particularly the 
[Style Guide Highlights](https://developers.google.com/style/highlights).
