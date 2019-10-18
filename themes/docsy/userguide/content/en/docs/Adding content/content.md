---
title: "Adding Content"
linkTitle: "Adding Content"
weight: 1
description: >
  Add different types of content to your Docsy site.
---

So you've got a new Hugo website with Docsy, now it's time to add some content! This page tells you how to use the theme to add and structure your site content. 

## Content root directory

You add content for your site under the **content root directory** of your Hugo site project - either `content/` or a [language-specific](/docs/language/) root like `content/en/`. The main exception here is static files that you don't want built into your site: you can find out more about where you add these below in [Adding static content](#adding-static-content). The files in your content root directory are typically grouped in subdirectories corresponding to your site's sections and templates, which we'll look at in [Content sections and templates](#content-sections-and-templates).

You can find out more about Hugo directory structure in [Directory Structure Explained](https://gohugo.io/getting-started/directory-structure/#directory-structure-explained).

## Content sections and templates

Hugo builds your site pages using the content files you provide plus any templates provided by your site's theme. These templates (or *"layouts"* in Hugo terminology) include things like your page's headers, footers, navigation, and links to stylesheets: essentially, everything except your page's specific content. The templates in turn can be made up of *partials*: little reusable snippets of HTML for page elements like headers, search boxes, and more.

Because most technical documentation sites have different sections for different types of content, the Docsy theme comes with the [following templates](https://github.com/google/docsy/tree/master/layouts) for top-level site sections that you might need:

* [`docs`](https://github.com/google/docsy/tree/master/layouts/docs) is for pages in your site's Documentation section.
* [`blog`](https://github.com/google/docsy/tree/master/layouts/blog) is for pages in your site's Blog.
* [`community`](https://github.com/google/docsy/tree/master/layouts/community) is for your site's Community page.

It also provides a [default "landing page" type of template](https://github.com/google/docsy/tree/master/layouts/_default) with the site header and footer, but no left nav, that you can use for any other section. In this site and our example site it's used for the site [home page](/) and the [About](/about/) page.

Each top-level **section** in your site corresponds to a **directory** in your site content root. Hugo automatically applies the appropriate **template** for that section, depending on which folder the content is in. For example, this page is in the `docs` subdirectory of the site's content root directory `content/en/`, so Hugo automatically applies the `docs` template. You can override this by explicitly specifying a template or content type for a particular page.

If you've copied the example site, you already have appropriately named top-level section directories for using Docsy's templates, each with an index page ( `_index.md` or `index.html`) page for users to land on. These top-level sections also appear in the example site's [top-level menu](/docs/adding-content/navigation/#top-level-menu). 

### Custom sections

If you've copied the example site and *don't* want to use one of the provided content sections, just delete the appropriate content subdirectory. Similarly, if you want to add a top-level section, just add a new subdirectory, though you'll need to specify the layout or content type explicitly in the [frontmatter](#page-frontmatter) of each page if you want to use any existing Docsy template other than the default one. For example, if you create a new directory `content/en/`**`amazing`** and want one or more pages in that custom section to use Docsy's `docs` template, you add `layout: docs` to the frontmatter of each page:

```yaml
---
title: "My amazing new section"
weight: 1
layout: docs
description: >
  A special section with a docs layout.
---
```

Alternatively, create your own page template for your new section in your project's `layouts` directory based on one of the existing templates.

You can find out much more about how Hugo page layouts work in [Hugo Templates](https://gohugo.io/templates/). The rest of this page tells you about how to add content and use each of Docsy's templates.

## Page frontmatter

Each page file in a Hugo site has metadata frontmatter that tells Hugo about the page. You specify page frontmatter in TOML, YAML, or JSON (our example site and this site use YAML). Use the frontmatter to specify the page title, description, creation date, link title, template, menu weighting, and even any resources such as images used by the page. You can see a complete list of possible page frontmatter in [Front Matter](https://gohugo.io/content-management/front-matter/).

For example, here's the frontmatter for this page:

```
---
title: "Adding Content"
linkTitle: "Adding Content"
weight: 1
description: >
  How to add content to your Docsy site.
---
```

The minimum frontmatter you need to provide is a title: everything else is up to you! (though if you leave out the page weight your [navigation](/docs/adding-content/navigation) may get a little disorganized).


## Page contents and markup

By default you create pages in a Docsy site as simple [Markdown or HTML files](https://gohugo.io/content-management/formats/) with [page frontmatter](#page-frontmatter), as described above. Hugo currently uses [BlackFriday](https://github.com/russross/blackfriday) as its default Markdown parser.

In addition to your marked-up text, you can also use Hugo and Docsy's [shortcodes](/docs/adding-content/shortcodes): reusable chunks of HTML that you can use to quickly build your pages. Find out more about shortcodes in [Docsy Shortcodes](/docs/adding-content/shortcodes).

{{% alert title="Note" color="info" %}}
Hugo also supports adding content using other markups using [external parsers as helpers](https://gohugo.io/content-management/formats/#additional-formats-through-external-helpers). For example, you can add content in RST using `rst2html` as an external parser (though be aware this does not support all flavors of RST, such as Sphinx RST). Similarly, you can use `asciidoctor` to parse Asciidoc files, or `pandoc` for other formats.

External parsers may not be suitable for use with all deployment options, as you'll need to install the external parser and run Hugo yourself to generate your site (so, for example, you won't be able to use [Netlify's continuous deployment feature](/docs/deployment/#deployment-with-netlify)). In addition, adding an external parser may cause performance issues building larger sites.
{{% /alert %}}

### Working with links

Hugo and Blackfriday let you specify links using normal Markdown syntax, though remember that you need to specify links relative to your site's root URL, and that relative URLs are left unchanged by Hugo in your site's generated HTML.

Alternatively you can use Hugo's helper [`ref` and `relref` shortcodes](https://gohugo.io/content-management/cross-references/) for creating internal links that resolve to the correct URL. However, be aware this means your links will not appear as links at all if a user views your page outside your generated site, for example using the rendered Markdown feature in GitHub's web UI.

You can find (or add!) tips and gotchas for working with Hugo links in [Hugo Tips](/docs/best-practices/site-guidance).

### Content style

We don't mandate any particular style for your page contents. However, if you'd like some guidance on how to write and format clear, concise technical documentation, we recommend the [Google Developer Documentation Style Guide](https://developers.google.com/style/), particularly the [Style Guide Highlights](https://developers.google.com/style/highlights).

## Page bundles

You can create site pages as standalone files in their section or subsection directory, or as folders where the content is in the folder's index page. Creating a folder for your page lets you [bundle](https://gohugo.io/content-management/page-bundles/) images and other resources together with the content. 

You can see examples of both approaches in this and our example site. For example, the source for this page is just a standalone file `/content/en/docs/adding-content.md`. However the source for [Docsy Shortcodes](/docs/adding-content/shortcodes/) in this site lives in `/content/en/docs/adding-content/shortcodes/index.md`, with the image resource used by the page in the same `/shortcodes/` directory. In Hugo terminology, this is called a *leaf bundle* because it's a folder containing all the data for a single site page without any child pages (and uses `index.md` without an underscore).

You can find out much more about managing resources with Hugo bundles in [Page Bundles](https://gohugo.io/content-management/page-bundles/).

## Adding docs and blog posts

The template you'll probably use most often is the [`docs` template](https://github.com/google/docsy/blob/master/layouts/docs/baseof.html) (as used in this page) or the very similar [`blog` template](https://github.com/google/docsy/blob/master/layouts/blog/baseof.html). Both these templates include:

* a left nav
* GitHub links (populated from your site config) for readers to edit the page or create issues
* a page menu

as well as the common header and footer used by all your site's pages. Which template is applied depends on whether you've added the content to the `blog` or `docs` content directory. You can find out more about how the nav and page menu are created in [Navigation and Search](/docs/adding-content/navigation/). 

### Organizing your documentation

While Docsy's top-level sections let you create site sections for different types of content, you may also want to organize your docs content within your `docs` section. For example, this site's `docs` section directory has multiple subdirectories for **Getting Started**, **Content and Customization**, and so on. Each subdirectory has an `_index.md` (it could also be an `_index.html`), which acts as a section index page and tells Hugo that the relevant directory is a subsection of your docs.

Docsy's `docs` layout gives you a left nav pane with an autogenerated nested menu based on your `docs` file structure. Each standalone page or subsection `_index.md` or `_index.html`  page in the `docs/` directory gets a top level menu item, using the link name and `weight` metadata from the page or index. 

To add docs to a subsection, just add your page files to the relevant subdirectory. Any pages that you add to a subsection in addition to the subsection index page will appear in a submenu (look to the left to see one in action!), again ordered by page `weight`. Find out more about adding Docsy's navigation metadata in [Navigation and Search](/docs/adding-content/navigation/)

If you've copied the example site, you'll already have some suggested subdirectories in your `docs` directory, with guidance for what types of content to put in them and some example Markdown pages. You can find out more about organizing your content with Docsy in [Organizing Your Content](/docs/organizing/).

#### Docs section landing pages

By default a docs section landing page (the `_index.md` or `_index.html` in the section directory) uses a layout that adds a formatted list of links to the pages in the section, with their frontmatter descriptions. The [Content and Customization](/docs/adding-content/) landing page in this site is a good example.

To display a simple bulleted list of links to the section's pages instead, specify `simple_list: true` in the landing page's frontmatter:

```
---
title: "Simple List Page"
simple_list: true
weight: 20
---
```

To display no links at all, specify `no_list: true` in the landing page's frontmatter:

```
---
title: "No List Page"
no_list: true
weight: 20
---
```

### Organizing your blog posts

Docsy's `blog` layout also gives you a left nav menu (like the `docs` layout), and a list-type index page for your blog that's applied to `/blog/_index.md` and automatically displays snippets of all your recent posts in reverse chronological order. 

To create different blog categories to organize your posts, create subfolders in `blog/`. For instance, in our [example site](https://github.com/google/docsy-example/tree/master/content/en/blog) we have `news` and `releases`. Each category needs to have its own `_index.md` or `_index.html` landing page file specifying the category title for it to appear properly in the left nav and top-level blog landing page. Here's the index page for `releases`:

```
---
title: "New Releases"
linkTitle: "Releases"
weight: 20
---
```

To add author and date information to blog posts, add them to the page frontmatter:

```
---
date: 2018-10-06
title: "Easy documentation with Docsy"
linkTitle: "Announcing Docsy"
description: "The Docsy Hugo theme lets project maintainers and contributors focus on content, not on reinventing a website infrastructure from scratch"
author: Riona MacNamara
resources:
- src: "**.{png,jpg}"
  title: "Image #:counter"
  params:
    byline: "Photo: Riona MacNamara / CC-BY-CA"
---
```

If you've copied the example site and you don't want a blog section, or want to link to an external blog instead, just delete the `blog` subdirectory.


## Working with top-level landing pages.

Docsy's [default page template](https://github.com/google/docsy/blob/master/layouts/docs/baseof.html) has no left nav and is useful for creating a home page for your site or other "landing" type pages.

### Customizing the example site pages

If you've copied the example site, you already have a simple site landing page in `content/en/_index.html`. This is made up of Docsy's provided Hugo shortcode [page blocks](/docs/adding-content/shortcodes).

To customize the large landing image, which is in a [cover](#blocks-cover) block, replace the `content/en/featured-background.jpg` file in your project with your own image (it can be called whatever you like as long as it has `background` in the file name). You can remove or add as many blocks as you like, as well as adding your own custom content. 

The example site also has an About page in `content/en/about/_index.html` using the same Docsy template. Again, this is made up of [page blocks](/docs/adding-content/shortcodes), including another background image in `content/en/about/featured-background.jpg`. As with the site landing page, you can replace the image, remove or add blocks, or just add your own content.

### Building your own landing pages

If you've just used the theme, you can still use all Docsy's provided [page blocks](/docs/adding-content/shortcodes)  (or any other content you want) to build your own landing pages in the same file locations.

## Adding a community page

The `community` landing page template has boilerplate content that's automatically filled in with the project name and community links specified in `config.toml`, providing your users with quick links to resources that help them get involved in your project. The same links are also added by default to your site footer.

```toml
[params.links]
# End user relevant links. These will show up on left side of footer and in the community page if you have one.
[[params.links.user]]
	name = "User mailing list"
	url = "https://example.org/mail"
	icon = "fa fa-envelope"
        desc = "Discussion and help from your fellow users"
[[params.links.user]]
	name ="Twitter"
	url = "https://example.org/twitter"
	icon = "fab fa-twitter"
        desc = "Follow us on Twitter to get the latest news!"
[[params.links.user]]
	name = "Stack Overflow"
	url = "https://example.org/stack"
	icon = "fab fa-stack-overflow"
        desc = "Practical questions and curated answers"
# Developer relevant links. These will show up on right side of footer and in the community page if you have one.
[[params.links.developer]]
	name = "GitHub"
	url = "https://github.com/google/docsy"
	icon = "fab fa-github"
        desc = "Development takes place here!"
[[params.links.developer]]
	name = "Slack"
	url = "https://example.org/slack"
	icon = "fab fa-slack"
        desc = "Chat with other project developers"
[[params.links.developer]]
	name = "Developer mailing list"
	url = "https://example.org/mail"
	icon = "fa fa-envelope"
        desc = "Discuss development issues around the project"
``` 

If you're creating your own site and want to add a page using this template, add a `/community/_index.md` file in your content root directory. If you've copied the example site and *don't* want a community page, just delete the `/content/en/community/` directory in your project repo.

## Adding static content

You may want to serve some non-Hugo-built content along with your site: for example, if you have generated reference docs using Doxygen, Javadoc, or other doc generation tools. 

To add static content to be served "as-is", just add the content as a folder and/or files in your site's `static` directory. When your site is deployed, content in this directory is served at the site root path. So, for example, if you have added content at `/static/reference/cpp/`, users can access that content at `http://{server-url}/reference/cpp/` and you can link to pages in this directory from other pages at `/reference/cpp/{file name}`.

You can also use this directory for other files used by your project, including image files. You can find out more about serving static files, including configuring multiple directories for static content, in [Static Files](https://gohugo.io/content-management/static-files/).

## RSS feeds

Hugo will, by default, create an RSS feed for the home page and any section. For the main RSS feed you can control which sections to include by setting a site param in your `config.toml`. This is the default configuration:

```toml
rss_sections = ["blog"]
```
To disable all RSS feeds, add the following to your `config.toml`:

```toml
disableKinds = ["RSS"]
```

## Sitemap

Hugo creates a `sitemap.xml` file for your generated site by default: for example, [here's the sitemap](/sitemap.xml) for this site.

You can configure the frequency with which your sitemap is updated, your sitemap filename, and the default page priority in your `config.toml`:

```toml
[sitemap]
  changefreq = "monthly"
  filename = "sitemap.xml"
  priority = 0.5
```

To override any of these values for a given page, specify it in page frontmatter:

```yaml
---
title: "Adding Content"
linkTitle: "Adding Content"
weight: 1
description: >
  Add different types of content to your Docsy site.
sitemap:
  priority: 1.0
---
```

To learn more about configuring sitemaps, see [Sitemap Template](https://gohugo.io/templates/sitemap-template/).

