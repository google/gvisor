---
title: "Hugo Content Tips"
linkTitle: "Hugo Content Tips"
weight: 9
description: >
  Tips for authoring content for your Docsy-themed Hugo site.
---

Docsy is a theme for the [Hugo](https://gohugo.io/) static site 
generator. If you're not already familiar with Hugo and, in particular, its version of Markdown, this page provides some 
useful tips and potential gotchas for adding and editing content for your site. Feel free to add your own!

## Nested lists

Hugo currently uses the [Blackfriday](https://github.com/russross/blackfriday) Markdown processor, which can be 
sensitive when it come to content that's deeply nested in a list. In particular, be aware that
[this known issue](https://github.com/russross/blackfriday/issues/329) can surface if or when you have multiple authors and
other contributors who might mix 'tabs' and 'spaces' when indenting lists, or fail to indent properly.

An additional factor here is that because GitHub uses a different Markdown processor, GitHub markdown and the editor UI may
render some nested lists properly, while Blackfriday might render that same content poorly. For example, the count in a
numbered list might restart, or your nested content within a list is not indented 
(shows as a peer element instead of a nested child element). You may want to recommend in your contribution guidelines
([as we do](/docs/contribution-guidelines/#contributing-to-these-docs)) that contributors preview their content with Hugo
(or use Netlify's preview feature for PRs if that's your chosen deployment tool) to ensure their content renders correctly
with Blackfriday.

{{% alert title="Tip" %}}
[Per comments on the known issue](https://github.com/russross/blackfriday/issues/329#issuecomment-277602856), some
users have found that using 4 spaces instead of a 'tab' results in consistent behavior. For example, consider
configuring your local editor to use 4 spaces when the **Tab** key is pressed.
{{% /alert %}}

## Linking

By default, regular relative URLs in links are left unchanged by Hugo (they're still relative links in your site's generated HTML), hence some hardcoded relative links like `[relative cross-link](../../peer-folder/sub-file.md)` might behave unexpectedly compared to how they work on your local file system. You may find it helpful to use some of Hugo's built-in [link shortcodes](https://gohugo.io/content-management/cross-references/#use-ref-and-relref) to avoid broken links in your generated site. For example a `{< ref "filename.md" >}` link in Hugo will actually
find and automatically link to your file named `filename.md`. 

Note, however, that `ref` and `relref` links don't work with `_index` or `index` files (for example, this site's [content landing page](`/docs/adding-content/`)): you'll need to use regular Markdown links to section landing or other index pages. Specify these links relative to the site's root URL, for example: `/docs/adding-content/`.

[Learn more about linking](/docs/adding-content/content/#working-with-links). 
