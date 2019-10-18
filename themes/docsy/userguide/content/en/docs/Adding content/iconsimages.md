---
title: "Logos and Images"
linkTitle: "Logos and Images"
date: 2017-01-05
weight: 6
description: >
  Add and customize logos, icons, and images in your project.
---

## Add your logo

Add your project logo as `assets/icons/logo.svg` in your project. This overrides the default Docsy logo in the theme. If you don't want a project logo, set `navbar_logo` to `false` (or delete the variable) in your `config.toml`:

```
navbar_logo = false
```

If you decide at a later stage that you'd like to add a logo to your navbar, you can set the parameter to `true`:

```
navbar_logo = true
```

{{% alert title="Tip" %}}
Your logo is included in the default Docsy navbar as an inline SVG with the following CSS styling (from [`_nav.scss`](https://github.com/google/docsy/blob/master/assets/scss/_nav.scss)):

```
svg {
    display: inline-block;
    margin: 0 10px;
    height: 30px;
}
```

To ensure your logo displays correctly, you may want to resize it, ensure it doesn't have height and width attributes so that its size is fully responsive, or override the default styling with your own CSS.
{{% /alert %}}

## Add your favicons

The easiest way to do this is to create a set of favicons via http://cthedot.de/icongen (which lets you create a huge range of icon sizes and options from a single image) and/or https://favicon.io/, and put them in your site project's `static/favicons` directory. This will override the default favicons from the theme.

Note that https://favicon.io/  doesn't create as wide a range of sizes as Icongen but *does* let you quickly create favicons from text: if you want to create text favicons you can use this site to generate them, then use Icongen to create more sizes (if necessary) from your generated `.png` file.

If you have special favicon requirements, you can create your own `layouts/partials/favicons.html` with your links.

## Add images

### Landing pages

Docsy's [`blocks/cover` shortcode](/docs/adding-content/shortcodes/#blocks-cover) make it easy to add large cover images to your landing pages. The shortcode looks for an image with the word "background" in the name inside the landing page's [Page Bundle](https://gohugo.io/content-management/page-bundles/) - so, for example, if you've copied the example site, the landing page image in `content/en/_index.html` is `content/en/featured-background.jpg`.

You specify the preferred display height of a cover block container (and hence its image) using the block's `height` parameter.  For a full viewport height, use `full`: 

```html
{{</* blocks/cover title="Welcome to the Docsy Example Project!" image_anchor="top" height="full" color="orange" */>}}
...
{{</* /blocks/cover */>}}
```

For a shorter image, as in the example site's About page, use one of `min`, `med`, `max` or `auto` (the actual height of the image):

```html
{{</* blocks/cover title="About the Docsy Example" image_anchor="bottom" height="min" */>}}
...
{{</* /blocks/cover */>}}
```

### Other pages

To add inline images to other pages, use the [`imgproc` shortcode](/docs/adding-content/shortcodes/#imgproc). Alternatively, if you prefer, just use regular Markdown or HTML images and add your image files to your project's `static` directory. You can find out more about using this directory in [Adding static content](/docs/adding-content/content/#adding-static-content).

## Images used on this site

Images used as background images in this site are in the [public domain](https://commons.wikimedia.org/wiki/User:Bep/gallery#Wed_Aug_01_16:16:51_CEST_2018) and can be used freely. The porridge image in the example site is by <a href="https://pixabay.com/users/iha31-560629/?utm_source=link-attribution&amp;utm_medium=referral&amp;utm_campaign=image&amp;utm_content=531209">iha31</a> from <a href="https://pixabay.com/?utm_source=link-attribution&amp;utm_medium=referral&amp;utm_campaign=image&amp;utm_content=531209">Pixabay</a>

