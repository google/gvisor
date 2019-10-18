---
title: "Docsy Shortcodes"
linkTitle: "Docsy Shortcodes"
date: 2017-01-05
weight: 5
description: >
  Use Docsy's Hugo shortcodes to quickly build site pages.
resources:
- src: "**spruce*.jpg"
  params:
    byline: "Photo: Bjørn Erik Pedersen / CC-BY-SA"
---

Rather than writing all your site pages from scratch, Hugo lets you define and use [shortcodes](https://gohugo.io/content-management/shortcodes/). These are reusable snippets of content that you can include in your pages, often using HTML to create effects that are difficult or impossible to do in simple Markdown. Shortcodes can also have parameters that let you, for example, add your own text to a fancy shortcode text box. As well as Hugo's [built-in shortcodes](https://gohugo.io/content-management/shortcodes/), Docsy provides some shortcodes of its own to help you build your pages.

## Shortcode blocks

The theme comes with a set of custom  **Page Block** shortcodes that can be used to compose landing pages, about pages, and similar.

These blocks share some common parameters:

height
: A pre-defined height of the block container. One of `min`, `med`, `max`, `full`, or `auto`. Setting it to `full` will fill the Viewport Height, which can be useful for landing pages.

color
: The block will be assigned a color from the theme palette if not provided, but you can set your own if needed. You can use all of Bootstrap's color names, theme color names or a grayscale shade. Some examples would be `primary`, `white`, `dark`, `warning`, `light`, `success`, `300`, `blue`, `orange`. This will become the **background color** of the block, but text colors will adapt to get proper contrast.

### blocks/cover

The **blocks/cover** shortcode creates a landing page type of block that fills the top of the page.

```html
{{</* blocks/cover title="Welcome!" image_anchor="center" height="full" color="primary" */>}}
<div class="mx-auto">
	<a class="btn btn-lg btn-primary mr-3 mb-4" href="{{</* relref "/docs" */>}}">
		Learn More <i class="fas fa-arrow-alt-circle-right ml-2"></i>
	</a>
	<a class="btn btn-lg btn-secondary mr-3 mb-4" href="https://example.org">
		Download <i class="fab fa-github ml-2 "></i>
	</a>
	<p class="lead mt-5">This program is now available in <a href="#">AppStore!</a></p>
	<div class="mx-auto mt-5">
		{{</* blocks/link-down color="info" */>}}
	</div>
</div>
{{</* /blocks/cover */>}}
```

Note that the relevant shortcode parameters above will have sensible defaults, but is included here for completeness.

{{% alert title="Hugo Tip" %}}
> Using the bracket styled shortcode delimiter, `>}}`, tells Hugo that the inner content is HTML/plain text and needs no further processing. Changing the delimiter to `%}}` means Hugo will treat the content as Markdown. You can use both styles in your pages.
{{% /alert %}}


| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| title | | The main display title for the block. | 
| image_anchor | |
| height | | See above.
| color | | See above. 


To set the background image, place an image with the word "background" in the name in the page's [Page Bundle](/docs/adding-content/content/#page-bundles). For example, in our the example site the background image in the home page's cover block is [`featured-background.jpg`](https://github.com/google/docsy-example/tree/master/content/en), in the same directory.

{{% alert title="Tip" %}}
If you also include the word **featured** in the image name, e.g. `my-featured-background.jpg`, it will also be used as the Twitter Card image when shared.
{{% /alert %}}

For available icons, see [Font Awesome](https://fontawesome.com/icons?d=gallery&m=free).

### blocks/lead

The **blocks/lead** block shortcode is a simple lead/title block with centred text and an arrow down pointing to the next section.

```go-html-template
{{%/* blocks/lead color="dark" */%}}
TechOS is the OS of the future. 

Runs on **bare metal** in the **cloud**!
{{%/* /blocks/lead */%}}
```

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| height | | See above.
| color | | See above. 

### blocks/section

The **blocks/section** shortcode is meant as a general-purpose content container. It comes in two "flavors", one for general content and one with styling more suitable for wrapping a horizontal row of feature sections.

The example below shows a section wrapping 3 feature sections.


```go-html-template
{{</* blocks/section color="dark" */>}}
{{%/* blocks/feature icon="fa-lightbulb" title="Fastest OS **on the planet**!" */%}}
The new **TechOS** operating system is an open source project. It is a new project, but with grand ambitions.
Please follow this space for updates!
{{%/* /blocks/feature */%}}
{{%/* blocks/feature icon="fab fa-github" title="Contributions welcome!" url="https://github.com/gohugoio/hugo" */%}}
We do a [Pull Request](https://github.com/gohugoio/hugo/pulls) contributions workflow on **GitHub**. New users are always welcome!
{{%/* /blocks/feature */%}}
{{%/* blocks/feature icon="fab fa-twitter" title="Follow us on Twitter!" url="https://twitter.com/GoHugoIO" */%}}
For announcement of latest features etc.
{{%/* /blocks/feature */%}}
{{</* /blocks/section */>}}
```

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| height | | See above.
| color | | See above. 
| type  | | Specify "section" if you want a general container,  omit this parameter if you want this section to contain a horizontal row of features.

### blocks/feature

```go-html-template

{{%/* blocks/feature icon="fab fa-github" title="Contributions welcome!" url="https://github.com/gohugoio/hugo" */%}}
We do a [Pull Request](https://github.com/gohugoio/hugo/pulls) contributions workflow on **GitHub**. New users are always welcome!
{{%/* /blocks/feature */%}}

```

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| title | | The title to use.
| url | | The URL to link to.
| icon | | The icon class to use.


### blocks/link-down

The **blocks/link-down** shortcode creates a navigation link down to the next section. It's meant to be used in combination with the other blocks shortcodes.

```go-html-template

<div class="mx-auto mt-5">
	{{</* blocks/link-down color="info" */>}}
</div>
```

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| color | info | See above. 

## Shortcode helpers

###  alert

The **alert** shortcode creates an alert block that can be used to display notices or warnings.

```go-html-template
{{%/* alert title="Warning" color="warning" */%}}
This is a warning.
{{%/* /alert */%}}

```

Renders to:

{{% alert title="Warning" color="warning" %}}
This is a warning.
{{% /alert %}}

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| color | primary | One of the theme colors, eg `primary`, `info`, `warning` etc.

###  pageinfo

The **pageinfo** shortcode creates a text box that you can use to add banner information for a page: for example, letting users know that the page contains placeholder content, that the content is deprecated, or that it documents a beta feature.

```go-html-template
{{%/* pageinfo color="primary" */%}}
This is placeholder content.
{{%/* /pageinfo */%}}

```

Renders to:

{{% pageinfo color="primary" %}}
This is placeholder content
{{% /pageinfo %}}

| Parameter        | Default    | Description  |
| ---------------- |------------| ------------|
| color | primary | One of the theme colors, eg `primary`, `info`, `warning` etc.


###  imgproc

The **imgproc** shortcode finds an image in the current [Page Bundle](/docs/adding-content/content/#page-bundles) and scales it given a set of processing instructions.


```go-html-template
{{</* imgproc spruce Fill "400x450" */>}}
Norway Spruce Picea abies shoot with foliage buds.
{{</* /imgproc */>}}
```

{{< imgproc spruce Fill "400x450" >}}
Norway Spruce Picea abies shoot with foliage buds.
{{< /imgproc >}}

The example above has also a byline with photo attribution added. When using illustrations with a free license from [WikiMedia](https://commons.wikimedia.org/) and simlilar, you will in most situations need a way to attribute the author or licensor. You can add metadata to your page resources in the page front matter. The `byline` param is used by convention in this theme:


```yaml
resources:
- src: "**spruce*.jpg"
  params:
    byline: "Photo: Bjørn Erik Pedersen / CC-BY-SA"
```


| Parameter        | Description  |
| ----------------: |------------|
| 1 | The image filename or enough of it to identify it (we do Glob matching)
| 2 | Command. One of `Fit`, `Resize` or `Fill`. See [Image Processing Methods](https://gohugo.io/content-management/image-processing/#image-processing-methods).
| 3 | Processing options, e.g. `400x450`. See [Image Processing Options](https://gohugo.io/content-management/image-processing/#image-processing-methods).

### swaggerui

The `swaggerui` shortcode can be placed anywhere inside a `swagger` layout; it renders [Swagger UI](https://swagger.io/tools/swagger-ui/) using any OpenAPI YAML or JSON file as source, which can be hosted anywhere (for example, the root `/static` folder of Hugo).

```go-html-template
{{</* swaggerui src="/openapi/openapi.yaml" */>}}
```

You can customize Swagger UI's look and feel by overriding Swagger's CSS or by editing and compiling a [Swagger UI dist](https://github.com/swagger-api/swagger-ui) yourself and replace `themes/docsy/static/css/swagger-ui.css`.
