# Docsy

Docsy is a Hugo theme for technical documentation sets, providing simple navigation, site structure, and more.

You can find an example project that uses Docsy in the [Docsy Example Project repo](https://github.com/google/docsy-example). The Docsy Example Project is hosted at [https://testydocsy.netlify.com/](https://testydocsy.netlify.com/), where you can find detailed theme instructions under **Documentation -> Getting Started**.

To use the Docsy theme, you can either:

* Copy and edit the example site’s repo, which will also give you a skeleton structure for your top-level and documentation sections, or
* Specify the Docsy theme like any other [Hugo theme](https://gohugo.io/themes/installing-and-using-themes/)
 when creating or updating your site. This gives you all the theme-y goodness but you’ll need to specify your own site structure.

This is not an officially supported Google product. This project is currently maintained.

## Installation and prerequisites

You need a recent version of Hugo to build sites using this theme (preferably 0.45+). If you install from the [release page](https://github.com/gohugoio/hugo/releases), make sure to get the `extended` Hugo version which supports SCSS. Alternatively, on macOS you can install Hugo via Brew.

If you want to do stylesheet changes, you will also need `PostCSS` to create the final assets. You can also install it locally with:

```
npm install
````

To use a local version of the theme files, clone the repo using:

```
git clone --recurse-submodules --depth 1 https://github.com/google/docsy.git
```

## Theme documentation

Detailed documentation for this theme is in the Docsy Example Project under **Documentation -> Getting Started**.
The Docsy Example Project is on [GitHub](https://github.com/google/docsy-example) and is hosted at [https://testydocsy.netlify.com/](https://testydocsy.netlify.com/).
