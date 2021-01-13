"""Wrappers for website documentation."""

load("//tools:defs.bzl", "short_path")

# DocInfo is a provider which simple adds sufficient metadata to the source
# files (and additional data files) so that a jeyll header can be constructed
# dynamically. This is done the via BUILD system so that the plain
# documentation files can be viewable without non-compliant markdown headers.
DocInfo = provider(
    "Encapsulates information for a documentation page.",
    fields = [
        "layout",
        "description",
        "permalink",
        "category",
        "subcategory",
        "weight",
        "editpath",
        "authors",
        "include_in_menu",
    ],
)

def _doc_impl(ctx):
    return [
        DefaultInfo(
            files = depset(ctx.files.src + ctx.files.data),
        ),
        DocInfo(
            layout = ctx.attr.layout,
            description = ctx.attr.description,
            permalink = ctx.attr.permalink,
            category = ctx.attr.category,
            subcategory = ctx.attr.subcategory,
            weight = ctx.attr.weight,
            editpath = short_path(ctx.files.src[0].short_path),
            authors = ctx.attr.authors,
            include_in_menu = ctx.attr.include_in_menu,
        ),
    ]

doc = rule(
    implementation = _doc_impl,
    doc = "Annotate a document for jekyll headers.",
    attrs = {
        "src": attr.label(
            doc = "The markdown source file.",
            mandatory = True,
            allow_single_file = True,
        ),
        "data": attr.label_list(
            doc = "Additional data files (e.g. images).",
            allow_files = True,
        ),
        "layout": attr.string(
            doc = "The document layout.",
            default = "docs",
        ),
        "description": attr.string(
            doc = "The document description.",
            default = "",
        ),
        "permalink": attr.string(
            doc = "The document permalink.",
            mandatory = True,
        ),
        "category": attr.string(
            doc = "The document category.",
            default = "",
        ),
        "subcategory": attr.string(
            doc = "The document subcategory.",
            default = "",
        ),
        "weight": attr.string(
            doc = "The document weight.",
            default = "50",
        ),
        "authors": attr.string_list(),
        "include_in_menu": attr.bool(
            doc = "Include document in the navigation menu.",
            default = True,
        ),
    },
)

def _docs_impl(ctx):
    # Tarball is the actual output.
    tarball = ctx.actions.declare_file(ctx.label.name + ".tgz")

    # But we need an intermediate builder to translate the files.
    builder = ctx.actions.declare_file("%s-builder" % ctx.label.name)
    builder_content = [
        "#!/bin/bash",
        "set -euo pipefail",
        "declare -r T=$(mktemp -d)",
        "function cleanup {",
        "    rm -rf $T",
        "}",
        "trap cleanup EXIT",
    ]
    for dep in ctx.attr.deps:
        doc = dep[DocInfo]

        # Sanity check the permalink.
        if not doc.permalink.endswith("/"):
            fail("permalink %s for target %s should end with /" % (
                doc.permalink,
                ctx.label.name,
            ))

        # Construct the header.
        header = """\
description: {description}
permalink: {permalink}
category: {category}
subcategory: {subcategory}
weight: {weight}
editpath: {editpath}
authors: {authors}
layout: {layout}
include_in_menu: {include_in_menu}"""

        for f in dep.files.to_list():
            # Is this a markdown file? If not, then we ensure that it ends up
            # in the same path as the permalink for relative addressing.
            if not f.basename.endswith(".md"):
                builder_content.append("mkdir -p $T/%s" % doc.permalink)
                builder_content.append("cp %s $T/%s" % (f.path, doc.permalink))
                continue

            # Is this a post? If yes, then we must put this in the _posts
            # directory. This directory is treated specially with respect to
            # pagination and page generation.
            dest = f.short_path
            if doc.layout == "post":
                dest = "_posts/" + f.basename
            builder_content.append("echo Processing %s... >&2" % f.short_path)
            builder_content.append("mkdir -p $T/$(dirname %s)" % dest)

            # Construct the header dynamically. We include the title field from
            # the markdown itself, as this is the g3doc format required. The
            # title will be injected by the web layout however, so we don't
            # want this to appear in the document.
            args = dict([(k, getattr(doc, k)) for k in dir(doc)])
            builder_content.append("title=\"$(grep -E '^# ' %s | head -n 1 | cut -d'#' -f2- || true)\"" % f.path)
            builder_content.append("cat >$T/%s <<EOF" % dest)
            builder_content.append("---")
            builder_content.append("title: $title")
            builder_content.append(header.format(**args))
            builder_content.append("---")
            builder_content.append("EOF")

            # To generate the final page, we need to strip out the title (which
            # was pulled above to generate the annotation in the frontmatter,
            # and substitute the [TOC] tag with the {% toc %} plugin tag. Note
            # that the pipeline here is almost important, as the grep will
            # return non-zero if the file is empty, but we ignore that within
            # the pipeline.
            builder_content.append("grep -v -E '^# ' %s | sed -e 's|^\\[TOC\\]$|- TOC\\n{:toc}|' >>$T/%s" %
                                   (f.path, dest))

    builder_content.append("declare -r filename=$(readlink -m %s)" % tarball.path)
    builder_content.append("(cd $T && tar -zcf \"${filename}\" .)\n")
    ctx.actions.write(builder, "\n".join(builder_content), is_executable = True)

    # Generate the tarball.
    ctx.actions.run(
        inputs = depset(ctx.files.deps),
        outputs = [tarball],
        progress_message = "Generating %s" % ctx.label,
        executable = builder,
    )
    return [DefaultInfo(
        files = depset([tarball]),
    )]

docs = rule(
    implementation = _docs_impl,
    doc = "Construct a site tarball from doc dependencies.",
    attrs = {
        "deps": attr.label_list(
            doc = "All document dependencies.",
        ),
    },
)
