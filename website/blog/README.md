# gVisor blog

The gVisor blog is owned and run by the gVisor team.

## Contact

Reach out to us on the
[mailing list](https://groups.google.com/forum/#!forum/gvisor-users) if you
would like to write a blog post.

## Submit a Post

Anyone can write a blog post and submit it for review. Purely commercial content
or vendor pitches are not allowed. Please refer to the
[blog guidelines](#blog-guidelines) for more guidance about content is that
allowed.

To submit a blog post, follow the steps below.

1.  Familiarize yourself with the Markdown format for the
    [existing blog posts](https://github.com/gvisor/gvisor/tree/master/website/blog).
1.  Write your blog post in a text editor of your choice.
1.  (Optional) If you need help with markdown, check out
    [StakEdit](https://stackedit.io/app#) or read
    [Jekyll's formatting reference](https://jekyllrb.com/docs/posts/#creating-posts)
    for more information.
1.  Click **Add file** > **Create new file**.
1.  Paste your content into the editor and save it. Name the file in the
    following way: *[BLOG] Your proposed title* , but don’t put the date in the
    file name. The blog reviewers will work with you on the final file name, and
    the date on which the blog will be published.
1.  In the **Commit changes** dialog, sign off on your commit as described in
    the
    [Developer Certificate of Origin](https://gvisor.dev/contributing/#developer-certificate-of-origin)
    section: add a `Signed-off-by: Your Name <email>` line to the extended
    description. The email must be the commit author email. If the dialog shows
    an email selector, use the selected email. If not, use the primary email in
    your GitHub email settings. If you keep your email private, use your
    `@users.noreply.github.com` email from the same page.
1.  When you save the file, GitHub will walk you through the pull request (PR)
    process.
1.  Send us a message on the
    [mailing list](https://groups.google.com/forum/#!forum/gvisor-users) with a
    link to your recently created PR.
1.  A reviewer will be assigned to the pull request. They check your submission,
    and work with you on feedback and final details. When the pull request is
    approved, the blog will be scheduled for publication.

### Blog Guidelines {#blog-guidelines}

#### Suitable content:

-   **Original content only**
-   gVisor features or project updates
-   Tutorials and demos
-   Use cases
-   Content that is specific to a vendor or platform about gVisor installation
    and use

#### Unsuitable Content:

-   Blogs with no content relevant to gVisor
-   Vendor pitches

## SVG diagrams

Put a diagram in `website/_includes/<post-name>/` and embed it with a caption:

```liquid
{% include diagram.html src="my-post/flow.svg" caption="The request reaches the worker." %}
```

The include adds the frame, accessible label, and caption. The blog layout loads
`assets/js/diagrams.js` once on pages with diagrams to pause animations offscreen
and when the reader prefers reduced motion. Static diagrams use the same include.

Use a `viewBox` so the SVG scales to the available width. Give paths and markers
IDs that are unique across all diagrams on the page. The shared
`website/_sass/diagrams.scss` supplies the site's colors and typography through
these classes:

| Classes | Purpose |
| --- | --- |
| `d-name`, `d-note`, `d-tag` | Names, supporting labels, and boundary labels |
| `d-hot` | Accent-colored text |
| `d-box`, `d-box-hot` | Component boxes |
| `d-zone`, `d-ghost` | Filled boundaries and dashed outlines |
| `d-cell`, `d-cell-hot` | Data blocks and chart bars |
| `d-line`, `d-line-hot`, `d-dash` | Connections and dashed connections |
| `d-head`, `d-head-hot` | Arrowheads |
| `d-pulse` | Animated traffic dots |

Put animated elements in a `<g class="d-moving">` group, which is hidden for
readers who prefer reduced motion. Keep labels and connections outside that group
so the explanation remains visible without animation. Use the SVGs in
`website/_includes/tines-3b/` as examples.

Feed readers do not receive the diagram stylesheet. For posts with these diagrams,
add a default scoped to the generated post filename in `website/_config.yml` so
the feed includes an excerpt and a link to the article:

```yaml
  - scope:
      path: "_posts/YYYY-MM-DD-my-post.md"
    values:
      feed:
        excerpt_only: true
```

## Review Process

Each blog post should be approved by at least one person on the team. Once all
of the review comments have been addressed and approved, a member of the team
will schedule publication of the blog post.
