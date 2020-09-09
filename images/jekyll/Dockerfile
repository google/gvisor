FROM jekyll/jekyll:4.0.0
USER root

RUN gem install \
        html-proofer:3.10.2 \
        nokogiri:1.10.1 \
        jekyll-autoprefixer:1.0.2 \
        jekyll-inline-svg:1.1.4 \
        jekyll-paginate:1.1.0 \
        kramdown-parser-gfm:1.1.0 \
        jekyll-relative-links:0.6.1 \
        jekyll-feed:0.13.0 \
        jekyll-sitemap:1.4.0

# checks.rb is used with html-proofer for presubmit checks.
COPY checks.rb /checks.rb

COPY build.sh /build.sh
CMD ["/build.sh"]
