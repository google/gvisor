# example based on https://github.com/errm/fib
FROM alpine:3.9 as build

COPY Gemfile Gemfile.lock ./

RUN apk add --no-cache ruby ruby-dev ruby-bundler ruby-json build-base bash \
        && bundle install --frozen -j4 -r3 --no-cache --without development \
        && apk del --no-cache ruby-bundler \
        && rm -rf /usr/lib/ruby/gems/*/cache

FROM alpine:3.9 as prod

COPY --from=build /usr/lib/ruby/gems /usr/lib/ruby/gems
RUN apk add --no-cache ruby ruby-json ruby-etc redis apache2-utils \
        && ruby -e "Gem::Specification.map.each do |spec| \
      Gem::Installer.for_spec( \
        spec, \
        wrappers: true, \
        force: true, \
        install_dir: spec.base_dir, \
        build_args: spec.build_args, \
      ).generate_bin \
    end"

COPY . /app/.

STOPSIGNAL SIGINT
