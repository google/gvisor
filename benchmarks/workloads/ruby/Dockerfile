# example based on https://github.com/errm/fib

FROM ruby:2.5

RUN apt-get update -qq && apt-get install -y build-essential libpq-dev nodejs libsodium-dev

# Set an environment variable where the Rails app is installed to inside of Docker image
ENV RAILS_ROOT /var/www/app_name
RUN mkdir -p $RAILS_ROOT

# Set working directory
WORKDIR $RAILS_ROOT

# Setting env up
ENV RAILS_ENV='production'
ENV RACK_ENV='production'

# Adding gems
COPY Gemfile Gemfile
COPY Gemfile.lock Gemfile.lock
RUN bundle install --jobs 20 --retry 5 --without development test

# Adding project files
COPY . .

EXPOSE $PORT
STOPSIGNAL SIGINT
CMD ["bundle", "exec", "puma", "config.ru"]
