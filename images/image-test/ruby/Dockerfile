FROM ruby:3.3.5

RUN gem install sinatra rackup puma

COPY server.rb /server.rb
CMD ["ruby", "/server.rb"]
