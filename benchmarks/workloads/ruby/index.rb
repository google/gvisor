require "sinatra"
require "puma"
require "redis"
require "rake"
require "squid"
require "cassandra"
require "ruby-fann"
require "rbnacl"
require "bcrypt"
require "activemerchant"

get "/" do
  "Hello World!"
end