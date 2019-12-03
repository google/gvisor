require "sinatra"
require "securerandom"
require "redis"

redis_host = ENV["host"]
$redis = Redis.new(host: redis_host)

def generateText
    for i in 0..99
        $redis.set(i, randomBody(1024))
    end
end

def randomBody(length)
    return SecureRandom.alphanumeric(length)
end

generateText
template = ERB.new(File.read('./index.erb'))

get "/" do
    texts = Array.new
    for i in 0..4
        texts.push($redis.get(rand(0..99)))
    end
    template.result_with_hash(text: texts)
end