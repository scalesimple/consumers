require 'patron'
require 'json'
require 'pathname'

cwd = Pathname(__FILE__).dirname
$:.unshift(cwd.to_s) unless $:.include?(cwd.to_s) || $:.include?(cwd.expand_path.to_s)

require 'logger/logger'
require 'dns_lib/dns_lib'
require 'subscriber/subscriber'


module SSConsumer

    def start
        s = SSConsumer::Subscriber.new
        s.subscribe 
    end

end
