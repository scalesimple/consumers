require './lib/dns'
require 'daemons'

   
  Daemons.run_proc('dns_daemon.rb') do
   s = SSConsumer::Subscriber.new
   s.subscribe
  end
