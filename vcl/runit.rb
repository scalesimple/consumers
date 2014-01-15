require 'daemons'
require './vcl'


  Daemons.run_proc('vcl_daemon.rb') do
    s = SSConsumer::Subscriber.new
    s.subscribe
  end
