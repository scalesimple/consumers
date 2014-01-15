require 'yaml'
require 'bunny'
require 'json'

module SSConsumer

	class Subscriber

		attr_accessor :logger

		def initialize
        	load_config
        	@logger = SSConsumer::Logger.new
        end

        def load_config
    		config_file= File.expand_path("../../../config/config.yml", __FILE__)
    		f = File.open(config_file)
    		@config = YAML.load(f)
    		f.close
  		end

  		def subscribe
  			

		     user = @config["rabbit_username"]
		     pass = @config["rabbit_password"]
		     host = @config["rabbit_host"]

		     b = Bunny.new("amqp://#{user}:#{pass}@#{host}")

		     # start a communication session with the amqp server
		     b.start

		     # create/get queue
		     q = b.queue(@config["rabbit_queue"])

		     # create/get exchange
		     exch = b.exchange('scalesimple', :durable => true)

		     # bind queue to exchange
		     q.bind(exch, :key => 'jobs.hostname')

		     # subscribe to queue
		     q.subscribe do |msg|
		       parse_payload("#{msg[:payload]}")
		     end
  		end

  		def parse_payload(payload)
		    begin
		       p = JSON.parse(payload)
		       action = p["action"] 
		       @logger.log('Received invalid action #{action}','error') and return unless action == 'create_hostname'
		       hostname = p["payload"]["hostname"] 
		       @logger.log("Creating hostname " + hostname,'info')
		       d = SSConsumer::DnsLib.new 
		       d.dns_add_hostname(hostname)
		       d.dns_add_test_hostname(hostname)
		     rescue => e 
		      @logger.log("Error parsing payload : #{e}",'error')
		     end      
		end


  	end  # end class 

end #end module 

