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
    		config_file= File.expand_path("../../config/config.yml", __FILE__)
    		f = File.open(config_file)
    		@config = YAML.load(f)
    		f.close
  		end

  		def subscribe
  			
		     user = @config["rabbit_username"]
		     pass = @config["rabbit_password"]
		     host = @config["rabbit_host"]

		     b = Bunny.new("amqp://#{user}:#{pass}@#{host}", :connect_timeout => 30)

		     # start a communication session with the amqp server
		     b.start

		     # create/get queue
		     q = b.queue(@config["rabbit_queue"])

		     # create/get exchange
		     exch = b.exchange('scalesimple', :durable => true)

		     # bind queue to exchange
		     q.bind(exch, :key => 'jobs.vcl')

		     # subscribe to queue
		     q.subscribe do |msg|
		       parse_payload("#{msg[:payload]}")
		     end
  		end

	def do_vcl(action,metadata=nil)
	      case action

	    	when 'generate_vcl'
	         vclgen = SSConsumer::VclGenerator.new(metadata["hostname_id"])
	         config = vclgen.generate_config
	         @logger.log("Now going to deploy the configs",'debug')
	         d = SSConsumer::VclDeploy.new(metadata["id"], metadata["hostname_id"])
	         d.deploy_configs(config)

	        when 'generate_ban'
	         b = SSConsumer::VclBan.new
	         host = metadata["hostname"]
	         path = metadata["path"] || "" 
	         @logger.log("Calling ban with #{host} and #{path}",'debug')
	         b.ban(host,path)

	        else
	         @logger.log('Received invalid action ' + action,'error') 	

	       end

        end

        def parse_payload(payload)
	      #begin
	      	 @logger.log("Received #{payload} on queue",'debug')
	         p = JSON.parse(payload)
	         action = p["action"]
	         metadata = p["payload"] || nil 
	         @logger.log("Action #{action} and meta #{metadata}",'debug')
	         do_vcl(action,metadata)
	       #rescue => e
	        #@logger.log("Error parsing payload : #{e}",'error')
	       #end
        end


  	end  # end class 

end #end module 

