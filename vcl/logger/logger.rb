module SSConsumer

	class Logger

        attr_reader :config, :debug, :logfile

        def initialize
        	load_config
        	@logfile = File.open(@config["logfile"],"a")
        end

        def load_config
    		config_file= File.expand_path("../../config/config.yml", __FILE__)
    		f = File.open(config_file)
    		@config = YAML.load(f)
    		f.close
  		end

        def debug
        	@config["debug"] == true
        end

		def log(msg,level='error')
	    	return if level == debug && @debug == false 
	    	@logfile.puts Time.now.to_s + ' : ' + msg 
	    	@logfile.flush
        end

	end

end