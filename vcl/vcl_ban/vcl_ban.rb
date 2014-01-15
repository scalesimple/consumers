module SSConsumer
	
	class VclBan

        attr_reader :servers

		def load_config
    		config_file= File.expand_path("../../config/config.yml", __FILE__)
    		f = File.open(config_file)
    		@config = YAML.load(f)
    		f.close
  		end

  		def initialize
  			load_config
  			@servers = @config["varnish_servers"]
  			@logger = SSConsumer::Logger.new
  		end

  		def setup_agent(server)
        	s = Patron::Session.new
			s.username = @config["agent_username"]
			s.password = @config["agent_password"]
			s.base_url = 'http://' + server + ':' + @config["agent_port"].to_s
			s
        end

        def issue_ban(server,host,path)
        	if path.empty? 
        		ban_syntax = 'obj.http.X-SS-PURGEHOST == "' + host + '"'
        	else
        		ban_syntax = 'obj.http.X-SS-PURGEHOST == "' + host + '" && obj.http.X-SS-PURGEURL == "' + path + '"'
            end

        	s = setup_agent(server)
        	path = '/ban' 
    			resp = s.post(path,ban_syntax)
    			@logger.log('Ban response ' + resp.body, 'debug')
        end

        def ban(host,path)
        	@logger.log("Ban request received for #{host} and #{path}",'debug')
        	@servers.each { |srv|
        		issue_ban(srv,host,path)
        	}
        end

    end # end VclBan
end  # end SSConsumer