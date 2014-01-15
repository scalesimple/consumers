module SSConsumer
	
	class VclDeploy

     
        attr_reader :servers, :ruleset_id, :status, :current_vcl, :hostname_id

        def load_config
    		config_file= File.expand_path("../../config/config.yml", __FILE__)
    		f = File.open(config_file)
    		@config = YAML.load(f)
    		f.close
  		end


  		def initialize(ruleset,hostname = nil)
  			load_config
  			@ruleset_id = ruleset
  			@hostname_id = hostname
  			@servers = @config["varnish_servers"]
  			@logger = SSConsumer::Logger.new
  			@status = nil
  			get_configs
  		end

  		def setup_agent(server)
        	s = Patron::Session.new
			s.username = @config["agent_username"]
			s.password = @config["agent_password"]
			s.base_url = 'http://' + server + ':' + @config["agent_port"].to_s
			s
        end

        #-------------------------------------------------------
        # Something broke, get everyone back to previous state
        #-------------------------------------------------------
        def restore_configs
        	@logger.log("Restoring previous configs")
			@current_vcl.each { |srv,vcl|
				activate_config(srv,vcl) 
			}
			@logger.log("About to make previous config in error state to mongo",'debug')
			Ruleset.find(@ruleset_id).invalidate
        end

        #------------------------------------------
        # Push new config to servers
        #------------------------------------------
		def deploy_configs(cfg)
			vcl = 'vcl.' + Time.now.tv_sec.to_s
			@servers.each { |srv|
				status = deploy_config(srv,cfg,vcl) 
				if status != 'SUCCESS'
					@logger.log('Received non-SUCCESS, restoring previous configs...','debug')
					restore_configs
					return
				end
			}
			@logger.log("About to push activate to mongo",'debug')
			Ruleset.find(@ruleset_id).activate
		end

		def deploy_config(server,cfg,vcl)
			s = setup_agent(server)
			path = '/vcl/' + vcl 
			resp = s.put(path,cfg)
			@status = resp.body.match(/VCL compiled/).nil? ? "FAILURE" : "SUCCESS"
			@logger.log("VCL Compile Status on #{server}: #{@status} Agent Response on #{server}: " + resp.body,'info')
			activate_config(server,vcl) if @status == 'SUCCESS'
			@status
		end

        #-----------------------------------
        # Activate config on servers
        #-----------------------------------
        def activate_config(server,vcl)
            @logger.log('Activating config ' + vcl + ' on server ' + server,'info')
        	s = setup_agent(server)
			path = '/vcldeploy/' + vcl 
			resp = s.put(path,'')
			@logger.log("VCL Activation response on #{server}: " + resp.body,'debug')
        end

        def get_config(server)
        	s = setup_agent(server)
			path = '/vcl/' 
			resp = s.get(path)
			resp.body.split("\n").each { |b| 
				next if b.match(/active/).nil?
				return config = b.split(/\s+/)[2]
			}
			nil
        end

		def get_configs
			@current_vcl = Hash.new
			@servers.each { |s|
				@current_vcl[s] = get_config(s)
			}
		end

	end

end