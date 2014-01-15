require 'patron'
require 'time'
require 'hmac-sha1'
require 'json'
require 'amqp'

module SSConsumer

 class DnsLib 

  attr_reader :dnsapi, :dns_secret, :domain, :debug , :cname_edge, :cname, :prefix

  def load_config
        config_file= File.expand_path("../../../config/config.yml", __FILE__)
        f = File.open(config_file)
        @config = YAML.load(f)
        f.close
  end

  def initialize(debug=false)
    load_config
    @dnsapi = @config["dns_api_key"]
    @dns_secret = @config["dns_api_secret"]
    @cname = @config["cname"]
    @cname_edge = @config["cname_edge"]
    @domain = @config["domain"]
    @debug = debug 
    @logger = SSConsumer::Logger.new
    @logger.log("Setting cname to #{@cname} and edge to #{@cname_edge}, debug set to #{@debug}")
  end


  #-------------------------------
  # setup some standard vars and the
  # necessary headers to make the request
  #-------------------------------
  def dns_setup_request
    date = Time.now.httpdate.to_s
    @sess = Patron::Session.new
    @sess.headers['x-dnsme-apiKey'] = @dnsapi
    @sess.headers['x-dnsme-requestDate'] = date
    @sess.headers['x-dnsme-hmac'] =  HMAC::SHA1.hexdigest(@dns_secret,date)
    @sess.headers['Content-Type'] =  'application/json'
  end 

  #-------------------------------
  # Search for the hostname, if it 
  # exists, return the id so we can 
  # delete it later 
  #-------------------------------
  def dns_search_hostname(hostname)
     dns_setup_request
     response = JSON.parse(@sess.get("http://api.dnsmadeeasy.com/V1.2/domains/#{@domain}/records?name=#{hostname}").body )
     return response[0]["id"] if !response.empty? && response.is_a?(Array) 
  end

  #-------------------------------
  # First search for the id of the 
  # hostname.  If it exists, delete it !!
  #-------------------------------
  def dns_delete_hostname(hostname)
    dns_setup_request
    id = dns_search_hostname(hostname)
    @sess.delete("http://api.dnsmadeeasy.com/V1.2/domains/#{@domain}/records/#{id}").body unless id.nil?

    #return if env == 'demo'

    # dns_setup_request('staging')
    # id = dns_search_hostname(hostname,'staging')
    # @sess.delete("http://api.dnsmadeeasy.com/V1.2/domains/#{@domain}/records/#{id}").body unless id.nil? 
  end

  #-------------------------------
  # Create TEST Hostname
  #-------------------------------
  def dns_add_test_hostname(hostname)
    demo_host = hostname + '.test' + '.' + @cname
    dns_delete_hostname(demo_host)
    
    dns_setup_request

    d = Hash.new
    d[:name] = demo_host
    d[:ttl] = '1800'
    d[:data] = @cname_edge
    d[:type] = 'CNAME'
    record = JSON.generate(d)
    @logger.log("Submitting #{demo_host} CNAMEd to #{@cname_edge} on #{@domain}..",'debug')
    response = JSON.parse(@sess.post("http://api.dnsmadeeasy.com/V1.2/domains/#{@domain}/records",record).body) 
    raise "Error creating dns request, #{response['error']} " if response["error"]
  end

  #-------------------------------
  # Add new hostname to both prod 
  # and to staging !!!
  #-------------------------------
  def dns_add_hostname(hostname)

    edge_host = hostname + '.' + @cname

    #-----------------------
    # Lets be safe :-) 
    #-----------------------
    dns_delete_hostname(edge_host)

    dns_setup_request

    d = Hash.new
    d[:name] = edge_host 
    d[:ttl] = '1800'
    d[:data] = @cname_edge
    d[:type] = 'CNAME'
    record = JSON.generate(d)
    @logger.log("Submitting #{edge_host} CNAMEd to #{@cname_edge} on #{@domain}..",'debug')
    response = JSON.parse(@sess.post("http://api.dnsmadeeasy.com/V1.2/domains/#{@domain}/records",record).body) 
    raise "Error creating dns request, #{response['error']} " if response["error"]

  end

 end ## end DnsLib

end ## end SSConsumer
