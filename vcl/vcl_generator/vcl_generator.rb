#! /usr/bin/env ruby 

#require File.expand_path(File.join(File.dirname(__FILE__), '..', 'config', 'environment'))

require 'ipaddress'
require 'bunny'
require 'json'

module SSConsumer

 class VclGenerator

  attr_accessor :hostname_id 

  def setup_config 

@vcl_imports = <<EOF
  import std; 
  import ssutil;
  import geoip; 
  import header;
  import digest; 


  #----------------------------------------
  # System Wide Subroutines
  #----------------------------------------
  sub cleanup_response_headers {
    unset resp.http.X-SS-PURGEURL;
    unset resp.http.X-SS-PURGEHOST; 
    unset resp.http.X-Varnish;
  }

  sub cleanup_request_headers {
    unset req.http.X-SS-ClientIP ; 
    unset req.http.X-SS-RequestStart ; 
    unset req.http.X-SS-Expiration;
    unset req.http.X-SS-Token; 
    unset req.http.X-SS-Key;
    unset req.http.ext ; 
    unset req.http.X-GeoIP-Client;
    unset req.http.X-GeoIP;
    unset req.http.X-SS-Key;
  }

  sub set_geoip { 
    set req.http.X-GeoIP-Client = client.ip;
    set req.http.X-GeoIP = geoip.country(req.http.X-GeoIP-Client);
  }

   sub validate_token_url {

     set req.http.X-SS-Token = regsuball(req.url,".*[?&]ss_token=([^&]+).*","\\1"); 
     set req.http.X-SS-Expiration = regsuball(req.url,".*[?&]ss_expiration=([^&]+).*","\\1");
     
     std.syslog(1,"EXPIRATION IS " + req.http.X-SS-Expiration); 

     set req.http.X-SS-Expiration2 = req.http.X-SS-Expiration;
     set req.http.X-SS-Token2 = req.http.X-SS-Token; 

     if (ssutil.time_expired(req.http.X-SS-Expiration) < 0) {
       error 403 "Token is expired" ; 
     }

     set req.url = regsuball(req.url,"\\?ss_token=[^&]+$",""); # strips when QS = "?sstoken=AAA"
     set req.url = regsuball(req.url,"\\?ss_token=[^&]+&","?"); # strips when QS = "?sstoken=AAA&foo=bar"
     set req.url = regsuball(req.url,"&ss_token=[^&]+",""); # strips when QS = "?foo=bar&sstoken=AAA" or QS = "?foo=bar&sstoken=AAA&bar=baz"

     set req.url = regsuball(req.url,"\\?ss_expiration=[^&]+$",""); # strips when QS = "?sstoken=AAA"
     set req.url = regsuball(req.url,"\\?ss_expiration=[^&]+&","?"); # strips when QS = "?sstoken=AAA&foo=bar"
     set req.url = regsuball(req.url,"&ss_expiration=[^&]+",""); # strips when QS = "?foo=bar&sstoken=AAA" or QS = "?foo=bar&sstoken=AAA&bar=baz"

     if (req.http.X-SS-Token != digest.hash_md5(req.http.X-SS-Key + digest.hash_md5(req.http.X-SS-Expiration + req.url + req.http.X-SS-Key ) )  ) {
        error 403 "Invalid Token"; 
      } 

     unset req.http.X-SS-Key ; 
     unset req.http.X-SS-Token ; 
     unset req.http.X-SS-Expiration ; 

  }

 sub validate_token_header {

     if (ssutil.time_expired(req.http.X-SS-Expiration) < 0) {
       error 403 "Token is expired" ; 
     }

     set req.http.X-Debug-Token = digest.hash_md5(req.http.X-SS-Key + digest.hash_md5(req.http.X-SS-Expiration + req.url + req.http.X-SS-Key ) ) ; 
     if (req.http.X-SS-Token != digest.hash_md5(req.http.X-SS-Key + digest.hash_md5(req.http.X-SS-Expiration + req.url + req.http.X-SS-Key ) ) ) {
        error 403 "Invalid Token in Header"; 
     } 

     unset req.http.X-SS-Key ; 
     unset req.http.X-SS-Token ; 
     unset req.http.X-SS-Expiration ; 

  }

  sub validate_token_cookie {

     set req.http.X-SS-Token = regsub( req.http.Cookie, "^.*?ss_token=([^;]*);*.*$", "\1" );
     set req.http.X-SS-Expiration = regsub( req.http.Cookie, "^.*?ss_expiration=([^;]*);*.*$", "\1" );

     unset req.http.Cookie ; 

     if (ssutil.time_expired(req.http.X-SS-Expiration) < 0) {
       error 403 "Token is expired" ; 
     }

     if (req.http.X-SS-Token != digest.hash_md5(req.http.X-SS-Key + digest.hash_md5(req.http.X-SS-Expiration + req.url + req.http.X-SS-Key ) ) ) {
        error 403 "Invalid Token in Cookie"; 
     } 

     unset req.http.X-SS-Key;
     unset req.http.X-SS-Token;
     unset req.http.X-SS-Expiration;

  }


  probe healthcheck {
   .url = "/scalesimple/index.html";
   .interval = 5s;
   .timeout = 0.3 s;
   .window = 8;
   .threshold = 3;
   .initial = 3;
   .expected_response = 200;
  }

  sub vcl_init {
     geoip.init_database("/usr/local/share/GeoIP/GeoLiteCity.dat");
  }

EOF

@vcl_deliver = <<EOF
#------------------------
# VCL_DELIVER
#------------------------
sub vcl_deliver { 

  if (obj.hits > 0) {
     set resp.http.X-SS-Cache = "HIT";
     } else {
     set resp.http.X-SS-Cache = "MISS";
  }

  set resp.http.X-SS-Expiration2 = req.http.X-SS-Expiration2; 
  set resp.http.X-SS-Token2 = req.http.X-SS-Token2; 
  
EOF

@vcl_fetch = <<EOF
#------------------------
# VCL_FETCH
#------------------------
sub vcl_fetch { 

  set beresp.http.X-SS-PURGEURL = req.url;
  set beresp.http.X-SS-PURGEHOST = req.http.host ; 
EOF

@vcl_recv = <<EOF
#------------------------
# VCL_RECV
#------------------------
sub vcl_recv { 

   # This is completely lame and just so the VCL compiler
   # doesnt bitch at unused functions
   if (false) { 
    call validate_token_header;
    call validate_token_url;
    call validate_token_cookie;
    call set_geoip; 
   }

   set req.http.X-SS-ClientIP = client.ip ; 
   set req.http.X-SS-RequestStart = ssutil.time_str();
   set req.http.ext = regsub( req.url, "\\?.+$", "" );
   set req.http.ext = regsub( req.http.ext, ".+\\.([a-zA-Z0-9]+)$", "\\1" );

   if (req.http.host ~ "#{$CNAME_TYPE[:test]}$") { 
    set req.http.host = regsub(req.http.host,"^(.*)?\.#{$CNAME_TYPE[:test]}","\\1");
   }
EOF

@vcl_error = <<EOF
#------------------------
# VCL_ERROR
#------------------------
sub vcl_error { 

    call cleanup_request_headers; 

    if (obj.status == 799) {
      set obj.http.Location = obj.response; 
      set obj.status = 302; 
      return(deliver); 
    }
}



EOF

    @vcl_subs = ''
    @global_config = ''
    @global_config += @vcl_imports 
  end

  def load_config
        config_file= File.expand_path("../../config/config.yml", __FILE__)
        f = File.open(config_file)
        @config = YAML.load(f)
        f.close
  end

  def debug(msg)
    puts msg if @config["debug"] == true 
  end

  def initialize(hostname_id)
    load_config
    @hostname_id = hostname_id 
    @logger = SSConsumer::Logger.new
    @generator_log = File.open('/tmp/generator.log','w')
    @debug = false
  end

  #--------------------------------------------
  # HELPER FUNCTIONS
  #--------------------------------------------

  def global_comment(comment)
    c = "#----------------------------------------\n"
    c += '#' + tabs(1) + comment + "\n"
    c += "#----------------------------------------\n"
    c
  end

  def add_to_vcl(vcl,func)
     case func 
      when 'vcl_fetch'
       @vcl_fetch += vcl  
      when 'vcl_deliver'
       @vcl_deliver += vcl  
      when 'vcl_recv'
       @vcl_recv += vcl  
    end
  end


  def op_to_text(field,op,value,quotes=true)
    quotechar = quotes == true ? '"' : '' 

    case op.downcase
    when 'equals'
      return "#{field} == #{quotechar}#{value}#{quotechar}"
    when 'doesnotequal'
      return "#{field} != #{quotechar}#{value}#{quotechar}"
    when 'matches' 
      return "#{field} ~ #{quotechar}#{value}#{quotechar}"
    when 'contains'
      return "#{field} ~ #{quotechar}#{value}#{quotechar}"
    when 'doesnotmatch' 
      return "#{field} !~ #{quotechar}#{value}#{quotechar}"
    when  'doesnotcontain'
      return "#{field} !~ #{quotechar}#{value}#{quotechar}"
    when 'greaterthan'
      return "#{field} > #{value}"
    when 'lessthan'
      return "#{field} < #{value}"
    when 'startswith'
      return "#{field} ~ #{quotechar}^#{value}#{quotechar}"
    else "UNKNOWN OP #{op.downcase}"
    end
  end


  def spaces(size=1)
    s = ''
    1.upto(size) { s += ' '}
    s
  end

  def tabs(size=1)
    t = ''
    1.upto(size) { t.concat("\t") }
    t
  end

  def ttl_time(t)
    case t
    when 'DAYS'
      'd'
    when 'HOURS'
      'h'
    when 'MINUTES'
      'm'
    when 'SECONDS'
      's'
    else
      's'
    end
  end


  #----------------------------------------------------
  # Here we generate a list of ACLs for a rule
  # Since it is easier to create an ACL and then call
  # ~ (match) on the ACL 
  #----------------------------------------------------
  def generate_acl(rule)
    return unless rule.needs_acl? 
    
     acl = "acl rule_#{rule.id} {\n"
     rule.conditions.find_all { |c| c.key == 'client_ip' }.first.value.split(',').each { |ip|
       ip_entry = IPAddress.parse ip.gsub(/\s+/,'')
       acl += "\"#{ip_entry.address}\"" 
       acl += "/#{ip_entry.prefix}" if ip_entry.prefix != 32
       acl += ";\n" 
     }
     acl += "}\n\n"
     @global_config += acl 
    
  end

  #-------------------------------#
  # Generate the backend 
  #-------------------------------#

  def generate_ips(ips)
    block = ''
    ips.each { |ip|
       block += tabs(2) + '"' + ip + '"' + "/32;\n"
    }
    block
  end

  def print_backend(name,ip,hostname)
    be =  ' backend ' + name + ' {' + "\n"
    be += tabs(1) + '.host = "' + ip + '";' + "\n"
    be += tabs(1) + '.host_header = "' + hostname + '";' + "\n"
    be += tabs(1) + '.port = "80";' + "\n"
    be += tabs(1) + '.probe = healthcheck;' + "\n"
    be += " }\n\n"
    be
  end

  def print_dns_director(hostname,backends)
    dir = ' director director_' + hostname.id.to_s + ' dns { ' + "\n"
    backends.each { |be| 
      dir += tabs(1) + '{ .backend = ' + be + '; }' + "\n"
    }
    dir += tabs(1) + '.ttl = 5m;'
    dir +=  " }\n\n"
    dir
  end

  def print_rr_director(hostname,backends)
    dir = ' director director_' + hostname.id.to_s + ' round-robin { ' + "\n"
    backends.each { |be| 
      dir += tabs(1) + '{ .backend = ' + be + '; }' + "\n"
    }
    dir +=  " }\n\n"
    dir
  end


  def generate_backend(hostname)
   ips = hostname.valid_origin_ips.blank? ? ['192.168.0.100'] : hostname.valid_origin_ips
   backend_names = Array.new

   @global_config += global_comment(tabs(1) + "HOSTNAME #{hostname.name}")
   ips.each { |ip|
     backend_name = 'backend_' + hostname.id.to_s + '_' + ip.gsub('.','_')
     backend_names.push(backend_name)
     @global_config += print_backend(backend_name,ip,hostname.name)
   }

   @global_config += print_rr_director(hostname,backend_names)
  end

  def get_global_functions(ruleset,v)
     funcs = '' 
     funcs += tabs(1) + "call set_geoip;\n" if ruleset.has_geo_rule && v == 'vcl_recv' 
     debug("returning global functions #{funcs} ") unless funcs.blank?
     funcs
  end

  #---------------------------------------------------
  # Generate all the IF conditions for the hostnames 
  #---------------------------------------------------
  def generate_host_conditions(hostnames)
    ifelse = 0 

    # if the hostname_id we called deploy with matches, we should use the pending config
    # not the active one.  Also prevents deploying pending_configs prematurely 
    hostnames.each { |h|
      ruleset = get_ruleset(h)
      next if ruleset.nil?

      # next if (h != @hostname_id && h.active_ruleset.nil?) || (h == @hostname_id && h.ruleset.nil?)
      # ruleset_id = (h == @hostname_id) ? h.ruleset.id.to_s : h.active_ruleset.id.to_s
      # next unless ruleset_id 
      ['vcl_fetch','vcl_recv','vcl_deliver'].each { |v| 
        block = ifelse > 0 ? ' else if ( ' : ' if ( '
        block += 'req.http.Host == "' + h.name + '" ) {' + "\n"
        block += tabs(1) + 'set req.backend = director_' + h.id.to_s + ";\n" if v == 'vcl_recv'
        block += get_global_functions(ruleset,v)
        block += tabs(1) + 'call ruleset_' + ruleset.id.to_s + '_global_' + v + ";\n"
        block += tabs(1) + 'call ruleset_' + ruleset.id.to_s + '_ordered_' + v + ";\n"
        block += " }\n"
        add_to_vcl(block,v)
      }
      ifelse += 1
    }
  end


  #--------------------------------------
  # If new actions are created they must
  # live here
  #--------------------------------------
  def parse_actions(actions,func) 

     vcl_actions = '' 

     actions.each { |action| 
        debug "testing action" + action.inspect.to_s + " with function " + func 
        next unless !action.vcl_functions.nil? && action.vcl_functions.include?(func)
        next if action.value.nil? || action.value.empty? 
        next if action.value == "false"
        debug "made it key is " + action.key + " func:" + func + ":" 

        case action.key
          when "do_not_cache" 
            vcl_actions += tabs(2) + 'set beresp.ttl = 0s;' if action.value == true 
          when "set_ttl" 
            vcl_actions += tabs(2) + 'set beresp.ttl = ' + action.value.to_s + ttl_time(action.unit) + ';'
          when 'http_redirect' 
            vcl_actions += tabs(2) + 'error 799 "' + action.value + '"; '
          when 'deny_request'
            vcl_actions += tabs(2) + 'error 403;'
          when 'remove_request_header' 
            vcl_actions += tabs(2) + 'unset req.http.' + action.value + ';'
          when 'remove_response_header' 
            vcl_actions += tabs(2) + 'unset resp.http.' + action.value + ';'
          when 'add_request_header' 
            vcl_actions += tabs(2) + 'set req.http.' + action.name + ' = "' + action.value + '";'
          when 'add_response_header' 
            vcl_actions += tabs(2) + 'set resp.http.' + action.name + ' = "' + action.value + '";'
          when 'remove_cookie' 
            if func == 'vcl_fetch'
              vcl_actions += tabs(2) + 'unset beresp.http.cookie;'
            elsif func == 'vcl_recv'
              vcl_actions += tabs(2) + 'unset req.http.cookie;'
            end
          when 'validate_token'
            begin
              token = Token.find(action.value)
            rescue
              debug "Can not find token"
              return
            end
            vcl_actions += tabs(2) + 'set req.http.X-SS-Key = "' + token.secret + '";' + "\n"
            vcl_actions += tabs(2) + 'call validate_token_' + token.location + ';' 
          else
            vcl_actions += ''
        end
        vcl_actions += "\n"
     }
     vcl_actions
  end


  #--------------------------------------------
  # PARSE CONDITIONS
  #--------------------------------------------
  def parse_condition_request_url(rule,key,op,value,name=nil)
     request_urls = Array.new
     request_urls.push(value.split(',').collect { |url|
          url.gsub!(/^\s*/,'')
          #url.gsub(/\//,'\/')
        }.compact )
     " ( " + op_to_text("req.url", op, request_urls.compact.join('|')) + " ) "
  end

  def parse_condition_content_type(rule,key,op,value,name=nil)
     content_types = Array.new
     content_types.push(value.split(',').collect { |ext|
          ext.gsub!(/^\s*/,'')
          ext.gsub(/^(\*?\.?)/,'')
        }.compact )
     " ( " + op_to_text("req.http.ext", op, "^(#{content_types.compact.join('|')})") + " ) "
  end

  def parse_condition_client_ip(rule,key,op,value,name=nil)
    " ( " + op_to_text("client.ip",op,'rule_'+rule.id.to_s,false) + " ) "
  end

  def parse_condition_request_parameter(rule,key,op,value,name=nil)
    " ( " + op_to_text("req.url",op,"#{name}=#{value}") + " ) "

  end

  def parse_condition_client_cookie(rule,key,op,value,name=nil)
   #   vcl += "( header.get(req.http.Cookie,\"#{rule.match_cookie_name}=#{rule.match_cookie_value}\") #{match_expr} \"^$\" )"
   " ( " + op_to_text("header.get(req.http.cookie,\"#{name}=#{value}\")",op,"^$") + " ) "
  end

  def parse_condition_request_header(rule,key,op,value,name=nil)
    " ( " + op_to_text("req.http." + name, op, value ) + " ) "
  end

  def parse_condition_country(rule,key,op,value,name=nil)
    "( " + op_to_text("req.http.X-GeoIP", op, value) + " ) "
  end


  #-------------------------------------------
  #   GLOBAL RULES
  #-------------------------------------------

  #--------------------------
  # Parse 1 global rule 
  #--------------------------
  def parse_global_rule(rule,func)

      debug "Calling parse actions on global rule " + rule.inspect.to_s 
      actions = parse_actions(rule.rule_actions,func)
      return if actions.blank?

      c = Array.new
      rule.conditions.each { |cond| 
        next if cond.value.blank?
        c << self.send('parse_condition_' + cond.key.to_s, rule,cond.key,cond.operator,cond.value,cond.name)    
      }
      
      vcl = tabs(1) + 'if ( '

      if c.size == 0 
         vcl += " true " #no conditions
      else
         vcl += c.join( rule.match == 'ANY' ? '||' : '&&') 
      end
      
      vcl += " )  { \n"
      vcl += actions
      vcl += tabs(1) + "}\n"
      vcl
      @global_config += vcl 
    end

  #-----------------------------------------------------------------------------------------
  # Parse all global rules
  # 
  # Here we need to combine all the rules based on vcl_function.  The
  # reason is we need to ensure the action lives in the appropriate place.  For 
  # example, if we want to set a TTL, we MUST do that in vcl_fetch, meanwhile other
  # actions must live in vcl_recv like an http_redirect.  So we end up with one sub
  # for each ruleset/function combination.  Then in the actual vcl function (say vcl_fetch) 
  # we can simply say if (hostname) { call sub_RULESET_vcl_fetch} and it will have
  # the appropriate rules for fetch
  #-----------------------------------------------------------------------------------------
  def parse_global_rules(ruleset,rules)
    debug "Parsing global ruleset " + ruleset.id.to_s 
    ['vcl_fetch','vcl_recv','vcl_deliver'].each  { |f| 
      @global_config += 'sub ruleset_' + ruleset.id.to_s + '_global_' + f + " { \n"
      rules.find_all { |r| 
        r.vcl_functions.include?(f)}.each { |r2| 
          parse_global_rule(r2,f)}
      @global_config += "}\n\n"
    }
  end



  #-------------------------------------------
  #   ORDERED RULES
  #-------------------------------------------
  #--------------------------
  # Parse 1 global rule 
  #--------------------------
  def parse_ordered_rule(rule,rulenum,func,actions)
      # actions = parse_actions(rule.rule_actions,func)
      # return if actions.blank?
      c = Array.new

      rule.conditions.each { |cond| 
        next if cond.value.blank?
        c << self.send('parse_condition_' + cond.key.to_s, rule,cond.key,cond.operator,cond.value,cond.name)    
      }
      
      vcl = tabs(1) + (rulenum > 0 ? 'else if ( ' : 'if ( ')

      if c.size == 0 
         vcl += " true " #no conditions
      else
         vcl += c.join( rule.match == 'ANY' ? '||' : '&&') 
      end
      
      vcl += " )  { \n"
      vcl += actions
      vcl += tabs(1) + "}\n"
      vcl
      @global_config += vcl 
  end


  def parse_ordered_rules(ruleset,rules)
     ['vcl_fetch','vcl_recv','vcl_deliver'].each  { |f| 
      @global_config += 'sub ruleset_' + ruleset.id.to_s + '_ordered_' + f + " { \n"
      rulenum = 0 
      sorted_rules = rules.sort_by { |r| r.sort_index }
      sorted_rules.find_all { |r| 
         r.vcl_functions.include?(f)
      }.each { |r2| 
          debug "Calling rule actions on ordered rule " + r2.inspect.to_s + " for function " + f
          actions = parse_actions(r2.rule_actions,f)
          next if actions.blank?
          parse_ordered_rule(r2,rulenum,f,actions)
          rulenum += 1
         }
      @global_config += "}\n\n"
     }
  end

  def parse_rules(ruleset)
      ruleset.rules.each { |r| generate_acl(r) }
      parse_global_rules(ruleset,ruleset.rules.find_all {|f| f.global == true  })
      parse_ordered_rules(ruleset,ruleset.rules.find_all { |f| f.global == false })
  end

  def generate_ruleset(ruleset)
    #return if ruleset.rules.size == 0 
    parse_rules(ruleset)
  end

  def close_configs
    #-----------------------
    #  Close out the VCL 
    #-----------------------

    @vcl_fetch += "}\n" # end vcl_fetch 
    @global_config += @vcl_fetch

    @vcl_recv += "\telse { error 403 ; } \n" 
    @vcl_recv += "\tcall cleanup_request_headers;\n"
    @vcl_recv += "}\n" # end vcl_recv 
    @global_config += @vcl_recv

    @vcl_deliver += "\tcall cleanup_response_headers;\n"
    @vcl_deliver += "}\n" # end vcl_deliver 
    @global_config += @vcl_deliver

    @global_config += @vcl_error 

    @global_config
  end

   
  def get_ruleset(hostname)
    if hostname.id.to_s == @hostname_id.to_s
      hostname.ruleset.nil? ? nil : hostname.ruleset
    else
      hostname.active_ruleset.nil? ? nil : hostname.active_ruleset
    end
  end

  #------------------------------------
  # Start the process !!
  #------------------------------------
  def generate_config 
     setup_config

     rulesets = Array.new
     hostnames = Hostname.all

     hostnames.each { |h|

      debug("processing hostname #{h}")
      ruleset = get_ruleset(h)
      next if ruleset.nil?
      generate_backend(h)


      @logger.log('Adding ' + h.ruleset.id.to_s + ' to rulesets for hostname ' + h.name,'debug')
      rulesets << ruleset
     }

     rulesets.uniq.each { |ruleset| 
        generate_ruleset(ruleset)
     }

     generate_host_conditions(hostnames)
     close_configs
  end
 end # class VclLib
end #module SSConsumer



