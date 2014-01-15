require 'patron'
require 'json'


cwd = Pathname(__FILE__).dirname
$:.unshift(cwd.to_s) unless $:.include?(cwd.to_s) || $:.include?(cwd.expand_path.to_s)

require '../../web_portal/config/environment'
require 'vcl_deploy/vcl_deploy'
require 'vcl_generator/vcl_generator'
require 'logger/logger'
require 'vcl_ban/vcl_ban'
require 'subscriber/subscriber'



module SSConsumer

   

end
