#!/usr/bin/ruby
$: << File.join(File.dirname(__FILE__), "")
$: << $APP_ROOT = File.expand_path(File.dirname(__FILE__))

require 'hashie'
require 'eventmachine'
require 'em-http-request'
require 'json'
require 'yaml'

# Grab OpenAIM Modules/Classes
require 'em-aim/helpers'
require 'em-aim/parsers'
require 'em-aim/session'

# Load Configurations
$config_app = Hashie::Mash.new(YAML.load_file(File.join($APP_ROOT,'config','config.yml')))
$config_aim = Hashie::Mash.new(YAML.load_file(File.join($APP_ROOT,"config","/openaim.yml")))

#puts "Application: #{$config_app.inspect}"
#puts "OpenAIM: #{$config_aim.inspect}"

#$config_aim.each{|branch| puts "\n\nOPENAIM CONFIG: #{branch.inspect}"}

# Error and Success Codes for AIM Responses
#p $config_aim.codes
#p $config_aim.codes[200]
# Status Messages for statusDetailCode in AIM API Responses
#p $config_aim.status
#p $config_aim.status[3011]
# API Urls/Protocols/URIs
#p $config_aim.aol_urls
#p $config_aim.aol_urls.base
# AOL Credentials
#p $config_aim.credentials
# AOL Request Information
#p $config_aim.request

EventMachine.run do
  puts "OpenAIM Server Running"
  #OpenAIM::Session.getToken({:request_url => @aol_oauth.token.get.url, :query => {'devId'=>@aol_credentials.devkey, 'f' => @aol_api_format, 's' => @aol_credentials.username}}) do |response|
    #puts response.inspect
  #end
  
  OpenAIM::Session::Client.login({
    :request_url => $config_aim.aol_urls.login.client.full_url, 
    :query => {
      'devId'=>$config_aim.credentials.devkey, 
      'f' => $config_aim.request.format, 
      'pwd' => $config_aim.credentials.password, 
      's' => $config_aim.credentials.username}
    }) do |response|
    
    # if login was successful
    if response.status.code == 200
      
      # now startSession
      OpenAIM::Session.start({:request_url => $config_aim.aol_urls.session.full_url, 
        :query => {
          "a"=>response.token.a,
          "anonymous"=>false,
          "buildNumber"=>1,
          "c"=>"parseSessionStartResponse",
          "encodeData"=>false,
          # myInfo
          # presence
          # buddylist
          # typing
          # im
          # dataIM
          # clientError
          # sessionEnded (don't need to subscribe to this)
          # offlineIM
          # sentIM
          # sentDataIM
          "events"=>"myInfo,presence,buddylist,im,dataIM,clientError,offlineIM,sentIM,sentDataIM",
          'f' => $config_aim.request.format,
          "friendly"=>"Convo Bot",
          "invisible"=>false,
          # same as devId
          'k' => $config_aim.credentials.devkey,
          "majorVersion"=>0,
          "minorVersion"=>0,
          "pointVersion"=>1,
          "pollTimeout"=>10,
          "r"=>"",
          "rawMsg"=>false,
          'ts' => response.host_time
          }
        }) do |response|
        puts response.inspect
      end
      
    else
      puts "something went wrong\n"
      p response
    end
    
  end

end