#!/usr/bin/ruby
require 'net/http'
require 'hpricot'
require 'open-uri'
require 'hashie'

# Class for logging into Open AIM

@aol_oauth_url = "http://api.screenname.aol.com/auth/login"
@username = "convo-dev@aolmobile.com"
@password = "C0nv03ng"
@devkey = "co1CUF33RYdKJBOl"

def login
  
  # params = {"type":"login","method":"post","args":{...see below...}}
  @response_format = "json"
  # url ( http://api.screenname.aol.com/auth/login )
  # method = POST
  # ARGUMENTS
  # devId (required)
  # f (format) (required) json, xml, qs
  # succUrl (optional) where to redirect to after the authentication success
  # s (optional) The loginID of the source user (if known)
  # language (optional) required language / locale of the error/status message (default: en)
  # c (optional) the callback method to use when using jsonp convention (argument f = json)
  # r (optional) a URL safe string to be used as a requestID - when passed it is returned back in the response
  # uiType (optional) 'mini' if a smaller version (230x230px) of OpenAuth login (works with iPhone)
  # supportedIdType (optional) SN, ICQ, OID
  #  supportedIdType=SN,ICQ,OID would enable all
  #  supportedIdType=SN,ICQ would enable AOL/AIM and ICQ 
  
  #http = Net::HTTP.start("http://api.screenname.aol.com/auth/login")
  req = Net::HTTP::Post.new(@aol_oauth_url, initheader = {'Content-Type' => 'application/json'})
  req_arguments = "devID=#{@devkey.to_s}&f=#{@response_format.to_s}"
  req.set_form_data(req_arguments)
  response = http.request(req)
  
  puts "RESPONSE FROM AIM: #{response.inspect}"
  
end

login