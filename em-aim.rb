#!/usr/bin/ruby
$: << File.join(File.dirname(__FILE__), "")

require 'hashie'
require 'eventmachine'
require 'em-http-request'
require 'json'
require 'em-aim/session'


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

#================================================================================================

# AOL CODES

@aol_codes = Hashie::Mash.new

@aol_codes.error = Hashie::Mash.new
@aol_codes.error[200] = "Success (Ok)"
@aol_codes.error[330] = "More Authentication Required"
@aol_codes.error[400] = "Invalid Request"
@aol_codes.error[401] = "Unauthorized (authentication required)"
@aol_codes.error[405] = "Method not Allowed"
@aol_codes.error[408] = "Request Timeout"
@aol_codes.error[430] = "Source Rate Limit Reached"
@aol_codes.error[440] = "Invalid Key"
@aol_codes.error[441] = "Key Usage Limit Reached"
@aol_codes.error[442] = "Key Invalid IP"
@aol_codes.error[443] = "Key used from unauthorized site"
@aol_codes.error[460] = "Missing required parameter"
@aol_codes.error[461] = "Source Required"
@aol_codes.error[462] = "Parameter Error"
@aol_codes.error[500] = "Generic Server Error"

# AOL Status Detail Codes (statusDetailCode)

@aol_codes.status_detail = Hashie::Mash.new
@aol_codes.status_detail[3011] = "Password-LoginId Required/Invalid"
@aol_codes.status_detail[3012] = "SecurId Required/Invalid"
@aol_codes.status_detail[3013] = "SecurId Next Token Required"
@aol_codes.status_detail[3014] = "ASQ Required/Invalid"
@aol_codes.status_detail[3015] = "Captcha Required/Invalid"
@aol_codes.status_detail[3016] = "AOLKey Required"
@aol_codes.status_detail[3017] = "Rights/Consent Required"
@aol_codes.status_detail[3018] = "TOS/Privacy Policy Accept Required"
@aol_codes.status_detail[3019] = "Account Not allowed"
@aol_codes.status_detail[3020] = "Email not confirmed"
@aol_codes.status_detail[3021] = "Account needs to be updated (send user to AOL)"

# Signing Requests 
# (HMAC-SHA256)
# The Session Key generated using the user's password and the session secret returned by 'clientLogin' 
# method should be used as the Key while generating the HMAC-SHA256 of the Signature Base String

# TODO





# AOL API URL/URIs

@aol_oauth_base_url = "api.screenname.aol.com/auth"

# main uri hash
@aol_oauth = Hashie::Mash.new

@aol_oauth.login = Hashie::Mash.new

@aol_oauth.login.base = Hashie::Mash.new

@aol_oauth.login.base.url = 'http://'+@aol_oauth_base_url+"/login"
@aol_oauth.login.base.name = "login"
@aol_oauth.login.base.factory = "login_factory"

@aol_oauth.login.client = Hashie::Mash.new
@aol_oauth.login.client.url = 'https://'+@aol_oauth_base_url+"/clientLogin"
@aol_oauth.login.client.name = "login_client"
@aol_oauth.login.client.factory = "login_client_factory"

@aol_oauth.token = Hashie::Mash.new
@aol_oauth.token.get = Hashie::Mash.new
@aol_oauth.token.get.url = 'http'+@aol_oauth_base_url+"/getToken"
@aol_oauth.token.get.name = "get_token"
@aol_oauth.token.get.factory = "get_token_factory"


# API credentials
@aol_credentials = Hashie::Mash.new
@aol_credentials.username = "convo-dev@aolmobile.com"
@aol_credentials.password = "C0nv03ng"
@aol_credentials.devkey = "co1CUF33RYdKJBOl"

@aol_api_format = "json"

# clientLogin
#client_login = Hashie::Mash.new
#client_login.url = "https://api.screenname.aol.com/auth/clientLogin"
#client_login.http_method = "POST"

#===============================================

EventMachine.run do
  
  #OpenAIM::Session.getToken({:request_url => @aol_oauth.token.get.url, :query => {'devId'=>@aol_credentials.devkey, 'f' => @aol_api_format, 's' => @aol_credentials.username}}) do |response|
    #puts response.inspect
  #end
  OpenAIM::Session::Client.login({
    :request_url => @aol_oauth.login.client.url, 
    :query => {
      'devId'=>@aol_credentials.devkey, 
      'f' => @aol_api_format, 
      'pwd' => @aol_credentials.password, 
      's' => @aol_credentials.username}
    }) do |response|
    puts response.inspect
  end

end