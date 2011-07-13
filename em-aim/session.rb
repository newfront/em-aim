#!/usr/bin/ruby
require 'hmac-sha1'
require 'digest/md5'
require 'base64'
require 'cgi'

module OpenAIM

  module Session

    # Used to get a new Session Token back from the AIM oAuth Server
    # @param [Hash] params is the main HTTP request data object
    # @param [String] :request_url is the oAuth request URL for getToken
    # @param [Hash] :query is the HTTP Request Parameters
    # @option :query [String] 'devId' is the Developer Key to use for the HTTP Request
    # @option :query [String] 'f' is the format type ('json','xml','qs')
    # @option :query [String] 's' is the aim loginId, eg screename
    # @option :query [String] 'succUrl' is the success url to redirect a user to upon success
    # @option :query [String] 'language' is the locale of the response, ('en')
    # @option :query [String] 'tokenType' ('shortterm','longterm') where shortterm is 24 hr, and longterm is 1 year from request
    # @option :query [String] 'c' is the callback method if using jsonp, f=json
    # @option :query [String] 'r' is the URL safe string to be used as a requestId - when passed it is returned in response

    def self.getToken(params = {
      :request_url => "", 
      :query => {'c'=>'parseToken','devId'=>"", 'f' => "", 's' => "",'succUrl'=>'http://anywhere.convorelay.com'}, 
      :timeout => 10}, 
      &block)

      puts "GET_AIM_TOKEN: PARAMS: #{params.inspect}"
      
      begin
        http = EventMachine::HttpRequest.new(params[:request_url]).get :query => params[:query], :timeout => params[:timeout], :head => {'x-header' => 'X-Forwarded-For: 10.0.0.3'}

        http.callback {

          response = Hashie::Mash.new
          response.header_status = http.response_header.status
          response.header = http.response_header
          response.body = http.response

          #p http.response_header.status
          #p http.response_header
          #p http.response
          #puts block.class
          block.call(response)

        }
        
      rescue => e
        puts "getToken Failure: #{e}"
        block.call(e)
      end

    end
    
    # startSession
    
    # Input Parameters
    # f * (format)
    # c * (callback)
    # r * (requestId)
    # k * (AIM Web Key) - use key for all cals
    # a * (Authenticaion Token)
    # events (comma separated list of events to subscribe to.) fetchEvents will only return these events
    # encodeData Boolean (Base64 encode the data in the imdata events)
    # assertCaps (Capability) Comma Separated List of capabilities to assert to other users and to receive from other users
    # interestCaps (Capability) Comma Separted List of capabilities to ONLY receive from other users
    # anonymous (Boolean) start an anonymous session
    # invisible (Boolean) start an invisible session
    # rawMsg (Boolean) Setting this will result in receiving raw data from fetchEvents API. (can be used with legacy clients)
    # friendly (String) for anonymous sessions, this is an optional friendly name to display
    # language (String) defualts to en. "<lang>-<local>" format, follows I18N codes
    # *** clientName (String) Client name - clientLogin parameter
    # *** clientVersion (Integer) Client Version - clientLogin parameter
    # *** ts (Integer) Epoch Timestamp - clientLogin required parameter
    # *** sig_sha256 (String) Signature - clientLogin required parameter
    # mobile (Boolean) is this session mobile or not
    # sessionTimeout (Integer) time in seconds before terminating idle web session
    # view (Presence State) How we should appear to other users, offline and mobile are not valid in this case
    # buildNumber (Integer) Build Number
    # majorVersion (Integer) Major Version, i.e for 1.2.3, major version = 1
    # minorVersion (Integer) Minor Version, i.e for 1.2.3, minor version = 2
    # pointVersion (Integer) Point Version, i.e. for 1.2.3, point version = 3
    # pollTimeout (Integer) Default value requested for fetchEvents, so client does not need to supply in each request
    # includePresenceFields (String) Comma separated list of fields to include in a presence object. This can be used to minimize data that the client does not use. You can also include "=" for any of the fields, so that the field will only be present if the value does not match the specified default value. Example: includePresenceFields=aimId,userType=icq,friendly
    # excludePresenceFields (String) Comma separated list of fields to exclude in a presence object. This can be used to minimize data that the client does not use. You can also include "=" for any of the fields, so that the field will only be present if the value does not match the specified default value. Example: excludePresenceFields=userType=icq,buddyIcon
    
    # Output Fields
    # fetchBaseURL (String) Base URL to do fetches with, see FetchEvents method
    # ts (Array of Integer) Epoch timestamp - clientLogin required paramter
    # aimsid (String) the aimsid to use in other calls
    # myInfo (Presence) Presence object about logged in user
    # creatorDisplayName (String) For anonymous sessions, this is the display name to use for the widget creator
    # 
    
    # Signing Requests 
    # (HMAC-SHA256)
    # The Session Key generated using the user's password and the session secret returned by 'clientLogin' 
    # method should be used as the Key while generating the HMAC-SHA256 of the Signature Base String
    
    def self.start(params = {
      :request_url => "", 
      :query => {
        "a"=>"",
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
        "f" => "",
        "friendly"=>"Convo Bot",
        "invisible"=>false,
        # same as devId
        "k"=>"",
        "majorVersion"=>0,
        "minorVersion"=>0,
        "pointVersion"=>1,
        "pollTimeout"=>10,
        "r"=>"",
        "rawMsg"=>false,
        "ts"=> ""
        }, 
      :timeout => 10},
      &block
      )
      #puts params.inspect
      
      puts "QUERY: #{params[:query].inspect}"
      
      sig_sha256 = calculate_signature_string(
      {
        :request_type => "GET",
        :request_url => params[:request_url],
        :data =>
        {
          :oauth_consumer_key => params[:query]['k'],
          :oauth_token => params[:query]['a'],
          :oauth_timestamp => params[:query]['ts']
        }
      })
      
      puts "\nBASE SIGNATURE STRING:: #{sig_sha256.inspect}\n"
      
      http = EventMachine::HttpRequest.new(params[:request_url]).get :query => params[:query], :timeout => params[:timeout], :head => {'x-header' => 'Content-Type: application/x-www-form-urlencoded'}
      
      http.callback {
        p http.response_header.status
        p http.response_header
        p http.response
      }
      
      block.call("hello jeff")
      
      
    end
    
    #GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal
    
    def self.calculate_signature(key,text)
      
      # HMAC-SHA1
      # text = Signature Base String
      # key = 
      
      sig_key = key
      sig_text = text
      HMAC::SHA1.digest(sig_key,sig_text)
      
    end
    
    def self.calculate_signature_string(params={:request_type=>"GET",:request_url=>"",:data=>{:oauth_consumer_key=>"",:oauth_token=>"",:oauth_timestamp=>""}})
      # http://oauth.net/core/1.0/#nonce
      #Unless otherwise specified by the Service Provider, the timestamp is expressed in the number of seconds since January 1, 1970 00:00:00 GMT. The timestamp value MUST be a positive integer and MUST be equal or greater than the timestamp used in previous requests.
      #The Consumer SHALL then generate a Nonce value that is unique for all requests with that timestamp. A nonce is a random string, uniquely generated for each request. The nonce allows the Service Provider to verify that a request has never been made before and helps prevent replay attacks when requests are made over a non-secure channel (such as HTTP).
      
      type = params[:request_type].upcase
      url = params[:request_url]
      
      oauth_consumer_key = params[:data][:oauth_consumer_key]
      oauth_nonce = self.calculate_nonce({:key=>params[:data][:oauth_consumer_key]})
      oauth_signature_method = "HMAC-SHA1"
      oauth_token = params[:data][:oauth_token]
      oauth_timestamp = params[:data][:oauth_timestamp].to_s
      oauth_version = "1.0"
      
      puts "oauth_consumer_key: #{oauth_consumer_key}"
      puts "oauth_nonce: #{oauth_nonce}"
      puts "oauth_signature_method: #{oauth_signature_method}"
      puts "oauth_token: #{oauth_token}"
      puts "oauth_timestamp: #{oauth_timestamp}"
      puts "oauth_version: #{oauth_version}"
      
      
      base_signature_string = CGI.escape(type+"&"+url+"&oauth_consumer_key="+oauth_consumer_key+"&oauth_nonce="+oauth_nonce+"&oauth_signature_method="+oauth_signature_method+"&oauth_timestamp="+oauth_timestamp+"&oauth_token="+oauth_token+"&oauth_version="+oauth_version)
      
      return base_signature_string
      
    end
    
    def self.calculate_nonce params={:key=>""}
      puts "calculate_nonce: #{params.inspect}"
      begin
        return Digest::MD5.hexdigest(params[:key])
      rescue NameError => e
        return e
      rescue TypeError => e
        return e
      end
        
    end
    
    # used to fire off EventMachine http requests
    class Request
      
      attr_accessor :request_url
      attr_accessor :query
      attr_accessor :headers
      attr_accessor :timeout
      
      def initalize(params = {}, &block)
        
        self.send(block)
        
      end
      
      def send &block
        http = EventMachine::HttpRequest.new(self.request_url).get :query => self.query, :timeout => self.timeout, :head => self.headers

        http.callback {

          response = Hashie::Mash.new
          response.header_status = http.response_header.status
          response.header = http.response_header
          response.body = http.response

          #p http.response_header.status
          #p http.response_header
          #p http.response
          #puts block.class
          block.call(response)

        }
      end
      
    end
    
    module Client
      
      # clientLogin method logs a user in on behalf of that User
      # clientLogin

      # REQUEST ELEMENTS
      # url = 'https://api.screenname.aol.com/auth/clientLogin'

      # http method = 'post'

      # http header = (required if proxying clientLogin requests) (client/servers using 'clientLogin'
      # must pass the peer-ip from the requests they receive from their clients as X-Forwarded-For header
      # in the 'clientLogin' request, so OpenAuth can enforce the rate limits on the correct client IP

      # Arguments
      # (***) devId (required)

      # (***) f (required) - format of the response (json, xml, or qs) qs = query string

      # (***) s (required) - loginId of the source User

      # language (optional) - defaults to 'en'

      # (***) tokenType (optional) - 
      # "shortterm" (24 hours) or
      # "longterm" (valid for 1 year) or 
      # non-negative long value representing the required Toekn validity in seconds

      # c (optional) - callback method to use when using jsonp (f=json)

      # (***) r (optional) - URL safe string to be used as a requestId - 
      # - when passed it is returned back in response

      # (***) pwd (optional) - User's password when initiating the request for the first time or 
      # when Password challenge is returned in previous request

      # (***) securid (optional) - User's securId when SecurId challenge is returned in previous request

      # (***) asqAnswer (optional) - AOL Account Security Question's Answer when ASQ Challenge is returned in previous request

      # (*****) word (optional) - Captcha Word when Captcha challenge is returned in previous request

      # context (optional) - Authentication Context returned in previous directLogin request -
      # when additional challenges are required

      # authMethod (optional) - Authentication Method required in addition to PWD (default), 
      # Additional authMethod supported in this phase is "ASQ" (Account Security Question)

      # idType (optional) - You can pass value as "ICQ" to make sure you are authenticating an ICQ user (both numeric id and email alias)
      # - No need to pass if you are just authenticating AOL/AIM users and even ICQ numeric ids only

      # rlToken (optional) - Rate Limit Token obtained via a previous directLogin call with successful
      # captcha challenge for the same user
      # - (s must match)
      # - if user loginId doesn't match, rlToken will be ignored

      # (***) clientName (optional) An optional name of the Client

      # (*) clientVersion (optional) An optional version of the Client

      # RESPONSE ELEMENTS

      # {'response':{
      #  "statusCode":"",
      #  "statusText":"",
      #  "statusDetailCode":"",
      #  "requestId":"",
      #  "data":{
      #    ...
      #  }
      #}}
      
      # http://www.tc.umn.edu/~brams006/selfsign.html
      # HTTPS
      #:ssl => {
      #              :private_key_file => '/tmp/server.key',
      #              :cert_chain_file => '/tmp/server.crt',
      #              :verify_peer => false
      #          },
      
      # SAMPLE RESPONSE as Mash
      #<#Hashie::Mash body="{\"response\": {\"statusCode\": 200, \"data\": {\"luid\": \"81D74799-89ED-8B1A-98EA-40D993C40B88\", \"loginId\": \"convo-dev@aolmobile.com\", \"hostTime\": 1310177208, \"sessionSecret\": \"VdGPKNaerJFnhbWV\", \"token\": {\"expiresIn\": 1209600, \"a\": \"%2FwQAAAAAAADYoauPSHX5GcFzxrZ%2FFcG7s5%2BFcR6fSDMuPZqMH2kg21oH6B4xdSv8Utm047uFg4Ut4%2BS68unebiNOzXjPoN71XL7iX9UOQfjY5RLhL5pAhu9gt0d6TgsE09sAeQ1djWAeWlYjTqr0KNtlN2IT5qz3nvAjSk0yq2zTaM%2BcVldjTxUEkTQ2drVv8QicnQ%3D%3D\"}}, \"statusText\": \"OK\"}}\n" header=<#Hashie::Mash CACHE_CONTROL="no-cache, must-revalidate" CONNECTION="Keep-Alive" CONTENT_LANGUAGE="en-US" CONTENT_TYPE="application/json;charset=UTF-8" DATE="Sat, 09 Jul 2011 02:06:48 GMT" EXPIRES="Thu, 01 Jan 1970 00:00:00 GMT" KEEP_ALIVE="timeout=15, max=500" P3P="CP=\"PHY ONL PRE STA CURi OUR IND\"" PRAGMA="No-cache" SET_COOKIE="JSESSIONID=CA763419D20DCBC2EB3635C4942ED001; Path=/auth; Secure" TRANSFER_ENCODING="chunked"> header_status=200>
      
      
      def self.login(params={},&block)
        #puts "LOGIN CLIENT: PARAMS: #{params.inspect}"
        #puts "TYPE? :#{block.class}"
        
        #TODO OpenAIM::Request.new(params,&block)
        
        # :head => {"X-Forwarded-For" => "10.0.0.3"}, 
        # :ssl => { :private_key_file => '/Users/scotthai/.ssh/ssl/server.key.insecure',:cert_chain_file => '/Users/scotthai/.ssh/ssl/server.key.insecure', :verify_peer => false}
        http = EventMachine::HttpRequest.new(params[:request_url]).post :query => params[:query], :timeout => params[:timeout], :head => {'x-header' => 'X-Forwarded-For: 10.0.0.3'}

        http.callback {
          
          #{"response":{
          #        "statusCode":""
          #        "statusText":"",
          #        "statusDetailCode":""
          #
          #        "requestId":""
          #        "data":{
          #              ....
          #        } 
          #   }}
          
          response = OpenAIM::Parser::Response.to_hashie("clientLogin",http)
          
          puts "HEADER STATUS: #{response.header_status.to_s}"
          
          if response.body.response.statusCode == 200
            
            begin
              
              data = response.body.response.data
              
              $session_aim = Hashie::Mash.new
              $session_aim.host_time = data.hostTime
              $session_aim.loginId = data.loginId
              $session_aim.luid = data.luid
              $session_aim.session_secret = data.sessionSecret
            
              $session_aim.token = Hashie::Mash.new
              $session_aim.token.a = data.token.a
              $session_aim.token.expires = data.token.expiresIn
            
              $session_aim.status = Hashie::Mash.new
              $session_aim.status.code = response.body.response.statusCode
              $session_aim.status.text = response.body.response.statusText
              
              @response = $session_aim
              
              puts "RESPONSE? #{@response.inspect}"
            
              #p $session_aim
            rescue JSON::ParserError => e
              @response = OpenAIM::Helpers::Error.to_error({"code"=>400,"status"=>e})
            rescue NoMethodError => e
              @response = OpenAIM::Helpers::Error.to_error({"code"=>400,"status"=>e})
            rescue NameError => e
              @response = OpenAIM::Helpers::Error.to_error({"code"=>400,"status"=>e})
            rescue TypeError => e
              @response = OpenAIM::Helpers::Error.to_error({"code"=>400,"status"=>e})
            end
            
          else
            @response = response
          end
          
          # send formatted response back to block as parameter
          block.call(@response)

        }
        
      end
      
      
      
    end
    
  end

end