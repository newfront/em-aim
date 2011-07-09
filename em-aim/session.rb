#!/usr/bin/ruby

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
        puts "LOGIN CLIENT: PARAMS: #{params.inspect}"
        puts "TYPE? :#{block.class}"
        
        #TODO OpenAIM::Request.new(params,&block)
        
        # :head => {"X-Forwarded-For" => "10.0.0.3"}, 
        # :ssl => { :private_key_file => '/Users/scotthai/.ssh/ssl/server.key.insecure',:cert_chain_file => '/Users/scotthai/.ssh/ssl/server.key.insecure', :verify_peer => false}
        http = EventMachine::HttpRequest.new(params[:request_url]).post :query => params[:query], :timeout => params[:timeout], :head => {'x-header' => 'X-Forwarded-For: 10.0.0.3'}

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
    
  end

end