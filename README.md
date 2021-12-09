# Rise of the First BOTs: 
> Remember AOL AIM. Did you know it was "bot-able". Like SLACK today, AIM could have been so much more.

This archived project makes me happy. Back in the day AOL instant messenger dominated the world. It was also ahead of its time in many ways including the fact that it could be 
`botted`. The AIM protocol was reverse engineered, and with that came the rise of the first bot processes.
EventMachine bindings for the OpenAIM (WebAIM APIs)

## Can I use this?
There is nothing that still works. The AIM service has been shut down. This is for nostalgia.

## OpenAIM::Session

**getToken**
~~~
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
      block.call(response)
    }

  rescue => e
    puts "getToken Failure: #{e}"
    block.call(e)
  end

end
~~~

**OpenAIM::Session.start**
~~~
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

    block.call("hello friends")
end
~~~

**OAuth Signing / Signature Generation**
~~~
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

  #puts "oauth_consumer_key: #{oauth_consumer_key}"
  #puts "oauth_nonce: #{oauth_nonce}"
  #puts "oauth_signature_method: #{oauth_signature_method}"
  #puts "oauth_token: #{oauth_token}"
  #puts "oauth_timestamp: #{oauth_timestamp}"
  #puts "oauth_version: #{oauth_version}"


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
~~~
