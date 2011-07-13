module OpenAIM
  
  module Parser
    
    module Response
      
      def self.to_hashie(type,data)
        
        # type = ("clientLogin","startSession",...)
        self.parse(type)
        
        begin
          # parse AIM Response from em-http-request
          response = Hashie::Mash.new
          response.header_status = data.response_header.status
          response.header = data.response_header
          
          # body is in JSON Format (if initial request was JSON)
          
          response.body = Hashie::Mash.new(JSON.parse(data.response))
          
          return response
        
        rescue NameError => e
        rescue ArgumentError => e
        rescue TypeError => e
          puts "rescured with error #{e.inspect}"
          response = OpenAIM::Helpers::Error.to_error({"code"=>400,"status"=>e})
          return response
        end
        return response
      end
      
      def self.parse(type)
        case type
          when "clientLogin"
            # response parameters
          when "startSession"
            puts "startSession"
        end
        
      end
      
    end
    
  end
  
end