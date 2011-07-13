module OpenAIM
  
  module Helpers
    
    module Error
      
      def self.to_error(params = {})
        
        error = Hashie::Mash.new
        
        params.each{|k,v| error[k] = v}
        
        return error
        
      end
      
    end  
    
  end
  
end