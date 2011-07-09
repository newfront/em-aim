require 'socket'
def get_server_info  
 orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  
 UDPSocket.open do |s|  
  s.connect '64.233.187.99',1  
  puts "IP ADDRESS: #{s.addr.last}"  
  return s.addr  
 end  
ensure  
 Socket.do_not_reverse_lookup = orig  
end

puts get_server_info.inspect