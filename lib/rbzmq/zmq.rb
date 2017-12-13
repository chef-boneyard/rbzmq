require 'zmq'

# This exists to mimic how ffi-rzmq's `recv_string` is used
# reference: https://github.com/chuckremes/ffi-rzmq/blob/release-2.0.4/lib/ffi-rzmq/socket.rb#L340-L346
module ZMQ
  class Socket
    def recv_string(message, flags = nil)
      message.replace(receive_string(flags))
    end
    alias_method :recv, :recv_string
  end
end
