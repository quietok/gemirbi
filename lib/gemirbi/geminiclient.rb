
#hash of ssl contexts
#no cert issuer check setting/tofu db always
#redirects
#sub request
#input queries

module Gemini
  class GeminiClient
    attr_accessor :tofu_db, :document, :ssl_context, :sockets, :certs
    
    def initialize(ca_file='/usr/local/etc/ssl/cert.pem', tofu_path='/usr/home/mouse/.gemini/tofudb.yml', verify_function)
      self.ssl_context = OpenSSL::SSL::SSLContext.new
      self.ssl_context.ca_file = ca_file
      self.sockets = []
      self.certs = []
      self.tofu_db = Gemini::TofuDB.new tofu_path, verify_function
    end

    def set_socket_context(socket, context)
    end
    
    def establish_connection(uri, port)
      socket = TCPSocket.new(uri, port)
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, self.ssl_context)
      ssl_socket.connect
      cert = ssl_socket.peer_cert
      subjectbits = cert.subject.to_s.split('/').reject { |mstr| mstr.empty? }.map { |nstr| nstr.split('=') }.to_h
      issuerbits = cert.issuer.to_s.split('/').reject { |mstr| mstr.empty? }.map { |nstr| nstr.split('=') }.to_h
      if subjectbits['CN'] == issuerbits['CN']
        puts 'in tofu part'
        indb = self.tofu_db.check_tofu(uri, cert)
        if indb
          success = true
          puts 'indb'
        else
          puts 'adding to db'
          success = self.tofu_db.add_tofu(uri, cert)
        end
        if success
          status = 'accepted by tofudb'
        else
          status = 'rejected by tofudb'
        end
      else
        verify_result = ssl_socket.verify_result
        if verify_result == 0
          success = true
        else
          status = 'check openssl verify(1)' 
          success = false
        end
      end
      if success
        self.certs.append(ssl_socket.peer_cert)
        self.sockets.append(ssl_socket)
        socketn = self.sockets.size-1
        puts status
      else
        puts 'SSL Error'
        puts status
      end
      return success, socketn
    end

    def send_request(uri, socketn)
      ## check ssl contexts, for sockets and urls
      self.sockets[socketn].connect()
      self.sockets[socketn].puts "gemini://#{uri}/\r\n"
      data = self.sockets[socketn].readlines
      header = data.slice!(0)
      content = data
      return header, content
    end

    def check_header(header)
      header_bits = header.split(' ')
      status = header_bits[0].to_i()
      header_hash = {}
      header_hash[:status_value] = status
      case status
      when 10
        header_hash[:status_text] = 'INPUT'
      when 11
        header_hash[:status_text] = 'SENSITIVE INPUT'
      when 20..29
        header_hash[:status_text] = 'SUCCESS'
      when 30
        header_hash[:status_text] = 'REDIRECT - TEMPORARY'
      when 31
        header_hash[:status_text] = 'REDIRECT - PERMANENT'
      when 40
        header_hash[:status_text] = 'TEMPORARY FAILURE'
      when 41
        header_hash[:status_text] = 'SERVER UNAVAILABLE'
      when 42
        header_hash[:status_text] = 'CGI ERROR'
      when 43
        header_hash[:status_text] = 'PROXY ERROR'
      when 44
        header_hash[:status_text] = 'SLOW DOWN'
      when 50
        header_hash[:status_text] = 'PERMANENT FAILURE'
      when 52
        header_hash[:status_text] = 'GONE'
      when 53
        header_hash[:status_text] = 'PROXY REQUEST REFUSED'
      when 59
        header_hash[:status_text] = 'BAD REQUEST'
      when 60
        header_hash[:status_text] = 'CLIENT CERTIFICATE REQUIRED'
      when 61
        header_hash[:status_text] = 'CERTIFICATE NOT AURTHORISED'
      when 62
        header_hash[:status_text] = 'CERTIFICATE NOT VALID'
      else
        header_hash[:status_text] = 'UNKNOWN STATUS CODE'
      end
      if header_bits.length > 1
        mime = header_bits[1].downcase.chomp(';')
        header_hash[:mime] = mime
        if mime == 'text/gemini'
          if header_bits.length > 2
            header_hash[:langs] = header_bits[2].split('=')[1].split(',')
          else
            header_hash[:langs] = ['UTF-8']
          end
        end
      end
      return header_hash
    end

    def process_gemini(content)
    end
  end
end
