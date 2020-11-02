
#hash of ssl contexts
#no cert issuer check setting/tofu db always
#redirects
#sub request
#input queries

module Gemini
  class GeminiClient
    attr_accessor :tofu_db, :document, :ssl_contexts, :sockets, :certs, :ca_file_path
    
    def initialize(ca_file_path='/usr/local/etc/ssl/cert.pem', tofu_path='/usr/home/mouse/.gemini/tofudb.yml', root_ca_path='/usr/mouse/.gemini/root.pem', verify_function)
      #self.ssl_context = OpenSSL::SSL::SSLContext.new
      self.ca_file_path = ca_file_path
      self.sockets = []
      self.ssl_contexts = []
      self.certs = []
      self.tofu_db = Gemini::TofuDB.new tofu_path, verify_function
    end

    def generate_client_root_ca
      root_key = OpenSSL::PKey::RSA.new 2048
      root_ca = OpenSSL::X509::Certificate.new
      root_ca.version = 2
      root_ca.serial = 1
      root_ca.subject = OpenSSL::X509::Name.parse "/DC=#{self.cdc[0]}/DC=#{self.cdc[1]}/CN=#{self.cn}"
      root_ca.issuer = root_ca.subject
      root_ca.not_before = Time.now
      root_ca.not_after = root_ca.not_before + self.ca_length
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = root_ca
      ef.issuer_certificate = root_ca
      root_ca.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
      root_ca.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
      root_ca.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      root_ca.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
      root_ca.sign(root_key, OpenSSL::Digest::SHA256.new)
      self.root_ca = root_ca
      return true
    end

    def create_ssl_context
      posistion = self.ssl_contexts.size
      self.ssl_contexts[posistion] = OpenSSL::SSL::SSLContext.new
      self.ssl_contexts[posistion].ca_file = self.ca_file_path
      return posistion
    end

    def generate_client_key(socket, dc, cn)
      key = OpenSSL::PKey::RSA.new 2048
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      cert.subject = OpenSSL::X509::Name.parse "/DC=#{dc[0]}/DC=#{dc[1]}/CN=Ruby certificate"
      cert.issuer = root_ca.subject # root CA is the issuer
      cert.public_key = key.public_key
      cert.not_before = Time.now
      cert.not_after = cert.not_before + 1 * 365 * 24 * 60 * 60 # 1 years validity
      ef = OpenSSL::X509::ExtensionFactory.new
      ef.subject_certificate = cert
      ef.issuer_certificate = root_ca
      cert.add_extension(ef.create_extension("keyUsage","digitalSignature", true))
      cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
      cert.sign(root_key, OpenSSL::Digest::SHA256.new)
      return cert
    end

    def add_client_key(socket,cert)
      
    end

    def send_input(site_path, input_data, socket)
      ready_input = URI.encode_www_form_component(input_data).gsub('+','%20')
      return self.send_request site_path + '?' + ready_input, socket
    end
    
    def establish_connection(uri, port)
      socket = TCPSocket.new(uri, port)
      ssl_context = create_ssl_context
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, self.ssl_contexts[ssl_context])
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
      self.sockets[socketn].puts "gemini://#{uri}\r\n"
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
