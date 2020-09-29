require 'date'
module Gemini
  class TofuDB

    attr_accessor :DB, :path, :verify_function

    def initialize(path, verify_function)
      if File.exists? path
        self.DB = YAML.load_file(path)
      else
        self.DB = {}
      end
      self.verify_function = verify_function
      self.path = path
    end
    
    def check_tofu(uri, cert)
      now = DateTime.now.to_time
      expires = cert.not_after
      valid_on = cert.not_before
      if self.DB.key? uri and now < expires
        if self.DB[uri][:public_key] == cert.public_key.to_s and self.DB[uri][:expires] == expires
          return true
        else
          if self.DB[uri][:expires] < now and expires > self.DB[uri][:expires]
            return self.update_tofu(uri, cert)
          else
            return false
          end
        end
      else
        return false
      end
    end

    def update_tofu(uri, cert)
      self.DB[uri] = {
        :public_key => cert.public_key.to_s,
        :valid_on => cert.not_before,
        :expires => cert.not_after
      }
      return self.verify_function.call uri, cert
    end

    def add_tofu(uri, cert)
      now = DateTime.now.to_time
      expires = cert.not_after
      valid_on = cert.not_before
      self.DB[uri] = {
        :public_key => cert.public_key.to_s, 
        :valid_on => cert.not_before,
        :expires => cert.not_after
      }
      return self.verify_function.call uri, cert
    end
    
    def remove_tofu(uri)
      self.DB.delete uri
    end

    def close
      File.open(self.path, 'w') do |yam|
        YAML.dump(self.DB,yam)
      end
    end
    
  end
  
end

