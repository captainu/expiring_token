require 'openssl'
require 'base64'
require 'digest/sha2'
require 'cgi'
require 'time'

class TokenExpired < StandardError; end
class InvalidToken < StandardError; end

class ExpiringToken

  def self.generate(key)
    cipher = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    cipher.encrypt
    cipher.key = Digest::SHA2.digest(key)
    token = cipher.update(Time.now.gmtime.to_s)
    token << cipher.final
    CGI.escape(Base64.encode64(token))
  end

  def self.valid?(token, key, lifespan)
    begin
      token = Base64.decode64(CGI.unescape(token))
      cipher = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
      cipher.decrypt
      cipher.key = Digest::SHA2.digest(key)
      data = cipher.update(token)
      data << cipher.final

      raise TokenExpired unless (Time.now.gmtime - Time.parse(data)) <= lifespan.to_i

      true
    rescue OpenSSL::Cipher::CipherError
      raise InvalidToken
    end
  end

end
