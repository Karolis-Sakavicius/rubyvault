# Local file descriptor:
#
# 0-15 (16 bytes): descriptor signature (10 F4 E8 0C 18 72 A3 5D 30 66 CB E3 62 A5 CF 31)
# 16-527 (512 bytes): AES-256 file key (encrypted with RSA pub)
# 528-535 (8 bytes): size of encrypted data
# 536-543 (8 bytes): mtime (Unix)
# 544-559 (16 bytes): data IV
#
# 560 bytes in total

require_relative 'errors/no_private_key.rb'

class ArchiveFile
  LFD_SIZE = 560

  attr_reader :lfd_location, :file_key, :iv, :encrypted_size, :mtime, :filename, :cipher

  def initialize(vault_file, rsa_pem, lfd_location: nil, file_key: nil, iv: nil, cipher: nil, decrypt_cipher: nil, encrypted_size: nil, mtime:, filename:, file: nil)
    @vault_file = vault_file
    @rsa_pem = rsa_pem
    @lfd_location = lfd_location
    @file_key = file_key
    @iv = iv
    @cipher = cipher
    @decrypt_cipher = decrypt_cipher
    @encrypted_size = encrypted_size
    @mtime = mtime
    @filename = filename
    @file = file
  end

  def pending?
    @lfd_location.nil?
  end

  def save_at!(location)
    encrypted_file = cipher.update(@file.read) + cipher.final

    @vault_file.lock_into(:data) do
      @vault_file.move_to(location)

      @vault_file << [16, 244, 232, 12, 24, 114, 163, 93, 48, 102, 203, 227, 98, 165, 207, 49].pack('C*') # signature (16 bytes)
      @vault_file << @rsa_pem.public_encrypt(@file_key) # file key
      @vault_file << [encrypted_file.size].pack('Q') # encrypted size (uint_64)
      @vault_file << [@mtime.to_i].pack('Q') # mtime (uint_64)
      @vault_file << @iv

      @vault_file << encrypted_file
    end

    @lfd_location = location
    @encrypted_size = encrypted_file.size

    true
  end

  def extract!
    raise NoPrivateKey unless @rsa_pem.private?

    @vault_file.pos = @lfd_location + LFD_SIZE

    @vault_file.lock_into(:data) do
      @vault_file.move_to(@lfd_location + LFD_SIZE) # skipping the LFD

      # TODO: loads everything to memory, decrypt in chunks
      encrypted_file = @vault_file.read(@encrypted_size)
      decrypted_file = @decrypt_cipher.update(encrypted_file) + @decrypt_cipher.final

      File.open(@filename, 'wb') do |f|
        f << decrypted_file
      end
    end
  end
end
