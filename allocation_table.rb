# Allocation table:
#
# 0-7 (8 bytes): pointer to local file descriptor
# 8-519 (512 bytes): AES-256 file key (encrypted with RSA pub)
# 520-535 (16 bytes): filename IV
# 536-551 (16 bytes): data IV
# 552-559 (8 bytes): size of encrypted data
# 560-567 (8 bytes): mtime (Unix)
# 568 (1 byte): filename length
# 569-824 (256 bytes): filename
#
# 825 bytes per row

require_relative './archive_file.rb'
require_relative 'errors/no_public_key.rb'

class AllocationTable
  ROW_LENGTH = 825
  LFD_LENGTH = 560

  def initialize(rsa_pem, vault_file)
    @rsa_pem = rsa_pem
    @vault_file = vault_file

    @table = []
    read_table
  end

  def add_file(file)
    raise NoPublicKey unless @rsa_pem.public?

    cipher, key, iv = new_cipher

    @table << ArchiveFile.new(
      @vault_file,
      @rsa_pem,
      file_key: key,
      iv: iv,
      cipher: cipher,
      mtime: file.mtime,
      filename: File.basename(file),
      file: file
    )
  end

  def files
    @table
  end

  def commit_changes!
    current_data_offset = 0

    4096.times do |row|
      record = @table[row]

      break if record.nil? # reached the end of files list

      if record.lfd_location
        # skipping an existing row
      else
        encrypted_filename = record.cipher.update(record.filename) + record.cipher.final
        record.save_at!(current_data_offset)

        @vault_file.lock_into(:allocation_table) do
          @vault_file.move_to(row * ROW_LENGTH)

          @vault_file << [record.lfd_location].pack('Q') # LFD location (uint_64)
          @vault_file << @rsa_pem.public_encrypt(record.file_key) # AES-256 key
          @vault_file << record.iv # dupe for now TODO
          @vault_file << record.iv # iv
          @vault_file << [record.encrypted_size].pack('Q') # encrypted size (uint_64)
          @vault_file << [record.mtime.to_i].pack('Q') # mtime (uint_64)
          @vault_file << [encrypted_filename.size].pack('C') # encrypted filename length
          @vault_file << encrypted_filename # filename
        end
      end

      # TODO: this is always EOF (vault.size pointer).
      # Probably makes sense not to keep record of current data offset.
      current_data_offset = current_data_offset + LFD_LENGTH + record.encrypted_size # shifting to the next file in data section
    end
  end

  private

  def read_table
    return if @vault_file.empty?

    @vault_file.lock_into(:allocation_table) do
      4096.times do |row|
        lfd_location = @vault_file.read(8).unpack('Q').first
        encrypted_file_key = @vault_file.read(512)
        iv = @vault_file.read(16)
        @vault_file.read(16) # TODO: unify IVs for filenames and data
        encrypted_size = @vault_file.read(8).unpack('Q').first
        mtime = @vault_file.read(8).unpack('Q').first
        encrypted_filename_length = @vault_file.read(1).unpack('C').first
        encrypted_filename = @vault_file.read(256)[0..encrypted_filename_length - 1]

        break if encrypted_filename_length == 0 # reached the end of the table

        if @rsa_pem.private?
          file_key = @rsa_pem.private_decrypt(encrypted_file_key)

          cipher = decrypt_cipher(file_key, iv)
          filename = cipher.update(encrypted_filename) + cipher.final
        else
          cipher = nil
          file_key = '[ENCRYPTED]'
          filename = '[ENCRYPTED]'
        end

        @table << ArchiveFile.new(
          @vault_file,
          @rsa_pem,
          lfd_location: lfd_location,
          file_key: file_key,
          iv: iv,
          encrypted_size: encrypted_size,
          decrypt_cipher: cipher,
          mtime: mtime,
          filename: filename
        )
      end
    end
  end

  def decrypt_cipher(key, iv)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    cipher
  end

  def new_cipher
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    iv = cipher.random_iv
    key = cipher.random_key

    return cipher, key, iv
  end
end
