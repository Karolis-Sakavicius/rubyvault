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
  ALLOCATION_TABLE_OFFSET = 1722
  ROW_LENGTH = 825
  LFD_LENGTH = 560
  INITIAL_DATA_OFFSET = 3_380_922

  def initialize(rsa_pem, file)
    @rsa_pem = rsa_pem
    @file = file

    @table = []
    read_table
  end

  def add_file(file)
    raise NoPublicKey unless @rsa_pem.public?

    cipher, key, iv = new_cipher

    @table << ArchiveFile.new(
      @file,
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
    current_data_offset = INITIAL_DATA_OFFSET

    4096.times do |row|
      record = @table[row]

      break if record.nil? # reached the end of files list

      if record.lfd_location
        # skipping an existing row
      else
        encrypted_filename = record.cipher.update(record.filename) + record.cipher.final
        record.save_at!(current_data_offset)

        @file.pos = ALLOCATION_TABLE_OFFSET + row * ROW_LENGTH

        @file << [record.lfd_location].pack('Q') # LFD location (uint_64)
        @file << @rsa_pem.public_encrypt(record.file_key) # AES-256 key
        @file << record.iv # dupe for now TODO
        @file << record.iv # iv
        @file << [record.encrypted_size].pack('Q') # encrypted size (uint_64)
        @file << [record.mtime.to_i].pack('Q') # mtime (uint_64)
        @file << [encrypted_filename.size].pack('C') # encrypted filename length
        @file << encrypted_filename # filename
      end

      current_data_offset = current_data_offset + LFD_LENGTH + record.encrypted_size # shifting to the next file in data section
    end
  end

  private

  def read_table
    @file.pos = ALLOCATION_TABLE_OFFSET

    return if @file.eof?

    4096.times do |row|
      lfd_location = @file.read(8).unpack('Q').first

      break if lfd_location == 0 # reached the end of the table

      if @rsa_pem.private?
        file_key = @rsa_pem.private_decrypt(@file.read(512))
      else
        @file.read(512)
        file_key = '[ENCRYPTED]'
      end

      iv = @file.read(16)
      @file.read(16) # TODO unify IVs for filenames and data
      encrypted_size = @file.read(8).unpack('Q').first
      mtime = @file.read(8).unpack('Q').first
      encrypted_filename_length = @file.read(1).unpack('C').first
      encrypted_filename = @file.read(256)[0..encrypted_filename_length - 1]

      if @rsa_pem.private?
        cipher = decrypt_cipher(file_key, iv)

        filename = cipher.update(encrypted_filename) + cipher.final
      else
        cipher = nil
        filename = '[ENCRYPTED]'
      end

      @table << ArchiveFile.new(
        @file,
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
