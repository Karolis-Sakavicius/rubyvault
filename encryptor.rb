# Header:
#
# 0-3 (4 bytes): vault file signature (0x0A447B22)
# 4-5 (2 bytes): files count
# 6-517 (512 bytes): AES-256 meta key (encrypted with RSA pub)
# 518 (1 byte): ID length
# 519-520 (2 bytes): name length
# 521-536 (16 bytes): metadata IV
# 537-568 (32 bytes): vault ID (encrypted with meta key, 1st)
# 569-1080 (512 bytes): vault name (encrypted with meta key, 2nd)
# 1081-1,299,512 (1,298,432 bytes): file allocation table, 4096 entries
# 1,299,513-n: data

# Allocation table:
#
# 0-7 (8 bytes): pointer to local file descriptor
# 8-519 (512 bytes): AES-256 file key (encrypted with RSA pub)
# 520-527 (8 bytes): size of encrypted data
# 528-535 (8 bytes): mtime (Unix)
# 536 (1 byte): filename length
# 537-552 (16 bytes): filename IV
# 553-568 (16 bytes): data IV
# 569-824 (256 bytes): filename
# 825-828 (4 bytes): CRC-32 of encrypted data
#
# 829 bytes per row

# Local file descriptor:
#
# 0-15 (16 bytes): descriptor signature (10 F4 E8 0C 18 72 A3 5D 30 66 CB E3 62 A5 CF 31)
# 16-527 (512 bytes): AES-256 file key (encrypted with RSA pub)
# 528-535 (8 bytes): size of encrypted data
# 536-543 (8 bytes): mtime (Unix)
# 544-559 (16 bytes): data IV
# 560-563 (4 bytes): CRC-32 of encrypted data
#
# 564 bytes in total

require 'openssl'

ALLOCATION_TABLE_OFFSET = 1081
DATA_OFFSET = 1_299_513
METADATA_OFFSET = 6
ALLOCATION_TABLE_ROW_LENGTH = 829
LOCAL_FILE_DESCRIPTOR_LENGTH = 564

class Encryptor
  def initialize(file, pem_file)
    @file = file
    @rsa = OpenSSL::PKey::RSA.new(pem_file)

    determine_offsets

    initialize_file if @file.size == 0
  end

  # TODO: filename length check
  # TODO; id length check
  def set_metadata(id, name)
    @file.pos = METADATA_OFFSET

    # encrypting metadata
    meta_cipher, meta_key, meta_iv = initialize_cipher

    encrypted_id = meta_cipher.update(id.to_s) + meta_cipher.final
    encrypted_name = meta_cipher.update(name) + meta_cipher.final
    encrypted_meta_key = @rsa.public_encrypt(meta_key)

    # writing metadata
    @file << encrypted_meta_key # meta key
    @file << [encrypted_id.size].pack('C') # id length
    @file << [encrypted_name.size].pack('S') # name length
    @file << meta_iv # meta iv
    @file << encrypted_id.ljust(64, "\x00") # vault id
    @file << encrypted_name.ljust(512, "\x00") # vault name
  end

  def add_file(file)
    filename_cipher, key, filename_iv = initialize_cipher
    data_cipher, data_key, data_iv = initialize_cipher(key)
    encrypted_key = @rsa.public_encrypt(key)

    File.open(file, 'rb') do |f|
      @file.pos = @table_offset

      encrypted_filename = filename_cipher.update(File.basename(f)) + filename_cipher.final
      encrypted_data = data_cipher.update(f.read) + data_cipher.final

      # allocation table entry
      @file << [@data_offset].pack('Q*') # pointer to LFD (8 bytes, unsigned int)
      @file << encrypted_key # pub encrypted AES-256 key
      @file << [encrypted_data.size].pack('Q*') # size (8 bytes, unsigned int)
      @file << [f.mtime.to_i].pack('Q*') # mtime unix time (8 bytes, unsigned int)
      @file << [encrypted_filename.size].pack('C') # filename length (1 byte, unsigned int)
      @file << filename_iv # filename iv (16 bytes)
      @file << data_iv # data iv (16 bytes)
      @file << encrypted_filename.ljust(256, "\x00") # encrypted filename (256 bytes, zero padded)
      @file << [Zlib::crc32(encrypted_data)].pack('L*') # crc-32 (4 bytes, unsigned int)

      @table_offset = @file.pos

      # local file descriptor
      @file.pos = @data_offset
      @file << [16, 244, 232, 12, 24, 114, 163, 93, 48, 102, 203, 227, 98, 165, 207, 49].pack('C*') # signature (16 bytes)
      @file << encrypted_key # pub encrypted key (512 bytes)
      @file << [encrypted_data.size].pack('Q*') # size (8 bytes, unsigned int)
      @file << [f.mtime.to_i].pack('Q*') # mtime unix time (8 bytes, unsigned int)
      @file << data_iv # data iv (16 bytes)
      @file << [Zlib::crc32(encrypted_data)].pack('L*') # crc-32 (4 bytes, unsigned int)

      # data
      @file << encrypted_data

      @data_offset = @file.pos

      # file count
      @file_count = @file_count + 1
      @file.pos = 4

      @file << [@file_count].pack('S')
    end
  end

  def close
    @file.close
  end

  private

  def initialize_file
    @file.pos = 0

    @file << [10, 68, 123, 34].pack('C*')
    @file << [@file_count].pack('S')
  end

  def decrypt_or_initialize_session_key
    if @file.size != 0
      @file.pos = 6

      encrypted_key = @file.read(512)

      rsa = OpenSSL::PKey::RSA.new(@pem_file)

      rsa.private_decrypt(encrypted_key)
    else
      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.encrypt
      key = cipher.random_key

      key
    end
  end

  def initialize_cipher(key = nil)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    iv = cipher.random_iv

    if key
      cipher.key = key
    else
      key = cipher.random_key
    end

    return cipher, key, iv
  end

  # TODO: check if file is correct
  def determine_offsets
    @data_offset = DATA_OFFSET
    @table_offset = ALLOCATION_TABLE_OFFSET
    @file_count = 0

    if @file.size != 0
      # jumping to allocation table
      @file.pos = @table_offset

      4096.times do |t|
        if @file.read(8).unpack('Q').first != 0
          size = @file.read(8).unpack('Q').first.to_i

          @table_offset = @table_offset + ALLOCATION_TABLE_ROW_LENGTH
          @data_offset = @data_offset + size + LOCAL_FILE_DESCRIPTOR_LENGTH
          @file_count = @file_count + 1

          @file.pos = @table_offset
        else
          break
        end
      end
    end
  end
end
