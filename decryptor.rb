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
require 'zlib'
require 'pry'

ALLOCATION_TABLE_OFFSET = 1081
DATA_OFFSET = 1_299_513
METADATA_OFFSET = 6
ALLOCATION_TABLE_ROW_LENGTH = 829
LOCAL_FILE_DESCRIPTOR_LENGTH = 564

class Decryptor
  attr_reader :file_count, :id, :name

  def initialize(file, pem_file)
    @file = file
    @rsa = OpenSSL::PKey::RSA.new(pem_file)

    @data_offset = DATA_OFFSET
    @table_offset = ALLOCATION_TABLE_OFFSET

    extract_metadata
  end

  def decrypt_file(num)
    @file.pos = @table_offset + num * ALLOCATION_TABLE_ROW_LENGTH

    lfd_offset = @file.read(8).unpack('Q*').first

    return false if lfd_offset == 0

    # reading allocation table entry
    key = @rsa.private_decrypt(@file.read(512))
    size = @file.read(8).unpack('Q*').first
    mtime = @file.read(8).unpack('Q*').first
    filename_size = @file.read(1).unpack('C').first
    filename_iv = @file.read(16)
    data_iv = @file.read(16)
    encrypted_filename = @file.read(256)
    crc32 = @file.read(4).unpack('L*')

    filename_cipher = initialize_cipher(key, filename_iv)
    data_cipher = initialize_cipher(key, data_iv)

    filename = filename_cipher.update(encrypted_filename[0..filename_size - 1]) + filename_cipher.final

    @file.pos = lfd_offset + LOCAL_FILE_DESCRIPTOR_LENGTH
    encrypted_contents = @file.read(size)
    contents = data_cipher.update(encrypted_contents) + data_cipher.final

    File.open("out/#{filename}", 'wb') do |outf|
      outf << contents
    end

    File.utime(mtime, mtime, "out/#{filename}")
  end

  def close
    @file.close
  end

  private

  def extract_metadata
    @file.pos = 4

    @file_count = @file.read(2).unpack('S').first.to_i

    meta_key = @rsa.private_decrypt(@file.read(512))
    id_size = @file.read(1).unpack('C').first
    name_size = @file.read(2).unpack('S').first
    meta_iv = @file.read(16)

    meta_cipher = initialize_cipher(meta_key, meta_iv)

    @id = meta_cipher.update(@file.read(64)[0..id_size - 1]) + meta_cipher.final
    @name = meta_cipher.update(@file.read(512)[0..name_size - 1]) + meta_cipher.final
  end

  def initialize_cipher(key, iv)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv

    cipher
  end
end

enc_file = File.open('enc.enc')
pem_file = File.open('rsa.pem')
decryptor = Decryptor.new(enc_file, pem_file)

puts decryptor.id
puts decryptor.name

decryptor.decrypt_file(0)
decryptor.decrypt_file(1)