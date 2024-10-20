# 6-519 (512 bytes): AES-256 meta key (encrypted with RSA pub)
# 520-535 (16 bytes): meta IV
#
# Metadata table
#
# 0 (1 byte): key length
# 1 (1 byte): value length
# 2 (1 byte): is row encrypted
# 3-34 (32 bytes): key
# 35-98 (64 bytes): value
#
# 12 rows allowed, 1,188 bytes

require 'pry'

class Metadata
  METADATA_OFFSET = 6

  def initialize(rsa_pem, metadata, cipher: nil, key: nil, iv: nil)
    @rsa_pem = rsa_pem
    @metadata = metadata

    if cipher
      @cipher = cipher
      @key = key
      @iv = iv
    else
      @cipher, @key, @iv = new_cipher
    end
  end

  def self.from_file(file, rsa_pem)
    file.pos = METADATA_OFFSET

    if rsa_pem.private?
      key = rsa_pem.private_decrypt(file.read(512))
      iv = file.read(16)

      cipher = OpenSSL::Cipher.new('aes-256-cbc')
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv
    else
      file.pos = METADATA_OFFSET + 512 + 16 # ignoring the key if pem does not have a private key
    end

    metadata = []

    12.times do |row|
      key_length = file.read(1).unpack('C').first
      value_length = file.read(1).unpack('C').first
      is_encrypted = file.read(1).unpack('C').first

      break if key_length == 0 # further meta rows are empty

      if is_encrypted == 1 && rsa_pem.private?
        encrypted_key = file.read(32)[0..key_length - 1]
        encrypted_value = file.read(64)[0..value_length - 1]

        row_key = cipher.update(encrypted_key) + cipher.final
        row_value = cipher.update(encrypted_value) + cipher.final

        metadata << {key: row_key, value: row_value, encrypted: true}
      elsif is_encrypted == 1 && !rsa_pem.private?
        file.read(96) # moving the pointer further & ignoring the encrypted row
        metadata << {key: '[ENCRYPTED]', value: '[ENCRYPTED]', encrypted: true}
      else
        row_key = file.read(32)[0..key_length - 1]
        row_value = file.read(64)[0..value_length - 1]

        metadata << {key: row_key, value: row_value, encrypted: false}
      end
    end

    new(rsa_pem, metadata, cipher: cipher, key: key, iv: iv)
  end

  def to_a
    @metadata
  end

  def to_h
    {}.tap do |meta_hash|
      @metadata.each do |meta|
        meta_hash[meta[:key]] = {value: meta[:value], encrypted: meta[:encrypted]}
      end
    end
  end

  def to_binary
    binary_string = ''

    binary_string << @rsa_pem.public_encrypt(@key) # AES key
    binary_string << @iv # IV
    binary_string << binary_table

    binary_string
  end

  private

  # TODO: max 12 entries
  # TODO: length validations
  def binary_table
    binary_string = ''

    12.times do |row_no|
      meta = @metadata[row_no]

      if meta.nil?
        binary_string << "\x00" * 99 # filling unused rows with NULL
      elsif meta[:encrypted]
        encrypted_key = @cipher.update(meta[:key].to_s) + @cipher.final
        encrypted_value = @cipher.update(meta[:value]) + @cipher.final

        binary_string << [encrypted_key.size].pack('C') # key length
        binary_string << [encrypted_value.size].pack('C') # value length
        binary_string << [1].pack('C') # is encrypted = 1
        binary_string << encrypted_key.ljust(32, "\x00") # key
        binary_string << encrypted_value.ljust(64, "\x00") # value
      else
        binary_string << [meta[:key].size].pack('C') # key length
        binary_string << [meta[:value].size].pack('C') # value length
        binary_string << [0].pack('C') # is encrypted = 0
        binary_string << [meta[:key].to_s].pack('a*').ljust(32, "\x00") # key
        binary_string << [meta[:value]].pack('a*').ljust(64, "\x00") # value
      end
    end

    binary_string
  end

  def new_cipher
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    iv = cipher.random_iv
    key = cipher.random_key

    return cipher, key, iv
  end
end
