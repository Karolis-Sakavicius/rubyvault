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
  def initialize(rsa_pem, vault_file)
    @rsa_pem = rsa_pem
    @vault_file = vault_file
    @metadata = []

    if @vault_file.empty?
      @initial_call = true
      # initializing encrypt cipher
      encrypt_cipher
    end

    read_metadata unless @vault_file.empty?
  end

  def read_metadata
    @vault_file.lock_into(:metadata) do
      if @rsa_pem.private?
        @key = @rsa_pem.private_decrypt(@vault_file.read(512))
        @iv = @vault_file.read(16)

        cipher = OpenSSL::Cipher.new('aes-256-cbc')
        cipher.decrypt
        cipher.key = @key
        cipher.iv = @iv
      else
        @vault_file.move_to(512 + 16) # ignoring the key if pem does not have a private key
      end

      12.times do |row|
        key_length = @vault_file.read(1).unpack('C').first
        value_length = @vault_file.read(1).unpack('C').first
        is_encrypted = @vault_file.read(1).unpack('C').first

        break if key_length == 0 # further meta rows are empty

        if is_encrypted == 1 && @rsa_pem.private?
          encrypted_key = @vault_file.read(32)[0..key_length - 1]
          encrypted_value = @vault_file.read(64)[0..value_length - 1]

          row_key = cipher.update(encrypted_key) + cipher.final
          row_value = cipher.update(encrypted_value) + cipher.final

          @metadata << {key: row_key, value: row_value, encrypted: true}
        elsif is_encrypted == 1 && !@rsa_pem.private?
          @vault_file.read(96) # moving the pointer further & ignoring the encrypted row
          @metadata << {key: '[ENCRYPTED]', value: '[ENCRYPTED]', encrypted: true}
        else
          row_key = @vault_file.read(32)[0..key_length - 1]
          row_value = @vault_file.read(64)[0..value_length - 1]

          @metadata << {key: row_key, value: row_value, encrypted: false}
        end
      end
    end
  end

  # Metadata key is encrypted with public key and requires private one to
  # decrypt it. Then this key gets encrypted again with a public key.
  # Hence this requires public & private keys to be present.
  #
  # TODO: can be optimized to work with only private key.
  def add_metadata(key:, value:, encrypt:)
    raise NoPrivateKey unless @rsa_pem.private?
    raise NoPublicKey unless @rsa_pem.public?

    @metadata << {key: key, value: value, encrypted: encrypt, pending: true}
  end

  def changes_pending?
    @metadata.any? { |meta| meta[:pending] == true }
  end

  def to_a
    @metadata
  end

  # When changes are present ALL metadata is rewritten to ensure AES-256 integrity.
  # Encrypted rows must be encrypted in a right order, as rows do not contain
  # individual IVs.
  def commit_changes!
    return unless changes_pending?

    @vault_file.lock_into(:metadata) do
      @vault_file << @rsa_pem.public_encrypt(@key) # AES key
      @vault_file << @iv

      write_binary_table
    end

    @metadata.each do |meta|
      meta.delete(:pending)
    end

    true
  end

  private

  # TODO: max 12 entries
  # TODO: length validations
  def write_binary_table
    12.times do |row_no|
      meta = @metadata[row_no]

      if meta.nil?
        @vault_file << "\x00" * 99 # filling unused rows with NULL
      elsif meta[:encrypted]
        encrypted_key = encrypt_cipher.update(meta[:key].to_s) + encrypt_cipher.final
        encrypted_value = encrypt_cipher.update(meta[:value]) + encrypt_cipher.final

        @vault_file << [encrypted_key.size].pack('C') # key length
        @vault_file << [encrypted_value.size].pack('C') # value length
        @vault_file << [1].pack('C') # is encrypted = 1
        @vault_file << encrypted_key.ljust(32, "\x00") # key
        @vault_file << encrypted_value.ljust(64, "\x00") # value
      else
        @vault_file << [meta[:key].size].pack('C') # key length
        @vault_file << [meta[:value].size].pack('C') # value length
        @vault_file << [0].pack('C') # is encrypted = 0
        @vault_file << [meta[:key].to_s].pack('a*').ljust(32, "\x00") # key
        @vault_file << [meta[:value]].pack('a*').ljust(64, "\x00") # value
      end
    end
  end

  def encrypt_cipher
    return @encrypt_cipher if @encrypt_cipher

    @encrypt_cipher = OpenSSL::Cipher.new('aes-256-cbc')
    @encrypt_cipher.encrypt

    if @initial_call
      @key = @encrypt_cipher.random_key
      @iv = @encrypt_cipher.random_iv
    else
      @encrypt_cipher.key = @key
      @encrypt_cipher.iv = @iv
    end

    @encrypt_cipher
  end
end
