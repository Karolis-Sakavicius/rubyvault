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

# Header:
#
# 0-3 (4 bytes): vault file signature
# 4 (1 byte): vault version
# 5 (1 byte): flags
# 6-517 (512 bytes): AES-256 meta key (encrypted with RSA pub)
# 518-533 (16 bytes): meta IV
# 534-1,721 (1,188 bytes): metadata table
# 1,722-3,380,921 (3,379,200 bytes): file allocation table
# 3,380,922-n: data

# Metadata table
#
# 0 (1 byte): key length
# 1 (1 byte): value length
# 2 (1 byte): is row encrypted
# 3-34 (32 bytes): key
# 35-98 (64 bytes): value
#
# 12 rows allowed, 1,188 bytes

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

require 'openssl'
require_relative './vault_file.rb'
require_relative './metadata.rb'
require_relative './flags.rb'
require_relative './allocation_table.rb'
require 'pry'

class Archive
  RUBYVAULT_VERSION = 1

  attr_reader :version, :metadata, :flags

  def initialize(filepath, rsa_pem:, **flags)
    @rsa_pem = rsa_pem
    @vault_file = VaultFile.new(filepath)

    if @vault_file.empty?
      @version = RUBYVAULT_VERSION
    else
      @version = @vault_file.read_from(:version, 1).unpack('C').first
    end

    binding.pry
    @flags = Flags.new(@vault_file)
    @metadata = Metadata.new(@rsa_pem, @vault_file)
    @allocation_table = AllocationTable.new(@rsa_pem, @vault_file)
  end

  def self.open(filepath, rsa_pem:)
    new(filepath, rsa_pem: rsa_pem)
  end

  def add_file(filepath)
    file = File.open(filepath, 'rb')

    @allocation_table.add_file(file)
  end

  def files
    @allocation_table.files
  end

  def save!
    @vault_file.write_to(:signature, [10, 68, 123, 34].pack('C*')) # vault file signature
    @vault_file.write_to(:version, [@version].pack('C')) # RubyVault version

    @flags.commit_changes!
    @metadata.commit_changes!
    @allocation_table.commit_changes!
  end
end

pem_file = File.open('rsa.pub')
rsa_pem = OpenSSL::PKey::RSA.new(pem_file)

archive = Archive.open('enc.rvault', rsa_pem: rsa_pem)
# archive.save!
binding.pry