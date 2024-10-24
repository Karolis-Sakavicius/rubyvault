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

require_relative 'errors/out_of_bounds_write_error.rb'
require_relative 'errors/out_of_bounds_read_error.rb'
require_relative 'errors/out_of_bounds_move_error.rb'
require_relative 'errors/signature_mismatch_error.rb'
require 'pry'

class VaultFile
  SECTION_BOUNDARIES = {
    signature: {start: 0, end: 3},
    version: {start: 4, end: 4},
    flags: {start: 5, end: 5},
    metadata: {start: 6, end: 1721},
    allocation_table: {start: 1722, end: 3_380_921},
    data: {start: 3_380_922}
  }.freeze

  TYPES = {
    uint8_t: {directive: 'C', length: 1},
    uint16_t: {directive: 'S', length: 2},
    uint32_t: {directive: 'L', length: 4},
    uint64_t: {directive: 'Q', length: 8}
  }.freeze

  TYPES.each do |type|
    define_method "read_#{type.first}" do
      read(type.last[:length]).unpack(type.last[:directive]).first
    end
  end

  TYPES.each do |type|
    define_method "write_#{type.first}" do |data|
      self << [data].pack(type.last[:directive])
    end
  end

  TYPES.each do |type|
    define_method "read_#{type.first}_from_section" do |section, position: 0|
      data = nil

      lock_into(section) do
        move_to position
        data = send("read_#{type.first}")
      end

      data
    end
  end

  TYPES.each do |type|
    define_method "write_#{type.first}_to_section" do |section, data, position: 0|
      lock_into(section) do
        move_to position
        self << [data].pack(type.last[:directive])
      end
    end
  end

  def initialize(filepath)
    if File.exists? filepath
      @file = File.open(filepath, "rb+")

      verify_signature!
    else
      @file = File.open(filepath, "wb+")
    end

    @current_section = nil
  end

  def lock_into(section)
    @current_section = section
    @file.pos = SECTION_BOUNDARIES[section][:start]
    yield
    @current_section = nil
  end

  def read_from(section, bytes, position: 0)
    data = nil

    lock_into(section) do
      move_to position
      data = read(bytes)
    end

    data
  end

  def write_to(section, data, position: 0)
    lock_into(section) do
      move_to position
      self << data
    end
  end

  def read(bytes)
    raise OutOfBoundsReadError.new(requested_read_length: bytes) unless @current_section

    if @file.pos - 1 + bytes > end_boundary
      raise OutOfBoundsReadError.new(
        current_section: @current_section,
        current_location: @file.pos,
        requested_read_length: bytes,
        section_start_boundary: start_boundary,
        section_end_boundary: end_boundary
      )
    end

    @file.read(bytes)
  end

  def <<(data)
    raise OutOfBoundsWriteError.new(data: data) unless @current_section

    ensure_integrity!(data)
    @file << data
  end

  def move_to(relative_location)
    raise OutOfBoundsMoveError.new(requested_move_location: relative_location) unless @current_section

    absolute_location = start_boundary + relative_location

    if absolute_location < start_boundary || absolute_location > end_boundary
      raise OutOfBoundsMoveError.new(
        requested_move_location: relative_location,
        current_section: @current_section.to_s,
        section_start_boundary: start_boundary,
        section_end_boundary: end_boundary
      )
    end

    @file.pos = absolute_location
  end

  def size
    @file.size
  end

  def close
    @file.close
  end

  def empty?
    size == 0
  end

  private

  def verify_signature!
    raise SignatureMismatchError unless read_from(:signature, 4).unpack('C*') == [10, 68, 123, 34]
  end

  def ensure_integrity!(data)
    current_position = @file.pos

    if current_position - 1 + data.size > end_boundary
      raise OutOfBoundsWriteError.new(
        current_section: @current_section,
        current_location: current_position,
        data: data,
        section_start_boundary: start_boundary,
        section_end_boundary: end_boundary
      )
    end
  end

  def start_boundary
    SECTION_BOUNDARIES[@current_section][:start]
  end

  def end_boundary
    SECTION_BOUNDARIES[@current_section][:end] || Float::INFINITY
  end
end
