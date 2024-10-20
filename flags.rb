# Flags (MSB first):
# Bits 0-7: unused

class Flags
  FLAGS_OFFSET = 5

  def initialize(flags)
  end

  def to_binary
    [0].pack('C')
  end

  def to_h
    {}
  end

  def self.from_file(file)
    new(0)
  end
end
