# Flags (MSB first):
# Bits 0-7: unused

class Flags
  def initialize(vault_file)
    @vault_file = vault_file
  end

  def commit_changes!
    @vault_file.write_to(:flags, "\x00")
  end
end
