class SignatureMismatchError < StandardError
  def initialize
    super("Opened file's signature does not match RubyVault file signature.")
  end
end
