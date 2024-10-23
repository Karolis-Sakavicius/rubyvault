class OutOfBoundsWriteError < StandardError
  def initialize(current_section: nil, current_location: nil, data:, section_start_boundary: nil, section_end_boundary: nil)
    @current_section = current_section
    @current_location = current_location
    @data = data
    @section_start_boundary = section_start_boundary
    @section_end_boundary = section_end_boundary
    @data_hex_string = data.bytes.map { |b| b.to_s(16).rjust(2, '0') }.join(' ')

    if @current_section
      @msg = "Illegal write outside of section's #{current_section} boundaries. " \
             "Section boundaries: #{section_start_boundary}-#{section_end_boundary}. " \
             "Tried to write #{data.size} bytes at location #{current_location}. " \
             "Data: #{@data_hex_string}"
    else
      @msg = "Write operation was called outside of lock_into block. " \
             "Tried to write #{data.size} bytes. Data: #{@data_hex_string}."
    end

    super(@msg)
  end
end
