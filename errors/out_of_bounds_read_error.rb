class OutOfBoundsReadError < StandardError
  def initialize(current_section: nil, current_location: nil, requested_read_length:, section_start_boundary: nil, section_end_boundary: nil)
    @current_section = current_section
    @current_location = current_location
    @requested_read_length = requested_read_length
    @section_start_boundary = section_start_boundary
    @section_end_boundary = section_end_boundary

    if @current_section
      @msg = "Requested read is outside of section's #{current_section} boundaries. " \
             "Section boundaries: #{section_start_boundary}-#{section_end_boundary}. " \
             "Requested read for #{requested_read_length} bytes, current location is #{current_location}."
    else
      @msg = "read was called outside of lock_into block. " \
             "Requested read for #{requested_read_length} bytes."
    end

    super(@msg)
  end
end
