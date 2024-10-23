class OutOfBoundsMoveError < StandardError
  def initialize(current_section: nil, requested_move_location:, section_start_boundary: nil, section_end_boundary: nil)
    @current_section = current_section
    @requested_move_location = requested_move_location
    @section_start_boundary = section_start_boundary
    @section_end_boundary = section_end_boundary

    if @current_section
      @msg = "Requested move is outside of section's #{current_section} boundaries. " \
             "Section boundaries: #{section_start_boundary}-#{section_end_boundary}. " \
             "Requested move location: #{requested_move_location}"
    else
      @msg = "move_to was called outside of lock_into block. " \
             "Requested relative move to position #{requested_move_location}."
    end

    super(@msg)
  end
end
