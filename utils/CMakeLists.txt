add_executable(generate_coeffs generate_cheb_coeffs.cpp)

target_include_directories(generate_coeffs PRIVATE ${CMAKE_SOURCE_DIR}/app)

  target_link_libraries(generate_coeffs
    PRIVATE
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_coeffs.h
    COMMAND generate_coeffs
    DEPENDS generate_coeffs
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

add_custom_target(generate_coeffs_target
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/generated_coeffs.h
)

add_dependencies(app generate_coeffs_target)

