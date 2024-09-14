add_executable(generate_coeffs generate_cheb_coeffs.cpp)
target_include_directories(generate_coeffs PRIVATE ${CMAKE_SOURCE_DIR}/app)
target_link_libraries(generate_coeffs
  PRIVATE
  ${OpenFHE_SHARED_LIBRARIES}
  OpenMP::OpenMP_CXX
)

set(GENERATED_COEFFS_PATH ${CMAKE_CURRENT_BINARY_DIR}/generated_coeffs.h)

add_custom_command(
  OUTPUT ${GENERATED_COEFFS_PATH}
  COMMAND ${CMAKE_COMMAND} -E echo "Running generate_coeffs in ${CMAKE_CURRENT_BINARY_DIR}"
  COMMAND $<TARGET_FILE:generate_coeffs>
  COMMAND ${CMAKE_COMMAND} -E echo "generate_coeffs completed"
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS generate_coeffs
  VERBATIM
)

add_custom_target(generate_coeffs_target
  DEPENDS ${GENERATED_COEFFS_PATH}
)

add_dependencies(app generate_coeffs_target)
add_dependencies(DirectSortTest generate_coeffs_target)
add_dependencies(SincTest generate_coeffs_target)
add_dependencies(DirectSortBenchmark generate_coeffs_target)

set_source_files_properties(${GENERATED_COEFFS_PATH} PROPERTIES GENERATED TRUE)

target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(DirectSortTest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(SincTest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(DirectSortBenchmark PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
