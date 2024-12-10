include(GoogleTest)

function(add_kway_unit_test TARGET_NAME)
  # The first argument is the target name, the rest are source files
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE
	  ${CMAKE_SOURCE_DIR}/app/k-way)

  target_link_libraries(${TARGET_NAME}
    PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
  
  gtest_discover_tests(${TARGET_NAME})
endfunction()

add_kway_unit_test(EvalUtilsTest 
	EvalUtilsTest.cpp 
	${CMAKE_SOURCE_DIR}/app/k-way/EvalUtils.cpp)
