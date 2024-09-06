include(GoogleTest)

function(add_unit_test TARGET_NAME)
  # The first argument is the target name, the rest are source files
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/app)

  target_link_libraries(${TARGET_NAME}
    PRIVATE
    GTest::gtest_main
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
  
  gtest_discover_tests(${TARGET_NAME})
endfunction()

add_unit_test(SincTest 
	      SincTest.cpp 
	      ${CMAKE_SOURCE_DIR}/app/comparison.cpp)

add_unit_test(SignTest 
	      SignTest.cpp 
	      ${CMAKE_SOURCE_DIR}/app/comparison.cpp)

add_unit_test(CompareTest 
	      CompareTest.cpp 
	      ${CMAKE_SOURCE_DIR}/app/encryption.cpp
	      ${CMAKE_SOURCE_DIR}/app/comparison.cpp)

add_unit_test(NAFTest
	      NAFTest.cpp)

add_unit_test(RotateTest
	      ${CMAKE_SOURCE_DIR}/app/encryption.cpp
	      RotationTest.cpp)

add_unit_test(DirectSortTest 
	      DirectSortTest.cpp 
	      ${CMAKE_SOURCE_DIR}/app/comparison.cpp
	      ${CMAKE_SOURCE_DIR}/app/encryption.cpp)
