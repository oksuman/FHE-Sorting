# New Google Benchmark setup
function(add_benchmark TARGET_NAME)
  # The first argument is the target name, the rest are source files
  set(SOURCE_FILES ${ARGN})
  
  add_executable(${TARGET_NAME} ${SOURCE_FILES})
  target_include_directories(${TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/app)
  target_include_directories(${TARGET_NAME} PRIVATE
	  ${CMAKE_SOURCE_DIR}/third_party/benchmark)
  target_link_libraries(${TARGET_NAME}
    PRIVATE
    benchmark::benchmark
    ${OpenFHE_SHARED_LIBRARIES}
    OpenMP::OpenMP_CXX
  )
endfunction()

add_benchmark(SincBenchmark 
              SincBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/app/sign.cpp
              ${CMAKE_SOURCE_DIR}/app/comparison.cpp)

add_benchmark(BitonicSortBenchmark 
	      BitonicSortBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/app/sign.cpp
              ${CMAKE_SOURCE_DIR}/app/comparison.cpp
              ${CMAKE_SOURCE_DIR}/app/encryption.cpp)

add_benchmark(DirectSortBenchmark 
	      DirectSortBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/app/sign.cpp
              ${CMAKE_SOURCE_DIR}/app/comparison.cpp
              ${CMAKE_SOURCE_DIR}/app/encryption.cpp)

      add_benchmark(SortNBenchmark 
	      SortNBenchmark.cpp 
              ${CMAKE_SOURCE_DIR}/app/sign.cpp
              ${CMAKE_SOURCE_DIR}/app/comparison.cpp
              ${CMAKE_SOURCE_DIR}/app/encryption.cpp)

      add_benchmark(RotationBenchmark 
	      RotationBenchmark.cpp)
