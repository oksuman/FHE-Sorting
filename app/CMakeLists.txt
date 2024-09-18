cmake_minimum_required(VERSION 3.5.1)

project(fherma_array_sorting CXX)
set(CMAKE_CXX_STANDARD 17)
option(BUILD_STATIC "Set to ON to include static versions of the library" OFF)

set(CMAKE_BUILD_TYPE Release FORCE)
set(WITH_NATIVEOPT ON FORCE)
find_package(OpenFHE)

set(CMAKE_CXX_FLAGS "${OpenFHE_CXX_FLAGS} ${CMAKE_CXX_FLAGS}")

find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

include_directories(${OPENMP_INCLUDES})
include_directories(${OpenFHE_INCLUDE})
include_directories(${OpenFHE_INCLUDE}/third-party/include)
include_directories(${OpenFHE_INCLUDE}/core)
include_directories(${OpenFHE_INCLUDE}/pke)
include_directories(${OpenFHE_INCLUDE}/binfhe)
### add directories for other OpenFHE modules as needed for your project

link_directories(${OpenFHE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
if (BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries(${OpenFHE_STATIC_LIBRARIES} OpenMP::OpenMP_CXX)
else ()
    set(CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS})
    link_libraries(${OpenFHE_SHARED_LIBRARIES} OpenMP::OpenMP_CXX)
endif ()

### ADD YOUR EXECUTABLE(s) HERE
add_executable(app main.cpp 
		   comparison.cpp
	           encryption.cpp
	           sign.cpp
		   )

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  # Disable printing for submission
  set(ENABLE_PRINT_PT OFF CACHE BOOL "Enable PRINT_PT macro")
endif()

if(ENABLE_PRINT_PT)
  add_definitions(-DENABLE_PRINT_PT)
endif()
###
### EXAMPLE:
### add_executable( test demo-simple-example.cpp )
