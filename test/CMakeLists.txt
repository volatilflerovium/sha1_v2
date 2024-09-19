cmake_minimum_required(VERSION 3.18)
project("SHA1_tests")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

get_filename_component(PARENT_DIR ../ ABSOLUTE)

if(NDEBUG)
	add_definitions(-DNDEBUG=1)
endif() 


if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	add_compile_options("/O2")
else()
   if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
		message(WARNING "Assuming system in Linux")
	endif()
	add_compile_options("-O3")
	add_compile_options("-g")
endif()

find_library(
	SHA1SUM_LIB
	NAMES sha1sum 
	PATHS "${PARENT_DIR}/lib" 
	REQUIRED
)

set(TEST test_sha1)

add_executable(${TEST} test_sha1.cpp)

target_link_libraries(
	${TEST}
	PRIVATE
	${SHA1SUM_LIB}
)

target_include_directories(
	${TEST}
	PUBLIC
	"${PARENT_DIR}/include"
)

#---------------------------------------------------------------------

