cmake_minimum_required(VERSION 3.18)
project("SHA1SUM")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
	add_definitions(-D_WIN32)
	add_compile_options("/O2")
else()
   if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
		message(WARNING "Assuming system in Linux")
	endif()
	add_definitions(-D_LINUX)
	add_compile_options("-O3")
endif()

include_directories(
	"${CMAKE_SOURCE_DIR}/include"
)

set(SHA1LIB "sha1sum")

set(LIBRAY_TYPE SHARED)

if(NOT("${BUILD_SHARED_LIBS}" STREQUAL ""))
	if(NOT BUILD_SHARED_LIBS)
		set(LIBRAY_TYPE STATIC)
		message(WARNING "Building static library.")	
	endif()
endif()

if(${LIBRAY_TYPE} STREQUAL "SHARED")
	message(WARNING "Building dynamic library (shared).")
endif()

add_library(
	${SHA1LIB}
	${LIBRAY_TYPE}
	sha1.cpp
)

set_target_properties(
	${SHA1LIB}
	PROPERTIES
	ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib"
	LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib"
)


