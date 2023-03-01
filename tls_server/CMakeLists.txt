
cmake_minimum_required (VERSION 3.0)
project (tls_server)

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	if(NOT DEFINED OPENSSL_ROOT_DIR)
		IF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64)|(arm64)")
			# M1 Apple
			set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl")
			message(STATUS "OPENSSL_ROOT_DIR set to default: ${OPENSSL_ROOT_DIR}")
		ELSE(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64)|(arm64)")
			# Intel Apple
			set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
			message(STATUS "OPENSSL_ROOT_DIR set to default: ${OPENSSL_ROOT_DIR}")
		ENDIF(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(aarch64)|(arm64)" )
	endif()
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARY_DIR})
message(STATUS "OPENSSL_LIBRARIES ${OPENSSL_LIBRARIES}")

add_executable(tls_server server.cpp)
target_link_libraries(tls_server ${OPENSSL_LIBRARIES})