cmake_minimum_required(VERSION 3.0)
project(otls-test)

set(PadoSSL ${CMAKE_CURRENT_SOURCE_DIR}/../../install)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

macro (add_otls_test name)
	add_executable(${name} ${name}.cpp)
	target_include_directories(${name} PUBLIC ${PadoSSL}/include/)
	target_link_libraries(${name} PUBLIC otls)
	target_link_libraries(${name} PUBLIC ${PadoSSL}/lib/libssl.a)
	target_link_libraries(${name} PUBLIC ${PadoSSL}/lib/libcrypto.a)
endmacro()

add_otls_test(otls_pado)
add_otls_test(otls_client)
