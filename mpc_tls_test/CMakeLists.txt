cmake_minimum_required(VERSION 3.0)
project(otls-test)

set(PadoSSL ${CMAKE_CURRENT_SOURCE_DIR}/../../install_openssl)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})
# message("cmake prefix" ${CMAKE_PREFIX_PATH})

macro (add_otls_test name)
    add_executable(otls_${name} ${name}.cpp)
    target_include_directories(otls_${name} PUBLIC ${PadoSSL}/include/)
	target_link_libraries(otls_${name} PUBLIC otls)
	target_link_libraries(otls_${name} PUBLIC ${PadoSSL}/lib/libssl.a)
	target_link_libraries(otls_${name} PUBLIC ${PadoSSL}/lib/libcrypto.a)
endmacro()

add_otls_test(pado)
add_otls_test(client)
add_otls_test(server)

