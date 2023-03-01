cmake_minimum_required(VERSION 3.0)
project(notary-test)

set(PSSL ${CMAKE_CURRENT_SOURCE_DIR}/../../install)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

macro (add_notary_test name)
	set(projname notary_${name})
	add_executable(${projname} ${name}.cpp)
	target_include_directories(${projname} PUBLIC ${PSSL}/include/)
	target_link_libraries(${projname} PUBLIC notary)
endmacro()

add_notary_test(client)
add_notary_test(server)
