cmake_minimum_required(VERSION 3.0)
project(notary)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

set(PadoSSL ${CMAKE_CURRENT_SOURCE_DIR}/../../install)

add_library(notary SHARED notary.cpp)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include/)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../)
target_link_libraries(notary PUBLIC ${EMP-OT_LIBRARIES} dl)
# target_link_libraries(notary PUBLIC ${EMP-TOOL_LIBRARIES} dl)
target_link_libraries(notary PUBLIC ${PadoSSL}/lib/libssl.a)
target_link_libraries(notary PUBLIC ${PadoSSL}/lib/libcrypto.a)

install(TARGETS notary DESTINATION lib)
install(FILES notary.h DESTINATION include/notary)
