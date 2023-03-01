cmake_minimum_required(VERSION 3.0)
project(notary)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

set(PSSL ${CMAKE_CURRENT_SOURCE_DIR}/../../install)

add_library(notary SHARED notary.cpp)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include/)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../)
if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  target_link_libraries(notary PUBLIC ${EMP-OT_LIBRARIES} dl)
else()
  target_link_libraries(notary PUBLIC ${EMP-TOOL_LIBRARY} dl)
endif()
target_link_libraries(notary PUBLIC ${PSSL}/lib/libssl.a)
target_link_libraries(notary PUBLIC ${PSSL}/lib/libcrypto.a)

install(TARGETS notary DESTINATION lib)
install(FILES notary.h DESTINATION include/notary)
