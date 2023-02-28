cmake_minimum_required(VERSION 3.0)
project(notary)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

add_library(notary SHARED notary.cpp)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include/)
target_include_directories(notary PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../)
target_link_libraries(notary PUBLIC ${EMP-OT_LIBRARIES} dl)

install(TARGETS notary DESTINATION lib)
install(FILES notary.h DESTINATION include/notary)
