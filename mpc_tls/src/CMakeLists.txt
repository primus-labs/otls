cmake_minimum_required(VERSION 3.0)
project(otls)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})

add_library(otls SHARED mpc_tls.cpp)
target_include_directories(otls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../../install/include/)
target_include_directories(otls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../)
target_link_libraries(otls PUBLIC ${EMP-OT_LIBRARIES} dl)

install(TARGETS otls DESTINATION lib)
install(FILES mpc_tls.h DESTINATION include/otls)
